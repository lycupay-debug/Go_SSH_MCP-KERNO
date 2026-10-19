package executor

/*
#cgo CFLAGS: -D_GNU_SOURCE -I/usr/local/include -I/usr/local/include/json-c
#cgo LDFLAGS: -L/usr/local/lib -ljson-c
#include <stdlib.h>
char *executor_process_json(const char *line);
int executor_read_file_raw(const char *path, size_t max_bytes, char **data, size_t *data_len, int *truncated, char **error_code, char **error_message);
char *executor_write_text_json(const char *path, const char *data, size_t len, int create_parents);
void executor_free(void *p);
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type Request struct {
	ProtocolVersion string         `json:"protocol_version"`
	TaskID          string         `json:"task_id"`
	Operation       string         `json:"operation"`
	Input           map[string]any `json:"input"`
}
type Response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *ErrorInfo      `json:"error,omitempty"`
}
type ErrorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Result struct {
	Response  Response
	Value     any
	Duration  time.Duration
	ExitError string
}
type Executor struct {
	Path           string
	Native         bool
	MaxOutputBytes int
}

func (e *Executor) Execute(parent context.Context, taskID, operation string, input map[string]any, timeout time.Duration) (Result, error) {
	if operation == "shell.exec" {
		return e.executeShellGo(parent, input, timeout)
	}
	if e.Native && nativeOperation(operation) {
		return e.executeNative(parent, taskID, operation, input)
	}
	start := time.Now()
	var result Result
	if e.Path == "" {
		return result, errors.New("C executor path is not configured")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	payload, err := json.Marshal(Request{ProtocolVersion: "1", TaskID: taskID, Operation: operation, Input: input})
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.Command(e.Path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = bytes.NewReader(append(payload, '\n'))
	limit := e.MaxOutputBytes
	if limit < 1024 {
		limit = 1024
	}
	stdout := &limitedBuffer{limit: limit}
	stderr := &limitedBuffer{limit: 64 * 1024}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err = cmd.Start(); err != nil {
		return result, fmt.Errorf("start C executor: %w", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-waitCh:
	case <-ctx.Done():
		signalName := "SIGTERM"
		if cmd.Process != nil {
			if killErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); killErr == syscall.ESRCH {
				signalName = "already_exited"
			}
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case waitErr = <-waitCh:
			if processGroupExists(cmd.Process.Pid) {
				signalName = "SIGKILL"
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		case <-timer.C:
			signalName = "SIGKILL"
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			select {
			case waitErr = <-waitCh:
			case <-time.After(2 * time.Second):
				_ = cmd.Process.Kill()
				waitErr = <-waitCh
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		cleanupComplete := waitForProcessGroupExit(cmd.Process.Pid, time.Second)
		result.Duration = time.Since(start)
		if operation == "shell.exec" {
			timeoutResult := map[string]any{"returncode": nil, "stdout": "", "stderr": "", "timed_out": true, "termination_signal": signalName, "cleanup_complete": cleanupComplete}
			raw, _ := json.Marshal(timeoutResult)
			result.Response = Response{OK: true, Result: raw}
			return result, nil
		}
		return result, fmt.Errorf("executor timed out or cancelled: %w", ctx.Err())
	}
	result.Duration = time.Since(start)
	if waitErr != nil {
		result.ExitError = waitErr.Error()
		if stderr.Len() > 0 {
			result.ExitError += ": " + stderr.String()
		}
		return result, fmt.Errorf("C executor process failed: %w", waitErr)
	}
	if stdout.Truncated() {
		return result, errors.New("C executor response exceeded output limit")
	}
	if err = json.Unmarshal(stdout.Bytes(), &result.Response); err != nil {
		return result, fmt.Errorf("invalid C executor JSON response: %w", err)
	}
	if !result.Response.OK {
		if result.Response.Error != nil {
			return result, fmt.Errorf("%s: %s", result.Response.Error.Code, result.Response.Error.Message)
		}
		return result, errors.New("C executor returned ok=false without error details")
	}
	return result, nil
}

// executeShellGo runs short shell commands directly from Go. It deliberately
// retains /bin/sh -c semantics and the process-group timeout cleanup contract.
func (e *Executor) executeShellGo(parent context.Context, input map[string]any, outerTimeout time.Duration) (Result, error) {
	start := time.Now()
	var result Result
	command, ok := input["command"].(string)
	if !ok || command == "" || len(command) > 131072 {
		return result, errors.New("INVALID_ARGUMENT: command must be 1..131072 bytes.")
	}
	timeoutSeconds := 30
	if value, exists := input["timeout_seconds"]; exists {
		switch n := value.(type) {
		case int:
			timeoutSeconds = n
		case int64:
			timeoutSeconds = int(n)
		case float64:
			timeoutSeconds = int(n)
		default:
			return result, errors.New("INVALID_ARGUMENT: timeout_seconds must be 1..300.")
		}
	}
	if timeoutSeconds < 1 || timeoutSeconds > 300 {
		return result, errors.New("INVALID_ARGUMENT: timeout_seconds must be 1..300.")
	}
	ctxTimeout := time.Duration(timeoutSeconds) * time.Second
	if outerTimeout > 0 && outerTimeout < ctxTimeout {
		ctxTimeout = outerTimeout
	}
	ctx, cancel := context.WithTimeout(parent, ctxTimeout)
	defer cancel()
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	stdout := &limitedBuffer{limit: 120000}
	stderr := &limitedBuffer{limit: 40000}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return result, fmt.Errorf("COMMAND_FAILED: %w", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-waitCh:
	case <-ctx.Done():
		signalName := "SIGTERM"
		if killErr := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); killErr == syscall.ESRCH {
			signalName = "already_exited"
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case waitErr = <-waitCh:
			if processGroupExists(cmd.Process.Pid) {
				signalName = "SIGKILL"
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		case <-timer.C:
			signalName = "SIGKILL"
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			select {
			case waitErr = <-waitCh:
			case <-time.After(2 * time.Second):
				_ = cmd.Process.Kill()
				waitErr = <-waitCh
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		cleanupComplete := waitForProcessGroupExit(cmd.Process.Pid, time.Second)
		result.Duration = time.Since(start)
		if parent.Err() != nil {
			return result, fmt.Errorf("executor cancelled: %w", parent.Err())
		}
		raw, _ := json.Marshal(map[string]any{"returncode": nil, "stdout": stdout.String(), "stderr": stderr.String(), "timed_out": true, "termination_signal": signalName, "cleanup_complete": cleanupComplete})
		result.Response = Response{OK: true, Result: raw}
		return result, nil
	}
	result.Duration = time.Since(start)
	if stdout.Truncated() || stderr.Truncated() {
		// Match the bounded C buffers: retain the prefix instead of allowing unbounded memory growth.
	}
	returnCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			returnCode = exitErr.ExitCode()
		} else {
			return result, fmt.Errorf("COMMAND_FAILED: %w", waitErr)
		}
	}
	raw, err := json.Marshal(map[string]any{"returncode": returnCode, "stdout": stdout.String(), "stderr": stderr.String(), "timed_out": false})
	if err != nil {
		return result, err
	}
	result.Response = Response{OK: true, Result: raw}
	return result, nil
}

func nativeOperation(operation string) bool {
	switch operation {
	case "directory.list", "file.read", "file.write", "file.replace", "file.delete":
		return true
	}
	return false
}

func (e *Executor) executeNative(ctx context.Context, taskID, operation string, input map[string]any) (Result, error) {
	if operation == "file.read" {
		return e.executeNativeRead(ctx, input)
	}
	if operation == "file.write" {
		return e.executeNativeWrite(ctx, input)
	}
	start := time.Now()
	var result Result
	if err := ctx.Err(); err != nil {
		return result, err
	}
	payload, err := json.Marshal(Request{ProtocolVersion: "1", TaskID: taskID, Operation: operation, Input: input})
	if err != nil {
		return result, err
	}
	cPayload := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cPayload))
	cResponse := C.executor_process_json(cPayload)
	if cResponse == nil {
		return result, errors.New("C executor returned a null response")
	}
	defer C.executor_free(unsafe.Pointer(cResponse))
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := json.Unmarshal([]byte(C.GoString(cResponse)), &result.Response); err != nil {
		return result, fmt.Errorf("invalid native C executor JSON response: %w", err)
	}
	result.Duration = time.Since(start)
	if !result.Response.OK {
		if result.Response.Error != nil {
			return result, fmt.Errorf("%s: %s", result.Response.Error.Code, result.Response.Error.Message)
		}
		return result, errors.New("native C executor returned ok=false without error details")
	}
	return result, nil
}

func nativePath(input map[string]any) (string, error) {
	path, ok := input["path"].(string)
	if !ok || path == "" {
		return "", errors.New("path is required")
	}
	if strings.IndexByte(path, 0) >= 0 {
		return "", errors.New("path contains a NUL byte")
	}
	return path, nil
}

func (e *Executor) executeNativeRead(ctx context.Context, input map[string]any) (Result, error) {
	start := time.Now()
	var result Result
	if err := ctx.Err(); err != nil {
		return result, err
	}
	path, err := nativePath(input)
	if err != nil {
		return result, err
	}
	maxBytes := 200000
	if value, ok := input["max_bytes"]; ok {
		switch n := value.(type) {
		case int:
			maxBytes = n
		case int64:
			maxBytes = int(n)
		case float64:
			maxBytes = int(n)
		}
	}
	if maxBytes < 1 || maxBytes > 2000000 {
		return result, errors.New("max_bytes 必须在 1 至 2000000 之间")
	}
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var data *C.char
	var dataLen C.size_t
	var truncated C.int
	var cCode, cMessage *C.char
	status := C.executor_read_file_raw(cPath, C.size_t(maxBytes), &data, &dataLen, &truncated, &cCode, &cMessage)
	if data != nil {
		defer C.executor_free(unsafe.Pointer(data))
	}
	if cCode != nil {
		defer C.executor_free(unsafe.Pointer(cCode))
	}
	if cMessage != nil {
		defer C.executor_free(unsafe.Pointer(cMessage))
	}
	if status != 0 {
		code, message := "FILE_READ_FAILED", "Could not read target file."
		if cCode != nil {
			code = C.GoString(cCode)
		}
		if cMessage != nil {
			message = C.GoString(cMessage)
		}
		return result, fmt.Errorf("%s: %s", code, message)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	content := string(C.GoBytes(unsafe.Pointer(data), C.int(dataLen)))
	result.Response = Response{OK: true}
	result.Value = map[string]any{"path": path, "content": content, "truncated": truncated != 0}
	result.Duration = time.Since(start)
	return result, nil
}

func (e *Executor) executeNativeWrite(ctx context.Context, input map[string]any) (Result, error) {
	start := time.Now()
	var result Result
	if err := ctx.Err(); err != nil {
		return result, err
	}
	path, err := nativePath(input)
	if err != nil {
		return result, err
	}
	content, ok := input["content"].(string)
	if !ok {
		return result, errors.New("content is required")
	}
	createParents, _ := input["create_parents"].(bool)
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var cData *C.char
	if len(content) > 0 {
		cData = (*C.char)(unsafe.Pointer(unsafe.StringData(content)))
	}
	create := C.int(0)
	if createParents {
		create = 1
	}
	cResponse := C.executor_write_text_json(cPath, cData, C.size_t(len(content)), create)
	if cResponse == nil {
		return result, errors.New("C executor returned a null write response")
	}
	defer C.executor_free(unsafe.Pointer(cResponse))
	if err := json.Unmarshal([]byte(C.GoString(cResponse)), &result.Response); err != nil {
		return result, fmt.Errorf("invalid native C write response: %w", err)
	}
	if !result.Response.OK {
		if result.Response.Error != nil {
			return result, fmt.Errorf("%s: %s", result.Response.Error.Code, result.Response.Error.Message)
		}
		return result, errors.New("native C write failed")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.Duration = time.Since(start)
	return result, nil
}

func processGroupExists(pgid int) bool {
	err := syscall.Kill(-pgid, 0)
	return err == nil || err == syscall.EPERM
}
func waitForProcessGroupExit(pgid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processGroupExists(pgid) {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return !processGroupExists(pgid)
}

type limitedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := b.limit - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
			b.truncated = true
		}
		_, _ = b.Buffer.Write(p)
	} else {
		b.truncated = true
	}
	return original, nil
}
func (b *limitedBuffer) Truncated() bool { return b.truncated }
