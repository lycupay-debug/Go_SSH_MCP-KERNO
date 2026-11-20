package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
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
	TaskID string          `json:"task_id,omitempty"`
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
	MaxOutputBytes int
}

func (e *Executor) Execute(parent context.Context, taskID, operation string, input map[string]any, timeout time.Duration) (Result, error) {
	if operation == "shell.exec" {
		return e.executeShellGo(parent, input, timeout)
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
	if len(payload) > maxRequestBytes {
		return result, fmt.Errorf("executor request exceeds %d-byte limit", maxRequestBytes)
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.Command(e.Path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = bytes.NewReader(append(payload, '\n'))
	limit := e.MaxOutputBytes
	if migratedCOperation(operation) && limit < 16*1024*1024 {
		limit = 16 * 1024 * 1024
	}
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
	if result.Response.TaskID != taskID {
		return result, fmt.Errorf("C executor response task_id mismatch: got %q, want %q", result.Response.TaskID, taskID)
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

const maxRequestBytes = 32 * 1024 * 1024

func migratedCOperation(operation string) bool {
	switch operation {
	case "directory.list", "file.read", "file.write", "file.replace", "file.delete":
		return true
	default:
		return false
	}
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
