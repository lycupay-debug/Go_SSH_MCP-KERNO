// Package parallel provides bounded, isolated shell-task execution for Go SSH MCP.
package parallel

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	MaxParallel        = 8
	MaxTasks           = 32
	MaxCommandBytes    = 8000
	MaxOutputBytes     = 1_000_000
	DefaultTimeoutSecs = 120
)

var (
	taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,48}$`)
	allowedRoots  = []string{"/opt", "/tmp", "/var/tmp", "/home"}
	protectedRoot = "/opt/kerno"
	globalSlots   = make(chan struct{}, MaxParallel)
)

type Task struct {
	TaskID           string `json:"task_id"`
	Command          string `json:"command"`
	WorkingDirectory string `json:"working_directory"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty"`
}

type Request struct {
	Tasks       []Task `json:"tasks"`
	MaxParallel int    `json:"max_parallel,omitempty"`
}

type Result struct {
	TaskID           string  `json:"task_id"`
	Status           string  `json:"status"`
	ReturnCode       *int    `json:"returncode"`
	TimedOut         bool    `json:"timed_out"`
	OutputLimited    bool    `json:"output_limited"`
	CleanupComplete  bool    `json:"cleanup_complete"`
	ElapsedSeconds   float64 `json:"elapsed_seconds"`
	WorkingDirectory string  `json:"working_directory"`
	LogPath          string  `json:"log_path"`
	Output           string  `json:"output,omitempty"`
	Error            string  `json:"error,omitempty"`
}

type Summary struct {
	RunID          string   `json:"run_id"`
	MaxParallel    int      `json:"max_parallel"`
	TaskCount      int      `json:"task_count"`
	ElapsedSeconds float64  `json:"elapsed_seconds"`
	Results        []Result `json:"results"`
}

type AuditFunc func(event string, fields map[string]any)

type validatedTask struct {
	task Task
	cwd  string
}

func Run(ctx context.Context, request Request, logRoot string, audit AuditFunc) (Summary, error) {
	validated, maxParallel, err := validate(request)
	if err != nil {
		return Summary{}, err
	}
	if logRoot == "" {
		logRoot = "/var/log/go-ssh-mcp-parallel"
	}
	if info, statErr := os.Lstat(logRoot); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return Summary{}, errors.New("parallel log root must be a real directory, not a symlink")
		}
	} else if !os.IsNotExist(statErr) {
		return Summary{}, fmt.Errorf("inspect parallel log directory: %w", statErr)
	}
	if err = os.MkdirAll(logRoot, 0700); err != nil {
		return Summary{}, fmt.Errorf("create parallel log directory: %w", err)
	}
	if info, statErr := os.Lstat(logRoot); statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return Summary{}, errors.New("parallel log root must be a real directory, not a symlink")
	}
	if err = os.Chmod(logRoot, 0700); err != nil {
		return Summary{}, fmt.Errorf("secure parallel log directory: %w", err)
	}
	runID, err := randomID()
	if err != nil {
		return Summary{}, err
	}
	runDir := filepath.Join(logRoot, runID)
	if err = os.Mkdir(runDir, 0700); err != nil {
		return Summary{}, fmt.Errorf("create parallel run directory: %w", err)
	}
	started := time.Now()
	results := make([]Result, len(validated))
	jobs := make(chan int)
	var workers sync.WaitGroup
	workerCount := maxParallel
	if workerCount > len(validated) {
		workerCount = len(validated)
	}
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				select {
				case globalSlots <- struct{}{}:
					results[index] = runOne(ctx, validated[index], runDir, audit)
					<-globalSlots
				case <-ctx.Done():
					results[index] = finishResult(Result{TaskID: validated[index].task.TaskID, Status: "cancelled", CleanupComplete: true, WorkingDirectory: validated[index].cwd, LogPath: filepath.Join(runDir, validated[index].task.TaskID+".log")}, time.Now(), audit)
				}
			}
		}()
	}
	for i := range validated {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	return Summary{RunID: runID, MaxParallel: workerCount, TaskCount: len(results), ElapsedSeconds: roundSeconds(time.Since(started)), Results: results}, nil
}

func validate(request Request) ([]validatedTask, int, error) {
	if len(request.Tasks) < 2 || len(request.Tasks) > MaxTasks {
		return nil, 0, fmt.Errorf("tasks 必须包含 2 至 %d 个任务", MaxTasks)
	}
	maxParallel := request.MaxParallel
	if maxParallel == 0 {
		maxParallel = MaxParallel
	}
	if maxParallel < 1 || maxParallel > MaxParallel {
		return nil, 0, fmt.Errorf("max_parallel 必须在 1 至 %d 之间", MaxParallel)
	}
	seenIDs := make(map[string]struct{}, len(request.Tasks))
	seenDirs := make(map[string]string, len(request.Tasks))
	seenGitDirs := make(map[string]string, len(request.Tasks))
	validated := make([]validatedTask, 0, len(request.Tasks))
	for _, task := range request.Tasks {
		if !taskIDPattern.MatchString(task.TaskID) {
			return nil, 0, fmt.Errorf("task_id %q 无效；仅允许 1 至 48 位字母、数字、点、下划线和连字符", task.TaskID)
		}
		if _, exists := seenIDs[task.TaskID]; exists {
			return nil, 0, fmt.Errorf("task_id 必须唯一：%s", task.TaskID)
		}
		seenIDs[task.TaskID] = struct{}{}
		if strings.TrimSpace(task.Command) == "" || strings.ContainsRune(task.Command, '\x00') || len(task.Command) > MaxCommandBytes {
			return nil, 0, fmt.Errorf("任务 %s 的 command 必须为 1 至 %d 字节且不能包含 NUL", task.TaskID, MaxCommandBytes)
		}
		if task.TimeoutSeconds == 0 {
			task.TimeoutSeconds = DefaultTimeoutSecs
		}
		if task.TimeoutSeconds < 1 || task.TimeoutSeconds > 300 {
			return nil, 0, fmt.Errorf("任务 %s 的 timeout_seconds 必须在 1 至 300 之间", task.TaskID)
		}
		if len(task.WorkingDirectory) == 0 || len(task.WorkingDirectory) > 1024 {
			return nil, 0, fmt.Errorf("任务 %s 的 working_directory 长度无效", task.TaskID)
		}
		resolved, err := filepath.EvalSymlinks(task.WorkingDirectory)
		if err != nil {
			return nil, 0, fmt.Errorf("任务 %s 的 working_directory 无法解析：%w", task.TaskID, err)
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return nil, 0, fmt.Errorf("任务 %s 的 working_directory 无法规范化：%w", task.TaskID, err)
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			return nil, 0, fmt.Errorf("任务 %s 的 working_directory 必须是存在的目录", task.TaskID)
		}
		if isSameOrChild(resolved, protectedRoot) {
			return nil, 0, errors.New("并行执行器禁止在 /opt/kerno 内运行；请使用该项目的独立 Git worktree")
		}
		allowed := false
		for _, root := range allowedRoots {
			if resolved != root && isSameOrChild(resolved, root) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, 0, fmt.Errorf("任务 %s 的工作目录必须位于 /opt、/tmp、/var/tmp 或 /home 的子目录", task.TaskID)
		}
		if previous, exists := seenDirs[resolved]; exists {
			return nil, 0, fmt.Errorf("任务 %s 与 %s 使用同一工作目录；每个任务必须有独立目录", task.TaskID, previous)
		}
		seenDirs[resolved] = task.TaskID
		if gitDir, ok := gitDirectory(resolved); ok {
			if previous, exists := seenGitDirs[gitDir]; exists {
				return nil, 0, fmt.Errorf("任务 %s 与 %s 位于同一个 Git 工作树；请为并行任务创建独立 git worktree", task.TaskID, previous)
			}
			seenGitDirs[gitDir] = task.TaskID
		}
		validated = append(validated, validatedTask{task: task, cwd: resolved})
	}
	return validated, maxParallel, nil
}

func runOne(parent context.Context, validated validatedTask, runDir string, audit AuditFunc) Result {
	task := validated.task
	started := time.Now()
	logPath := filepath.Join(runDir, task.TaskID+".log")
	if audit != nil {
		audit("parallel_task_started", map[string]any{"task_id": task.TaskID, "working_directory": validated.cwd, "timeout_seconds": task.TimeoutSeconds})
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(task.TimeoutSeconds)*time.Second)
	defer cancel()
	output := &cappedBuffer{limit: MaxOutputBytes}
	cmd := exec.Command("/bin/sh", "-c", task.Command)
	cmd.Dir = validated.cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		return finishResult(Result{TaskID: task.TaskID, Status: "error", CleanupComplete: true, WorkingDirectory: validated.cwd, LogPath: logPath, Error: trimError(err)}, started, audit)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	var waitErr error
	timedOut, outputLimited, cleanupComplete := false, false, true
selectLoop:
	for {
		select {
		case waitErr = <-waitCh:
			break selectLoop
		case <-ctx.Done():
			timedOut = parent.Err() == nil
			cleanupComplete = terminateProcessGroup(cmd.Process.Pid)
			waitErr = <-waitCh
			break selectLoop
		case <-time.After(25 * time.Millisecond):
			if output.Overflowed() {
				outputLimited = true
				cleanupComplete = terminateProcessGroup(cmd.Process.Pid)
				waitErr = <-waitCh
				break selectLoop
			}
		}
	}
	if output.Overflowed() {
		outputLimited = true
	}
	if !timedOut && !outputLimited && processGroupExists(cmd.Process.Pid) {
		cleanupComplete = terminateProcessGroup(cmd.Process.Pid)
	}
	code := 0
	status := "succeeded"
	if timedOut {
		status = "timed_out"
	} else if parent.Err() != nil {
		status = "cancelled"
	} else if outputLimited {
		status = "output_limited"
	} else if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			code = exitErr.ExitCode()
			status = "failed"
		} else {
			status = "error"
		}
	}
	var returnCode *int
	if status != "timed_out" && status != "cancelled" {
		returnCode = &code
	}
	captured := output.String()
	if err := os.WriteFile(logPath, []byte(captured), 0600); err != nil {
		if status == "succeeded" {
			status = "error"
		}
		return finishResult(Result{TaskID: task.TaskID, Status: status, ReturnCode: returnCode, TimedOut: timedOut, OutputLimited: outputLimited, CleanupComplete: cleanupComplete, WorkingDirectory: validated.cwd, LogPath: logPath, Error: "write task log failed: " + trimError(err)}, started, audit)
	}
	return finishResult(Result{TaskID: task.TaskID, Status: status, ReturnCode: returnCode, TimedOut: timedOut, OutputLimited: outputLimited, CleanupComplete: cleanupComplete, WorkingDirectory: validated.cwd, LogPath: logPath, Output: tailUTF8(captured, 30000)}, started, audit)
}

func finishResult(result Result, started time.Time, audit AuditFunc) Result {
	result.ElapsedSeconds = roundSeconds(time.Since(started))
	if audit != nil {
		audit("parallel_task_finished", map[string]any{"task_id": result.TaskID, "working_directory": result.WorkingDirectory, "status": result.Status, "returncode": result.ReturnCode, "timed_out": result.TimedOut, "output_limited": result.OutputLimited, "cleanup_complete": result.CleanupComplete, "elapsed_seconds": result.ElapsedSeconds})
	}
	return result
}

func gitDirectory(path string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "--absolute-git-dir")
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	gitDir := strings.TrimSpace(string(out))
	if gitDir == "" {
		return "", false
	}
	if abs, err := filepath.Abs(gitDir); err == nil {
		gitDir = abs
	}
	return filepath.Clean(gitDir), true
}

func isSameOrChild(path, root string) bool {
	path, err1 := filepath.Abs(filepath.Clean(path))
	root, err2 := filepath.Abs(filepath.Clean(root))
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))))
}

func terminateProcessGroup(pid int) bool {
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !processGroupExists(pid) {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !processGroupExists(pid) {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return !processGroupExists(pid)
}

func processGroupExists(pid int) bool {
	err := syscall.Kill(-pid, 0)
	return err == nil || err == syscall.EPERM
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func roundSeconds(d time.Duration) float64 { return float64(int64(d*100)/int64(time.Second)) / 100 }
func trimError(err error) string {
	if err == nil {
		return ""
	}
	value := err.Error()
	if len(value) > 2000 {
		value = value[:2000]
	}
	return value
}
func tailUTF8(value string, maxRunes int) string {
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "�")
	}
	runes := []rune(value)
	if len(runes) > maxRunes {
		return string(runes[len(runes)-maxRunes:])
	}
	return value
}

type cappedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
		} else {
			_, _ = b.buf.Write(p)
		}
	}
	if len(p) > remaining {
		b.overflow = true
	}
	return len(p), nil
}
func (b *cappedBuffer) Overflowed() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.overflow }
func (b *cappedBuffer) String() string   { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }
