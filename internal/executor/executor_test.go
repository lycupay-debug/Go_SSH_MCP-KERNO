package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type wireResponse struct {
	OK     bool           `json:"ok"`
	Result map[string]any `json:"result"`
	Error  struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func runC(t *testing.T, bin, op string, input map[string]any) wireResponse {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"protocol_version": "1", "task_id": "test", "operation": op, "input": input})
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(string(raw) + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("C executor failed: %v", err)
	}
	var r wireResponse
	if err = json.Unmarshal(out, &r); err != nil {
		t.Fatalf("invalid JSON %q: %v", out, err)
	}
	return r
}
func TestCExecutorFileLifecycleAndAtomicEdit(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	moved := filepath.Join(dir, "renamed.txt")
	r := runC(t, bin, "file.write", map[string]any{"path": path, "content": "alpha alpha\n"})
	if !r.OK {
		t.Fatalf("file.write failed: %#v", r.Error)
	}
	r = runC(t, bin, "file.edit", map[string]any{"path": path, "old_text": "alpha", "new_text": "x", "expected_matches": 2})
	if !r.OK {
		t.Fatalf("file.edit failed: %#v", r.Error)
	}
	r = runC(t, bin, "file.read", map[string]any{"path": path})
	if !r.OK || r.Result["content"] != "x x\n" {
		t.Fatalf("unexpected read result: %#v", r)
	}
	r = runC(t, bin, "file.move", map[string]any{"source": path, "destination": moved})
	if !r.OK {
		t.Fatalf("file.move failed: %#v", r.Error)
	}
	r = runC(t, bin, "file.delete", map[string]any{"path": moved})
	if !r.OK {
		t.Fatalf("file.delete failed: %#v", r.Error)
	}
	if _, err := os.Stat(moved); !os.IsNotExist(err) {
		t.Fatalf("file still exists: %v", err)
	}
}

func TestCExecutorDeleteRequiresRecursiveAndDoesNotFollowSymlinks(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	root := t.TempDir()
	tree := filepath.Join(root, "tree")
	if err := os.MkdirAll(filepath.Join(tree, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "nested", "data.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	result := runC(t, bin, "file.delete", map[string]any{"path": tree, "recursive": false})
	if result.OK || result.Error.Code != "RECURSION_REQUIRED" {
		t.Fatalf("non-recursive deletion of non-empty directory = %#v, want RECURSION_REQUIRED", result)
	}
	result = runC(t, bin, "file.delete", map[string]any{"path": tree, "recursive": true})
	if !result.OK {
		t.Fatalf("recursive directory deletion failed: %#v", result.Error)
	}
	if _, err := os.Stat(tree); !os.IsNotExist(err) {
		t.Fatalf("recursive delete left directory present: %v", err)
	}

	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	result = runC(t, bin, "file.delete", map[string]any{"path": link})
	if !result.OK {
		t.Fatalf("symlink deletion failed: %#v", result.Error)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("symlink still exists after deletion: %v", err)
	}
	if content, err := os.ReadFile(target); err != nil || string(content) != "target" {
		t.Fatalf("deleting symlink modified target: content=%q err=%v", content, err)
	}
}

func TestCExecutorReadsLargeFileWithinConfiguredOutputLimit(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "large.txt")
	content := strings.Repeat("large-file-content\n", 80000)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	e := Executor{Path: bin, MaxOutputBytes: 6 * 1024 * 1024}
	result, err := e.Execute(context.Background(), "large-read", "file.read", map[string]any{"path": path, "max_bytes": 2000000}, 10*time.Second)
	if err != nil {
		t.Fatalf("large file read failed: %v", err)
	}
	var payload struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(result.Response.Result, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Content != content {
		t.Fatalf("read content mismatch: got %d bytes, want %d", len(payload.Content), len(content))
	}
}

func TestCExecutorListsDirectoryMetadata(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sample.txt"), []byte("x"), 0640); err != nil {
		t.Fatal(err)
	}
	r := runC(t, bin, "directory.list", map[string]any{"path": dir})
	if !r.OK {
		t.Fatalf("directory.list failed: %#v", r.Error)
	}
	entries, ok := r.Result["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("unexpected directory entries: %#v", r.Result)
	}
	entry, ok := entries[0].(map[string]any)
	if !ok || entry["name"] != "sample.txt" || entry["type"] != "file" || entry["mode"] != "0o640" {
		t.Fatalf("unexpected directory metadata: %#v", entries[0])
	}
}

func TestCExecutorAllowsRootServiceControl(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	// Invalid service name verifies that the request reaches rc.d validation
	// instead of being rejected by a hard-coded protected-service policy.
	r := runC(t, bin, "service.control", map[string]any{"service": "nonexistent_test_service", "action": "restart"})
	if r.Error.Code == "PROTECTED_SERVICE_CONTROL" {
		t.Fatalf("service control should not be blocked by service-name policy: %#v", r)
	}
	r = runC(t, bin, "shell.exec", map[string]any{"command": "printf root-shell-enabled"})
	if !r.OK {
		t.Fatalf("root shell should be allowed: %#v", r)
	}
}
func TestExecutorTimeoutKillsProcessGroup(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	e := Executor{Path: bin, MaxOutputBytes: 1024 * 1024}
	start := time.Now()
	result, err := e.Execute(context.Background(), "timeout-test", "shell.exec", map[string]any{"command": "printf partial; sleep 10", "timeout_seconds": 1}, 6*time.Second)
	if err != nil {
		t.Fatalf("timeout should return a structured shell result: %v", err)
	}
	var timeoutFields map[string]any
	if err := json.Unmarshal(result.Response.Result, &timeoutFields); err != nil {
		t.Fatal(err)
	}
	if timeoutFields["timed_out"] != true {
		t.Fatalf("expected timed_out=true, got %#v", timeoutFields)
	}
	if timeoutFields["stdout"] != "partial" || timeoutFields["cleanup_complete"] != true {
		t.Fatalf("expected partial output and completed process cleanup, got %#v", timeoutFields)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("timeout cleanup took too long: %s", time.Since(start))
	}
}

func TestPythonParityOperations(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	e := Executor{Path: bin, MaxOutputBytes: 1024 * 1024}
	ctx := context.Background()

	info, err := e.Execute(ctx, "parity-info", "system.info", map[string]any{}, 15*time.Second)
	if err != nil {
		t.Fatalf("system.info: %v", err)
	}
	var infoFields map[string]any
	if err := json.Unmarshal(info.Response.Result, &infoFields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"system", "release", "version", "machine", "hostname", "uptime", "disk", "memory", "runtime"} {
		if _, ok := infoFields[key]; !ok {
			t.Errorf("system.info missing %q", key)
		}
	}
	if infoFields["runtime"] != "Go SDK + C executor" {
		t.Errorf("system.info runtime=%v, want Go SDK + C executor", infoFields["runtime"])
	}

	path := filepath.Join(t.TempDir(), "parity.txt")
	write, err := e.Execute(ctx, "parity-write", "file.write", map[string]any{"path": path, "content": "alpha\nbeta\nalpha\n", "create_parents": false}, 5*time.Second)
	if err != nil {
		t.Fatalf("file.write: %v", err)
	}
	var writeFields map[string]any
	if err := json.Unmarshal(write.Response.Result, &writeFields); err != nil {
		t.Fatal(err)
	}
	if writeFields["previously_existed"] != false {
		t.Errorf("new file previously_existed=%v", writeFields["previously_existed"])
	}

	read, err := e.Execute(ctx, "parity-read", "file.read", map[string]any{"path": path, "max_bytes": 5}, 5*time.Second)
	if err != nil {
		t.Fatalf("file.read: %v", err)
	}
	var readFields map[string]any
	if err := json.Unmarshal(read.Response.Result, &readFields); err != nil {
		t.Fatal(err)
	}
	if readFields["content"] != "alpha" || readFields["truncated"] != true {
		t.Errorf("unexpected truncated read: %#v", readFields)
	}

	replace, err := e.Execute(ctx, "parity-replace", "file.replace", map[string]any{"path": path, "old_text": "alpha", "new_text": "omega", "replace_all": false}, 5*time.Second)
	if err != nil {
		t.Fatalf("file.replace: %v", err)
	}
	var replaceFields map[string]any
	if err := json.Unmarshal(replace.Response.Result, &replaceFields); err != nil {
		t.Fatal(err)
	}
	if replaceFields["matches"] != float64(2) || replaceFields["replacements"] != float64(1) {
		t.Errorf("unexpected replacement counts: %#v", replaceFields)
	}

	shell, err := e.Execute(ctx, "parity-shell", "shell.exec", map[string]any{"command": "printf out; printf err >&2; exit 7"}, 5*time.Second)
	if err != nil {
		t.Fatalf("non-zero shell exit should be a result, not transport error: %v", err)
	}
	var shellFields map[string]any
	if err := json.Unmarshal(shell.Response.Result, &shellFields); err != nil {
		t.Fatal(err)
	}
	if shellFields["returncode"] != float64(7) || shellFields["stdout"] != "out" || shellFields["stderr"] != "err" {
		t.Errorf("unexpected shell result: %#v", shellFields)
	}
}

func BenchmarkProcessExecutor(b *testing.B) {
	e := &Executor{MaxOutputBytes: 6 * 1024 * 1024}
	ctx := context.Background()
	root := b.TempDir()
	dir := filepath.Join(root, "listing")
	if err := os.Mkdir(dir, 0700); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("item-%03d.txt", i)), []byte("x"), 0600); err != nil {
			b.Fatal(err)
		}
	}
	b.Run("list_directory_100", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r, err := e.Execute(ctx, "bench", "directory.list", map[string]any{"path": dir}, 5*time.Second)
			if err != nil {
				b.Fatal(err)
			}
			var envelope map[string]any
			if err = json.Unmarshal(r.Response.Result, &envelope); err != nil {
				b.Fatal(err)
			}
			if _, err = json.Marshal(envelope["entries"]); err != nil {
				b.Fatal(err)
			}
		}
	})
	for _, size := range []int{1024, 100 * 1024, 1024 * 1024} {
		data := strings.Repeat("a", size)
		path := filepath.Join(root, fmt.Sprintf("file-%d.txt", size))
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("read_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r, err := e.Execute(ctx, "bench", "file.read", map[string]any{"path": path, "max_bytes": size}, 5*time.Second)
				if err != nil {
					b.Fatal(err)
				}
				if r.Value != nil {
					if _, err = json.Marshal(r.Value); err != nil {
						b.Fatal(err)
					}
				} else if _, err = json.Marshal(r.Response.Result); err != nil {
					b.Fatal(err)
				}
			}
		})
		writePath := filepath.Join(root, fmt.Sprintf("write-%d.txt", size))
		b.Run(fmt.Sprintf("write_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r, err := e.Execute(ctx, "bench", "file.write", map[string]any{"path": writePath, "content": data, "create_parents": false}, 5*time.Second)
				if err != nil {
					b.Fatal(err)
				}
				var fields map[string]any
				if err = json.Unmarshal(r.Response.Result, &fields); err != nil {
					b.Fatal(err)
				}
				out := map[string]any{"success": true, "path": fields["path"], "previously_existed": fields["previously_existed"], "characters_written": fields["characters_written"]}
				if _, err = json.Marshal(out); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestGoShellExecutorDoesNotLaunchCExecutor(t *testing.T) {
	e := &Executor{Path: "/definitely/not/a/real/c-executor", MaxOutputBytes: 1024 * 1024}
	result, err := e.Execute(context.Background(), "go-shell", "shell.exec", map[string]any{"command": "printf out; printf err >&2; exit 7"}, 5*time.Second)
	if err != nil {
		t.Fatalf("shell command should return structured result: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(result.Response.Result, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["returncode"] != float64(7) || fields["stdout"] != "out" || fields["stderr"] != "err" || fields["timed_out"] != false {
		t.Fatalf("unexpected Go shell result: %#v", fields)
	}
}

func TestGoShellExecutorTimeoutCleansProcessGroup(t *testing.T) {
	e := &Executor{}
	start := time.Now()
	result, err := e.Execute(context.Background(), "go-shell-timeout", "shell.exec", map[string]any{"command": "printf partial; sleep 10", "timeout_seconds": 1}, 5*time.Second)
	if err != nil {
		t.Fatalf("timeout should return structured result: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(result.Response.Result, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["timed_out"] != true || fields["stdout"] != "partial" || fields["cleanup_complete"] != true {
		t.Fatalf("unexpected timeout result: %#v", fields)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("timeout cleanup took too long: %s", time.Since(start))
	}
}

func BenchmarkShortShellGoDirect(b *testing.B) {
	e := &Executor{}
	input := map[string]any{"command": "printf x"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Execute(context.Background(), "bench-go-shell", "shell.exec", input, 5*time.Second); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkShortShellCProcess(b *testing.B) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	e := &Executor{Path: bin, MaxOutputBytes: 1024 * 1024}
	input := map[string]any{"command": "printf x"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Execute(context.Background(), "bench-c-shell", "shell.exec", input, 5*time.Second); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCExecutorRejectsNULInPath(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	r := runC(t, bin, "file.read", map[string]any{"path": "/tmp/invalid\x00suffix"})
	if r.OK || r.Error.Code != "INVALID_ARGUMENT" {
		t.Fatalf("expected INVALID_ARGUMENT for NUL path, got %#v", r)
	}
}

func TestExecutorRejectsMismatchedResponseTaskID(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-executor")
	script := "#!/bin/sh\nprintf '%s\\n' '{\"ok\":true,\"result\":{},\"task_id\":\"different-task\"}'\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	e := &Executor{Path: bin, MaxOutputBytes: 1024 * 1024}
	_, err := e.Execute(context.Background(), "expected-task", "system.info", map[string]any{}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "task_id mismatch") {
		t.Fatalf("expected task_id mismatch error, got %v", err)
	}
}

func TestExecutorRejectsOversizedRequestBeforeStartingProcess(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	bin := filepath.Join(dir, "fake-executor")
	script := "#!/bin/sh\ntouch " + marker + "\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	e := &Executor{Path: bin, MaxOutputBytes: 1024 * 1024}
	_, err := e.Execute(context.Background(), "large-task", "test.operation", map[string]any{"data": strings.Repeat("x", maxRequestBytes)}, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "request exceeds") {
		t.Fatalf("expected request size rejection, got %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("executor process should not start for oversized request, stat error=%v", statErr)
	}
}

func TestCExecutorRejectsOversizedStdin(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(strings.Repeat("x", maxRequestBytes+1))
	out, err := cmd.Output()
	if err == nil {
		t.Fatal("expected oversized stdin to return a non-zero exit status")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2, got %v", err)
	}
	var response wireResponse
	if unmarshalErr := json.Unmarshal(out, &response); unmarshalErr != nil {
		t.Fatalf("invalid oversized-input response %q: %v", out, unmarshalErr)
	}
	if response.OK || response.Error.Code != "INVALID_REQUEST" {
		t.Fatalf("unexpected oversized-input response: %#v", response)
	}
}

func TestProcessFileWriteAcceptsPayloadLargerThanLegacyDispatcherLimit(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	path := filepath.Join(t.TempDir(), "large-write.bin")
	content := strings.Repeat("z", 5*1024*1024)
	e := &Executor{Path: bin, MaxOutputBytes: 1024 * 1024}
	result, err := e.Execute(context.Background(), "large-write", "file.write", map[string]any{"path": path, "content": content}, 15*time.Second)
	if err != nil {
		t.Fatalf("5 MiB file.write failed: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(result.Response.Result, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["bytes_written"] != float64(len(content)) {
		t.Fatalf("bytes_written mismatch: %#v", fields)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatalf("large write content mismatch: got %d bytes, want %d", len(got), len(content))
	}
}

func TestProcessFileReadEscapedOutputFitsCompatibilityBudget(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	path := filepath.Join(t.TempDir(), "nul-data.bin")
	content := strings.Repeat("\x00", 2*1024*1024)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	e := &Executor{Path: bin, MaxOutputBytes: 1024 * 1024}
	result, err := e.Execute(context.Background(), "nul-read", "file.read", map[string]any{"path": path, "max_bytes": len(content)}, 15*time.Second)
	if err != nil {
		t.Fatalf("2 MiB escaped file.read failed: %v", err)
	}
	var fields struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(result.Response.Result, &fields); err != nil {
		t.Fatal(err)
	}
	if fields.Content != content {
		t.Fatalf("file.read content mismatch: got %d bytes, want %d", len(fields.Content), len(content))
	}
}

func TestProcessDirectoryListingStopsAtSerializedBudget(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	dir := t.TempDir()
	namePrefix := strings.Repeat("x", 180)
	for i := 0; i < 30000; i++ {
		name := fmt.Sprintf("%s-%05d", namePrefix, i)
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatalf("create directory fixture %d: %v", i, err)
		}
	}
	e := &Executor{Path: bin, MaxOutputBytes: 1024 * 1024}
	_, err := e.Execute(context.Background(), "large-directory", "directory.list", map[string]any{"path": dir}, 30*time.Second)
	if err == nil || !strings.Contains(err.Error(), "DIRECTORY_OUTPUT_LIMIT") {
		t.Fatalf("expected bounded directory listing error, got %v", err)
	}
}

func TestExecutorTimeoutKillsCExecutorDescendants(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	bin := filepath.Join(dir, "fake-executor")
	script := "#!/bin/sh\nsleep 30 &\nchild=$!\necho $child > " + pidFile + "\nwait\n"
	if err := os.WriteFile(bin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	e := &Executor{Path: bin, MaxOutputBytes: 1024 * 1024}
	_, err := e.Execute(context.Background(), "child-timeout", "system.info", map[string]any{}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "timed out or cancelled") {
		t.Fatalf("expected executor timeout, got %v", err)
	}
	pidBytes, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("read child pid: %v", readErr)
	}
	var pid int
	if _, scanErr := fmt.Sscanf(string(pidBytes), "%d", &pid); scanErr != nil || pid <= 0 {
		t.Fatalf("invalid child pid %q: %v", pidBytes, scanErr)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if killErr := syscall.Kill(pid, 0); killErr == syscall.ESRCH {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("executor descendant pid %d still exists after process-group cleanup", pid)
}

func TestCExecutorShellTimeoutKillsDescendants(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	request, _ := json.Marshal(map[string]any{
		"protocol_version": "1", "task_id": "c-shell-child-timeout", "operation": "shell.exec",
		"input": map[string]any{"command": "sleep 30 & child=$!; echo $child; wait", "timeout_seconds": 1},
	})
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(string(request) + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("C executor shell timeout returned process error: %v (%s)", err, out)
	}
	var response struct {
		OK     bool `json:"ok"`
		Result struct {
			Stdout          string `json:"stdout"`
			TimedOut        bool   `json:"timed_out"`
			CleanupComplete bool   `json:"cleanup_complete"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatalf("decode C timeout response %q: %v", out, err)
	}
	if !response.OK || !response.Result.TimedOut || !response.Result.CleanupComplete {
		t.Fatalf("unexpected C timeout result: %#v", response)
	}
	var pid int
	if _, err := fmt.Sscanf(response.Result.Stdout, "%d", &pid); err != nil || pid <= 0 {
		t.Fatalf("invalid child pid in stdout %q: %v", response.Result.Stdout, err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("C executor descendant pid %d still exists (kill error=%v)", pid, err)
	}
}

func TestCExecutorServiceStatusContract(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	r := runC(t, bin, "service.status", map[string]any{"service": "nonexistent_test_service"})
	if !r.OK {
		t.Fatalf("service.status should return command status as result: %#v", r.Error)
	}
	for _, key := range []string{"service", "action", "exit_code", "stdout", "stderr"} {
		if _, ok := r.Result[key]; !ok {
			t.Errorf("service.status result missing %q: %#v", key, r.Result)
		}
	}
	if r.Result["service"] != "nonexistent_test_service" || r.Result["action"] != "status" {
		t.Fatalf("unexpected service.status identity: %#v", r.Result)
	}
}

func TestCExecutorLogsTailContract(t *testing.T) {
	bin := os.Getenv("C_EXECUTOR_TEST_PATH")
	if bin == "" {
		bin = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	path := filepath.Join(t.TempDir(), "sample.log")
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\nfour\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := runC(t, bin, "logs.tail", map[string]any{"path": path, "lines": 2})
	if !r.OK {
		t.Fatalf("logs.tail failed: %#v", r.Error)
	}
	if r.Result["stdout"] != "three\nfour\n" || r.Result["returncode"] != float64(0) {
		t.Fatalf("unexpected logs.tail result: %#v", r.Result)
	}
}
