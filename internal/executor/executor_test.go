package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func BenchmarkNativeExecutor(b *testing.B) {
	e := &Executor{Native: true, MaxOutputBytes: 6 * 1024 * 1024}
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
	e := &Executor{Path: "/definitely/not/a/real/c-executor", Native: true, MaxOutputBytes: 1024 * 1024}
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
	e := &Executor{Native: true}
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
	e := &Executor{Native: true}
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
	e := &Executor{Path: bin, Native: false, MaxOutputBytes: 1024 * 1024}
	input := map[string]any{"command": "printf x"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Execute(context.Background(), "bench-c-shell", "shell.exec", input, 5*time.Second); err != nil {
			b.Fatal(err)
		}
	}
}
