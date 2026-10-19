package parallel

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func task(id, cwd, command string, timeout int) Task {
	return Task{TaskID: id, WorkingDirectory: cwd, Command: command, TimeoutSeconds: timeout}
}

func TestRunExecutesEightTasksConcurrently(t *testing.T) {
	root := t.TempDir()
	tasks := make([]Task, 8)
	for i := range tasks {
		cwd := filepath.Join(root, string(rune('a'+i)))
		if err := os.Mkdir(cwd, 0700); err != nil {
			t.Fatal(err)
		}
		tasks[i] = task("task-"+string(rune('a'+i)), cwd, "sleep 0.35; printf done", 5)
	}
	start := time.Now()
	result, err := Run(context.Background(), Request{Tasks: tasks, MaxParallel: 8}, filepath.Join(root, "logs"), nil)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if result.MaxParallel != 8 || result.TaskCount != 8 {
		t.Fatalf("unexpected run summary: %#v", result)
	}
	if elapsed > 1800*time.Millisecond {
		t.Fatalf("8 tasks did not run concurrently; elapsed=%s", elapsed)
	}
	for _, item := range result.Results {
		if item.Status != "succeeded" || item.Output != "done" || item.ReturnCode == nil || *item.ReturnCode != 0 {
			t.Errorf("unexpected task result: %#v", item)
		}
		info, err := os.Stat(item.LogPath)
		if err != nil {
			t.Errorf("task log missing: %v", err)
		} else if info.Mode().Perm() != 0600 {
			t.Errorf("task log mode=%o, want 600", info.Mode().Perm())
		}
	}
}

func TestValidateCapsMaxParallelAtEight(t *testing.T) {
	root := t.TempDir()
	tasks := []Task{task("a", root, "true", 1), task("b", filepath.Dir(root), "true", 1)}
	if _, _, err := validate(Request{Tasks: tasks, MaxParallel: 9}); err == nil || !strings.Contains(err.Error(), "1 至 8") {
		t.Fatalf("expected max_parallel limit error, got %v", err)
	}
}

func TestValidateRejectsDuplicateTaskIDsAndDirectories(t *testing.T) {
	root := t.TempDir()
	if _, _, err := validate(Request{Tasks: []Task{task("same", root, "true", 1), task("same", filepath.Join(root, "child"), "true", 1)}}); err == nil {
		t.Fatal("duplicate task IDs must be rejected")
	}
	if err := os.Mkdir(filepath.Join(root, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validate(Request{Tasks: []Task{task("a", root, "true", 1), task("b", root, "true", 1)}}); err == nil || !strings.Contains(err.Error(), "同一工作目录") {
		t.Fatalf("expected duplicate directory error, got %v", err)
	}
}

func TestValidateRejectsSameGitWorktree(t *testing.T) {
	root := t.TempDir()
	if err := exec.Command("git", "init", "-q", root).Run(); err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	if err := os.Mkdir(a, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(b, 0700); err != nil {
		t.Fatal(err)
	}
	_, _, err := validate(Request{Tasks: []Task{task("a", a, "true", 1), task("b", b, "true", 1)}})
	if err == nil || !strings.Contains(err.Error(), "同一个 Git 工作树") {
		t.Fatalf("expected same worktree rejection, got %v", err)
	}
}

func TestRunTimesOutAndKillsProcessGroup(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	if err := os.Mkdir(a, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(b, 0700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	result, err := Run(context.Background(), Request{Tasks: []Task{task("slow", a, "printf partial; sleep 10", 1), task("fast", b, "printf ok", 5)}, MaxParallel: 2}, filepath.Join(root, "logs"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Results[0].Status != "timed_out" || !result.Results[0].TimedOut || !result.Results[0].CleanupComplete {
		t.Fatalf("timeout did not report cleanup: %#v", result.Results[0])
	}
	if result.Results[0].Output != "partial" {
		t.Fatalf("partial output lost: %#v", result.Results[0])
	}
	if result.Results[1].Status != "succeeded" {
		t.Fatalf("fast task failed: %#v", result.Results[1])
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("timeout cleanup too slow: %s", time.Since(start))
	}
}

func TestRunStopsAtOutputLimit(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	if err := os.Mkdir(a, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(b, 0700); err != nil {
		t.Fatal(err)
	}
	result, err := Run(context.Background(), Request{Tasks: []Task{task("noisy", a, "yes x | head -c 2000000", 10), task("other", b, "true", 5)}, MaxParallel: 2}, filepath.Join(root, "logs"), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := result.Results[0]
	if got.Status != "output_limited" || !got.OutputLimited || !got.CleanupComplete {
		t.Fatalf("output cap not enforced: %#v", got)
	}
	info, err := os.Stat(got.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > MaxOutputBytes {
		t.Fatalf("log exceeded cap: %d", info.Size())
	}
}

func TestValidateRejectsProtectedProjectDirectory(t *testing.T) {
	if info, err := os.Stat(protectedRoot); err != nil || !info.IsDir() {
		t.Skip("protected project path does not exist on this host")
	}
	other := t.TempDir()
	_, _, err := validate(Request{Tasks: []Task{task("a", protectedRoot, "true", 1), task("b", other, "true", 1)}})
	if err == nil || !strings.Contains(err.Error(), "禁止在 /opt/kerno 内运行") {
		t.Fatalf("expected protected directory rejection, got %v", err)
	}
}

func TestGlobalParallelSlotPoolIsBoundedAtEight(t *testing.T) {
	if cap(globalSlots) != 8 {
		t.Fatalf("global parallel slots=%d, want 8", cap(globalSlots))
	}
	root := t.TempDir()
	var tasks []Task
	for i := 0; i < 8; i++ {
		cwd := filepath.Join(root, "run", string(rune('a'+i)))
		if err := os.MkdirAll(cwd, 0700); err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, task("a"+string(rune('a'+i)), cwd, "sleep 0.08", 3))
	}
	for i := 0; i < 8; i++ {
		cwd := filepath.Join(root, "run2", string(rune('a'+i)))
		if err := os.MkdirAll(cwd, 0700); err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, task("b"+string(rune('a'+i)), cwd, "sleep 0.08", 3))
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, batch := range [][]Task{tasks[:8], tasks[8:]} {
		wg.Add(1)
		go func(batch []Task) {
			defer wg.Done()
			_, err := Run(context.Background(), Request{Tasks: batch, MaxParallel: 8}, filepath.Join(root, "logs"), nil)
			errs <- err
		}(batch)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(globalSlots) > 8 {
		t.Fatalf("global active task count exceeded cap: %d", len(globalSlots))
	}
}
