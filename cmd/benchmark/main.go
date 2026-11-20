package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/executor"
)

func main() {
	executorPath := flag.String("executor", os.Getenv("C_EXECUTOR_TEST_PATH"), "candidate C Executor path")
	tempDir := flag.String("temp-dir", "", "directory for benchmark files; defaults to the OS temp directory")
	iterations := flag.Int("iterations", 200, "timed samples per case")
	warmup := flag.Int("warmup", 10, "warmup samples per case")
	flag.Parse()

	if *executorPath == "" {
		*executorPath = filepath.Join("bin", "host-executor-candidate")
	}
	if *iterations < 20 || *iterations > 10000 || *warmup < 0 || *warmup > 1000 {
		fmt.Fprintln(os.Stderr, "iterations must be 20..10000 and warmup must be 0..1000")
		os.Exit(2)
	}
	if info, err := os.Stat(*executorPath); err != nil || !info.Mode().IsRegular() {
		fmt.Fprintf(os.Stderr, "candidate C Executor is unavailable: %s\n", *executorPath)
		os.Exit(2)
	}

	binary, err := os.ReadFile(*executorPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	sum := sha256.Sum256(binary)

	commitBytes, err := osexec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read source commit: %v\n", err)
		os.Exit(2)
	}
	statusBytes, err := osexec.Command("git", "status", "--porcelain").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read worktree status: %v\n", err)
		os.Exit(2)
	}
	sourceHashes := map[string]string{}
	for _, source := range []string{"cmd/benchmark/main.go", "internal/executor/executor.go", "executor/c/executor_impl.inc", "executor/c/Makefile"} {
		content, readErr := os.ReadFile(source)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "read source %s: %v\n", source, readErr)
			os.Exit(2)
		}
		digest := sha256.Sum256(content)
		sourceHashes[source] = hex.EncodeToString(digest[:])
	}

	root, err := os.MkdirTemp(*tempDir, "kerno-current-benchmark-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer os.RemoveAll(root)

	listDir := filepath.Join(root, "listing")
	if err := os.Mkdir(listDir, 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for i := 0; i < 100; i++ {
		name := filepath.Join(listDir, fmt.Sprintf("item-%03d.txt", i))
		if err := os.WriteFile(name, []byte("x"), 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}

	filePath := filepath.Join(root, "payload.bin")
	data := strings.Repeat("needle", 174762)
	if err := os.WriteFile(filePath, []byte(data), 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	expectedMatches := float64(strings.Count(data, "needle"))

	e := &executor.Executor{Path: *executorPath, MaxOutputBytes: 16 * 1024 * 1024}
	ctx := context.Background()
	var results []map[string]any
	failures := 0

	add := func(name string, fn func(int) error) {
		result := runCase(name, *iterations, *warmup, fn)
		results = append(results, result)
		if result["errors"].(int) != 0 {
			failures += result["errors"].(int)
		}
	}

	add("system.info", func(i int) error {
		r, err := e.Execute(ctx, fmt.Sprintf("bench-system-%d", i), "system.info", map[string]any{}, 30*time.Second)
		if err != nil {
			return err
		}
		var value map[string]any
		if err := json.Unmarshal(r.Response.Result, &value); err != nil {
			return err
		}
		if value["runtime"] != "Go SDK + C executor" {
			return fmt.Errorf("unexpected runtime field: %v", value["runtime"])
		}
		return nil
	})

	add("directory.list_100", func(i int) error {
		r, err := e.Execute(ctx, fmt.Sprintf("bench-list-%d", i), "directory.list", map[string]any{"path": listDir}, 30*time.Second)
		if err != nil {
			return err
		}
		var value map[string]any
		if err := json.Unmarshal(r.Response.Result, &value); err != nil {
			return err
		}
		entries, ok := value["entries"].([]any)
		if !ok || len(entries) != 100 {
			return fmt.Errorf("directory.list returned %d entries, want 100", len(entries))
		}
		return nil
	})

	add("file.read_1MiB", func(i int) error {
		r, err := e.Execute(ctx, fmt.Sprintf("bench-read-%d", i), "file.read", map[string]any{"path": filePath, "max_bytes": 2 * 1024 * 1024}, 30*time.Second)
		if err != nil {
			return err
		}
		var value map[string]any
		if err := json.Unmarshal(r.Response.Result, &value); err != nil {
			return err
		}
		if value["content"] != data {
			return fmt.Errorf("file.read output mismatch")
		}
		return nil
	})

	add("file.write_1MiB_direct", func(i int) error {
		_, err := e.Execute(ctx, fmt.Sprintf("bench-write-direct-%d", i), "file.write", map[string]any{"path": filePath, "content": data}, 30*time.Second)
		return err
	})

	add("file.write_1MiB_atomic", func(i int) error {
		_, err := e.Execute(ctx, fmt.Sprintf("bench-write-atomic-%d", i), "file.write", map[string]any{"path": filePath, "content": data, "atomic": true}, 30*time.Second)
		return err
	})

	add("file.replace_1MiB_all", func(i int) error {
		if err := os.WriteFile(filePath, []byte(data), 0600); err != nil {
			return err
		}
		r, err := e.Execute(ctx, fmt.Sprintf("bench-replace-%d", i), "file.replace", map[string]any{
			"path": filePath, "old_text": "needle", "new_text": "change", "replace_all": true,
		}, 60*time.Second)
		if err != nil {
			return err
		}
		var value map[string]any
		if err := json.Unmarshal(r.Response.Result, &value); err != nil {
			return err
		}
		if value["matches"] != expectedMatches || value["replacements"] != expectedMatches {
			return fmt.Errorf("replace counts mismatch: matches=%v replacements=%v", value["matches"], value["replacements"])
		}
		return nil
	})

	add("execute_shell_go_printf", func(i int) error {
		r, err := e.Execute(ctx, fmt.Sprintf("bench-shell-%d", i), "shell.exec", map[string]any{"command": "printf x"}, 5*time.Second)
		if err != nil {
			return err
		}
		var value map[string]any
		if err := json.Unmarshal(r.Response.Result, &value); err != nil {
			return err
		}
		if value["stdout"] != "x" || value["returncode"] != float64(0) {
			return fmt.Errorf("shell output mismatch: %#v", value)
		}
		return nil
	})

	report := map[string]any{
		"timestamp_utc":   time.Now().UTC().Format(time.RFC3339),
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"go_version":      runtime.Version(),
		"executor_path":   *executorPath,
		"benchmark_dir":   root,
		"executor_sha256": hex.EncodeToString(sum[:]),
		"git_commit":      strings.TrimSpace(string(commitBytes)),
		"git_status":      strings.TrimSpace(string(statusBytes)),
		"source_sha256":   sourceHashes,
		"iterations":      *iterations,
		"warmup":          *warmup,
		"results":         results,
		"total_errors":    failures,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if failures != 0 {
		os.Exit(1)
	}
}

func runCase(name string, iterations, warmup int, fn func(int) error) map[string]any {
	for i := 0; i < warmup; i++ {
		if err := fn(-i - 1); err != nil {
			return map[string]any{"name": name, "samples": 0, "errors": 1, "error": err.Error()}
		}
	}
	samples := make([]float64, 0, iterations)
	errorsCount := 0
	errorSamples := make([]string, 0, 3)
	start := time.Now()
	for i := 0; i < iterations; i++ {
		one := time.Now()
		if err := fn(i); err != nil {
			errorsCount++
			if len(errorSamples) < 3 {
				errorSamples = append(errorSamples, err.Error())
			}
			continue
		}
		samples = append(samples, float64(time.Since(one).Microseconds())/1000)
	}
	elapsed := time.Since(start)
	if len(samples) == 0 {
		return map[string]any{"name": name, "samples": 0, "errors": errorsCount, "elapsed_ms": float64(elapsed.Microseconds()) / 1000}
	}
	sort.Float64s(samples)
	median := percentile(samples, 0.50)
	p95 := percentile(samples, 0.95)
	return map[string]any{
		"name":               name,
		"samples":            len(samples),
		"errors":             errorsCount,
		"error_samples":      errorSamples,
		"median_ms":          median,
		"p95_ms":             p95,
		"min_ms":             samples[0],
		"max_ms":             samples[len(samples)-1],
		"throughput_ops_sec": float64(len(samples)) / elapsed.Seconds(),
		"elapsed_ms":         float64(elapsed.Microseconds()) / 1000,
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(p*float64(len(sorted))+0.999999) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
