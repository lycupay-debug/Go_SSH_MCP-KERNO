# Language replacement benchmark (first synchronous parity pass)

Test environment: FreeBSD 15.1 amd64. File cases used temporary files only. These measurements describe one host and are not general performance guarantees.

## Method

- Python baseline: call the existing Python tool function in-process, then JSON-serialize its return value to approximate MCP result encoding. For filesystem cases, 20 warmups and 1,000 timed repetitions were used.
- Go/C filesystem path: call the native C implementation through cgo, apply the Go tool adapter's output-shape projection, then JSON-serialize the result. Each case ran 1,000 timed repetitions. This includes typed Go-to-C argument handling, C operation, result projection and response JSON encoding.
- System information and shell were measured separately with 10 warmups and 100 repetitions. The C version includes starting the isolated C executor process and JSON IPC; the Python version includes the Python tool function and result JSON encoding.
- These are same-host microbenchmarks, not a complete HTTP/MCP/OAuth end-to-end benchmark. Host scheduling and filesystem cache state still introduce noise. Treat the results as the first language-replacement comparison, not the final production acceptance test.

## Local filesystem results

Median milliseconds; Python and Go/C result payloads are JSON-serialized in both harnesses. P95 for the Go/C filesystem microbenchmarks was not collected in this run.

| Operation | Python median | Go/C median | Result |
|---|---:|---:|---:|---|
| List directory (100 entries) | 1.268 | 0.714 | 1.78× faster |
| Read 1 KiB | 0.0208 | 0.0066 | 3.13× faster |
| Read 100 KiB | 0.3956 | 0.1500 | 2.64× faster |
| Read 1 MiB | 3.9434 | 1.8774 | 2.10× faster |
| Write 1 KiB | 0.0255 | 0.0158 | 1.62× faster |
| Write 100 KiB | 0.0327 | 0.0236 | 1.38× faster |
| Write 1 MiB | 0.1743 | 0.1331 | 1.31× faster |

The Python comparison harness used for the original baseline is not included in this public repository. The Go/C microbenchmark can be repeated with `go test ./internal/executor -run '^$' -bench BenchmarkNativeExecutor -benchmem -benchtime=1000x`. Treat the values above as a recorded, host-specific result rather than a universal performance claim.

## Process-backed operations

| Operation | Python median | C process median | Python P95 | C process P95 |
|---|---:|---:|---:|---:|
| `get_system_info` | 12.89 ms | 11.54 ms | 14.34 ms | 12.01 ms |
| `execute_shell('printf x')` | 4.48 ms | 7.38 ms | 5.26 ms | 8.17 ms |

The C process path is about 1.12× faster for system information but about 1.65× slower for a short shell command. The shell path deliberately retains a separate process group for timeout/cancellation safety. This overhead is measurable and is not being presented as a performance win.

## Interpretation and remaining acceptance

- After removing the per-call C process from local filesystem operations, the current same-host microbenchmark is faster than Python for the tested list/read/write sizes.
- Short shell commands remain slower because each call starts an isolated C executor process. Keep the timeout and process-group cleanup guarantees; do not remove them solely to improve a microbenchmark.
- This does **not** yet prove end-to-end ChatGPT/MCP latency or OAuth continuity after production cutover. The measurements do not establish end-to-end MCP/OAuth latency or deployment acceptance. Run the full OAuth and authenticated-tool acceptance checklist in the intended staging environment before production use.
- Before deployment, compare each tool's output/error contract against the baseline and report HTTP median/P95 and error counts. Use a dedicated staging environment and test database.
