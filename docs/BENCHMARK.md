# Historical language-replacement benchmark (pre-IPC migration)

Test environment: FreeBSD 15.1 amd64. File cases used temporary files only. These measurements describe one host and are not general performance guarantees.

Historical note: these measurements were collected before the P1 migration of all local C operations from in-process cgo to the standalone C Executor. The filesystem numbers therefore do not describe the current process-per-operation architecture and must not be used as current release performance claims. A new benchmark run is required after feature freeze.

## Method

- Python baseline: call the existing Python tool function in-process, then JSON-serialize its return value to approximate MCP result encoding. For filesystem cases, 20 warmups and 1,000 timed repetitions were used.
- Historical Go/C filesystem path: call the native C implementation through cgo, apply the Go tool adapter's output-shape projection, then JSON-serialize the result. This is the pre-P1 architecture, not the current runtime path.
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

The Python comparison harness used for the original baseline is not included in this public repository. The original Go/C microbenchmark harness and its numbers are historical. Rebuild a benchmark harness for the current standalone-process architecture before making current performance claims.

## Process-backed operations

| Operation | Python median | C process median | Python P95 | C process P95 |
|---|---:|---:|---:|---:|
| `get_system_info` | 12.89 ms | 11.54 ms | 14.34 ms | 12.01 ms |
| `execute_shell('printf x')` | 4.48 ms | 7.38 ms | 5.26 ms | 8.17 ms |

The C process path is about 1.12× faster for system information but about 1.65× slower for a short shell command. The shell path deliberately retains a separate process group for timeout/cancellation safety. This overhead is measurable and is not being presented as a performance win.

## Interpretation and remaining acceptance

- The historical cgo filesystem measurements are not comparable to the current one-shot C Executor JSON IPC path.
- Short shell commands remain slower because each call starts an isolated C executor process. Keep the timeout and process-group cleanup guarantees; do not remove them solely to improve a microbenchmark.
- This does **not** yet prove end-to-end ChatGPT/MCP latency or OAuth continuity after production cutover. The measurements do not establish end-to-end MCP/OAuth latency or deployment acceptance. Run the full OAuth and authenticated-tool acceptance checklist in the intended staging environment before production use.
- Current architecture preliminary sequential benchmark: recorded in the section below. Before unified deployment, rerun against the final frozen release candidate and separately measure full HTTP/MCP/OAuth latency, concurrency, failures, throughput and output equivalence in a dedicated staging environment and test database.

## Current standalone C Executor benchmark (2026-11-20)

This section measures the current process-per-request architecture. It is separate from the historical cgo measurements above.

### Reproducibility and environment

- OS/architecture: FreeBSD 15.1 amd64.
- Host CPU/memory visible to the VM: Intel Xeon Platinum 8488C, 2 vCPU, 8 GiB RAM.
- Go: 1.26.9.
- Test filesystem: temporary 256 MiB mdconfig UFS volume created with `newfs -U`; it was mounted only for the benchmark and detached afterward.
- Each C-backed operation starts one C Executor process, sends one JSON request over stdin, receives one JSON response over stdout, then exits. `execute_shell_go_printf` is the Go `os/exec` route and is not a C Executor operation.
- Three independent runs; each case has 5 warmups and 100 timed samples. Cases execute sequentially; this is not a concurrency/load test.
- Payload: 1,048,572 bytes; directory listing: 100 entries; replace: replace all `needle` occurrences with `change`.
- Candidate C Executor SHA-256: `8a299105ca72b569b534b261714a421c4f7f14c64af6bbf5fe04b6d07d8ee4c5`.
- Source commit: `a8fe9d05fa5f9c98ab0a473d5532803f0d5cfde1`; worktree was dirty. The report also recorded per-file source SHA-256 values for the benchmark harness, Go executor, C executor implementation, and C Makefile. This is a candidate-worktree measurement, not a release artifact claim.

### Results

The table reports the arithmetic mean of the three per-run medians, the observed range of the three P95 values, and the observed throughput range. Every case completed 100/100 samples in all three runs; total errors were zero in each run.

| Operation | Mean of run medians (ms) | P95 range (ms) | Throughput range (ops/s) |
|---|---:|---:|---:|
| `system.info` | 5.482 | 5.716–6.774 | 177.02–180.59 |
| `directory.list` (100 entries) | 1.534 | 1.851–1.893 | 621.05–649.41 |
| `file.read` (1 MiB) | 12.923 | 13.664–16.113 | 74.46–76.53 |
| `file.write` (1 MiB, direct) | 12.451 | 13.486–13.684 | 77.65–78.56 |
| `file.write` (1 MiB, atomic) | 13.332 | 14.148–14.528 | 72.90–74.03 |
| `file.replace` (1 MiB, replace all) | 3.862 | 4.081–4.407 | 248.48–257.17 |
| Go shell (`printf x`) | 1.090 | 1.217–1.682 | 739.93–957.89 |

### Atomic-operation stability note

A separate 100-attempt repetition on the isolated UFS test volume produced 0 failures for atomic write; another 100-attempt repetition produced 0 failures for atomic replace. The benchmark's three runs likewise produced 300/300 successful atomic writes and 300/300 successful atomic replacements.

Historical diagnostic for the earlier candidate: the host root UFS showed intermittent ctime-only changes, while the isolated UFS volume did not. The later atomic durability update and its root-UFS regression results are documented in “Current candidate benchmark after atomic durability update” below. The earlier measurements and diagnosis are retained here as historical evidence, not as the current candidate status.

### Limitations

- Sequential microbenchmark only; no concurrent saturation, long-duration soak, HTTP/MCP/OAuth, or remote SSH measurements.
- Measurements include process creation and JSON IPC for C operations, but exclude the full authenticated network path.
- At the time of this historical benchmark, ACL/extattr-only concurrent changes were still an open limitation. The later metadata-fingerprint implementation and deterministic race tests are recorded in the final section below.
- Do not compare these numbers directly with the historical in-process cgo filesystem measurements above.


## Current candidate benchmark after atomic durability update (2026-11-20)

This later measurement supersedes the earlier preliminary benchmark table for the current candidate. It uses the same test method and a fresh temporary UFS volume.

- OS/architecture: FreeBSD 15.1 amd64; Intel Xeon Platinum 8488C, 2 vCPU, 8 GiB visible RAM; Go 1.26.9.
- Test filesystem: temporary 256 MiB mdconfig UFS (`newfs -U`), mounted for the three runs and detached afterward.
- Three independent runs; 5 warmups and 100 timed samples per case; sequential execution; all cases completed 100/100 samples with 0 errors in every run.
- Candidate C Executor SHA-256: `800f447a09402b6ddc1335f10d6e04f0b9e33d7397f0d38485e401c5d1be0536`.
- Source commit: `a8fe9d05fa5f9c98ab0a473d5532803f0d5cfde1`; worktree dirty.
- Source SHA-256: `cmd/benchmark/main.go` `1afd342da2539d75b18ff92cf901f0a3670a38c42e7617d8f4576a02255b6187`; `internal/executor/executor.go` `ba1d7a7f0638ee75f03890fec7afd1e82f9bca8f8ff4a50e950aceea9e6d6db1`; `executor/c/executor_impl.inc` `e24f4cb9913987e22ef4606c4907e801f252afdc8234ffdd77c7bb6146b7c216`; `executor/c/Makefile` `4fb444ab9e5caab904a8bbb16d8809f3f84c5fd7e254d58750bb87081d7070c3`.

| Operation | Mean of run medians (ms) | P95 range (ms) | Throughput range (ops/s) |
|---|---:|---:|---:|
| `system.info` | 5.444 | 5.544–5.828 | 176.05–183.93 |
| `directory.list` (100 entries) | 1.549 | 1.894–2.476 | 558.56–627.70 |
| `file.read` (1 MiB) | 12.959 | 13.632–15.394 | 74.49–75.42 |
| `file.write` (1 MiB, direct) | 12.343 | 13.052–13.800 | 78.52–80.50 |
| `file.write` (1 MiB, atomic) | 13.158 | 14.030–14.287 | 74.01–75.30 |
| `file.replace` (1 MiB, replace all) | 4.435 | 4.618–6.395 | 218.56–226.95 |
| Go shell (`printf x`) | 1.093 | 1.311–1.735 | 783.08–911.37 |

The benchmark includes one C process startup and JSON stdin/stdout IPC per C-backed operation. The shell case is the Go native route. This remains a sequential microbenchmark, not a full MCP/OAuth or concurrency benchmark. Atomic file write/replace now include source and post-rename durability synchronization; compare these numbers only against measurements with the same semantics.

## Final candidate benchmark after write-and-replace ctime adjustment (2026-11-20)

This is the latest candidate measurement and supersedes the preceding candidate tables.

- Environment: FreeBSD 15.1 amd64; Intel Xeon Platinum 8488C; 2 vCPU; 8 GiB visible RAM; Go 1.26.9.
- Filesystem: temporary 256 MiB mdconfig UFS (`newfs -U`), unmounted and detached after the three runs.
- Three independent runs; 5 warmups + 100 samples per case per run; sequential; all 100/100 samples succeeded with zero errors in every case.
- C Executor SHA-256: `8dfd29d585a4e22f2d7938a0008d28e0d6fcedc9e35787f3c5825b936b27252a`.
- Go GSM SHA-256: `8cafda7a56ae1fcf28d144757bad30791f758054cbc1668da03a34daede468da`.
- admin-user SHA-256: `e7a01a7a594dc871cb2fa2150fc388ff132cc1845e08f8cbf5c228ec7a5bb98c`.
- Git HEAD: `a8fe9d05fa5f9c98ab0a473d5532803f0d5cfde1` (dirty worktree).
- `executor/c/executor_impl.inc` SHA-256: `0e26e0ed398c26d2eae49c0f32a2081f892b79cac93b5126e152ed277c391cb1`.

| Operation | Mean of run medians (ms) | P95 range (ms) | Throughput range (ops/s) |
|---|---:|---:|---:|
| `system.info` | 5.500 | 5.700–7.361 | 174.42–181.63 |
| `directory.list` (100 entries) | 1.551 | 1.908–1.942 | 622.52–631.50 |
| `file.read` (1 MiB) | 12.950 | 13.704–14.643 | 74.11–75.85 |
| `file.write` (1 MiB, direct) | 12.287 | 13.164–15.174 | 79.04–80.93 |
| `file.write` (1 MiB, atomic) | 13.101 | 14.069–14.679 | 74.16–74.34 |
| `file.replace` (1 MiB, replace all) | 4.134 | 4.418–4.498 | 224.76–242.29 |
| Go shell (`printf x`) | 1.061 | 1.093–1.566 | 893.24–941.12 |

The C operations include one process startup and JSON stdin/stdout exchange per request. Go shell remains a native Go path. This is still a sequential microbenchmark, not a concurrency, soak, or full HTTP/MCP/OAuth benchmark.


## Latest candidate benchmark after initial source/path ctime check adjustment (2026-11-20)

This measurement supersedes the earlier candidate tables for the current worktree. It was run after the race-test failure was traced to the remaining post-source-fsync source/path comparison using a ctime-sensitive version check. Both atomic write and streaming atomic replace now use the content/basic-metadata comparison for that check.

- Environment: FreeBSD 15.1 amd64; Intel Xeon Platinum 8488C; 2 vCPU; 8 GiB visible RAM; Go 1.26.9.
- Filesystem: temporary 256 MiB mdconfig UFS (`newfs -U`), mounted only for the three benchmark runs, then unmounted and detached.
- Three independent runs; each case used 5 warmups and 100 timed samples; sequential execution; every case completed 100/100 samples in every run with 0 errors.
- C Executor SHA-256: `f719af849c166705f7192da9ae925744a5ff8bbbf8ae28aea6b02c75256a9339`.
- Go GSM candidate SHA-256: `c9edc59cc81c1e203478116605fc8d08cd7a5a1da90b23e7012149339feaa6e8`.
- admin-user candidate SHA-256: `e7a01a7a594dc871cb2fa2150fc388ff132cc1845e08f8cbf5c228ec7a5bb98c`.
- Git HEAD: `a8fe9d05fa5f9c98ab0a473d5532803f0d5cfde1`; worktree dirty.
- Source SHA-256: `cmd/benchmark/main.go` `1afd342da2539d75b18ff92cf901f0a3670a38c42e7617d8f4576a02255b6187`; `internal/executor/executor.go` `ba1d7a7f0638ee75f03890fec7afd1e82f9bca8f8ff4a50e950aceea9e6d6db1`; `executor/c/executor_impl.inc` `d7f2efdda29cbef4faa5a3dcf085618e6d513d97747ec6b5f448f344881b73c1`; `executor/c/Makefile` `4fb444ab9e5caab904a8bbb16d8809f3f84c5fd7e254d58750bb87081d7070c3`.

| Operation | Mean of run medians (ms) | P95 range (ms) | Throughput range (ops/s) |
|---|---:|---:|---:|
| `system.info` | 5.523 | 5.802–6.610 | 177.70–178.77 |
| `directory.list` (100 entries) | 1.532 | 1.869–2.412 | 555.66–631.45 |
| `file.read` (1 MiB) | 12.970 | 14.081–15.382 | 73.85–75.30 |
| `file.write` (1 MiB, direct) | 12.561 | 13.256–14.056 | 77.77–78.38 |
| `file.write` (1 MiB, atomic) | 13.446 | 14.296–15.083 | 72.72–73.11 |
| `file.replace` (1 MiB, replace all) | 4.249 | 4.482–4.732 | 213.03–236.97 |
| Go shell (`printf x`) | 1.101 | 1.128–1.737 | 795.64–928.51 |

The C cases include one Executor process startup and JSON stdin/stdout IPC per operation; the shell case remains a Go-native path. This is a sequential microbenchmark, not a concurrency, soak, or full HTTPS MCP/OAuth benchmark. The run JSON recorded the candidate and source hashes, sample counts, and per-case errors. The temporary benchmark filesystem was detached; no md device remained afterward.

## Final candidate after audit-redaction integration (2026-11-20)

This is the latest default-build candidate measurement. It supersedes earlier candidate hashes and benchmark tables above; those remain as historical records.

- Environment: FreeBSD 15.1 amd64; Intel Xeon Platinum 8488C; 2 vCPU; 8 GiB visible RAM; Go 1.26.9.
- Filesystem: temporary 256 MiB mdconfig UFS (`newfs -U`), detached after the three runs.
- Three independent runs; 5 warmups + 100 samples per operation per run; sequential; all cases 100/100 successful with zero errors in each run.
- C Executor SHA-256: `f719af849c166705f7192da9ae925744a5ff8bbbf8ae28aea6b02c75256a9339`.
- Go GSM SHA-256: `c9edc59cc81c1e203478116605fc8d08cd7a5a1da90b23e7012149339feaa6e8`.
- admin-user SHA-256: `e7a01a7a594dc871cb2fa2150fc388ff132cc1845e08f8cbf5c228ec7a5bb98c`.
- Git HEAD: `a8fe9d05fa5f9c98ab0a473d5532803f0d5cfde1` (dirty worktree).
- `executor/c/executor_impl.inc` SHA-256: `d7f2efdda29cbef4faa5a3dcf085618e6d513d97747ec6b5f448f344881b73c1`.

| Operation | Mean of run medians (ms) | P95 range (ms) | Throughput range (ops/s) |
|---|---:|---:|---:|
| `system.info` | 5.470 | 5.678–5.876 | 176.23–183.09 |
| `directory.list` (100 entries) | 1.538 | 1.823–2.532 | 554.96–641.63 |
| `file.read` (1 MiB) | 13.066 | 14.105–14.365 | 73.84–74.76 |
| `file.write` (1 MiB, direct) | 12.504 | 13.308–16.410 | 76.31–79.48 |
| `file.write` (1 MiB, atomic) | 13.439 | 14.179–14.918 | 71.05–73.52 |
| `file.replace` (1 MiB, replace all) | 4.241 | 4.504–6.040 | 228.19–235.28 |
| Go shell (`printf x`) | 1.069 | 1.251–1.688 | 799.97–935.55 |

The C cases include one process start and JSON stdin/stdout IPC per operation. Go shell is the native Go route. This remains a sequential microbenchmark, not a concurrency/soak or full HTTP/MCP/OAuth benchmark.

## Final candidate benchmark after OAuth expiry-boundary correction (2026-11-20)

This run is bound to the current candidate binaries after the OAuth exact-expiry-boundary correction. It supersedes the previous candidate benchmark section for this worktree.

- Environment: FreeBSD 15.1 amd64; Intel Xeon Platinum 8488C; 2 vCPU; 8 GiB visible RAM; Go 1.26.9.
- Filesystem: temporary 256 MiB mdconfig UFS (`newfs -U`); three independent runs on the mounted filesystem, then unmounted and detached. Cleanup was verified: no benchmark mount, md device, or temporary directory remained.
- Three independent runs; 5 warmups + 100 timed samples per case per run; sequential; every case completed 100/100 samples with zero errors in every run.
- C Executor SHA-256: `f719af849c166705f7192da9ae925744a5ff8bbbf8ae28aea6b02c75256a9339`.
- Go GSM SHA-256: `d90aa4d99d5e9147c5f138897c05136c66ee0888b588ba0d635ff623f3609215`.
- admin-user SHA-256: `e7a01a7a594dc871cb2fa2150fc388ff132cc1845e08f8cbf5c228ec7a5bb98c`.
- Git HEAD: `a8fe9d05fa5f9c98ab0a473d5532803f0d5cfde1`; worktree dirty.
- Source SHA-256: `cmd/benchmark/main.go` `1afd342da2539d75b18ff92cf901f0a3670a38c42e7617d8f4576a02255b6187`; `internal/executor/executor.go` `ba1d7a7f0638ee75f03890fec7afd1e82f9bca8f8ff4a50e950aceea9e6d6db1`; `executor/c/executor_impl.inc` `d7f2efdda29cbef4faa5a3dcf085618e6d513d97747ec6b5f448f344881b73c1`; `executor/c/Makefile` `4fb444ab9e5caab904a8bbb16d8809f3f84c5fd7e254d58750bb87081d7070c3`.

| Operation | Mean of run medians (ms) | P95 range (ms) | Throughput range (ops/s) |
|---|---:|---:|---:|
| `system.info` | 5.440 | 5.642–5.796 | 176.00–183.35 |
| `directory.list` (100 entries) | 1.575 | 1.883–2.560 | 539.00–620.67 |
| `file.read` (1 MiB) | 12.868 | 13.685–14.043 | 74.60–76.54 |
| `file.write` (1 MiB, direct) | 12.387 | 13.220–13.774 | 78.62–79.73 |
| `file.write` (1 MiB, atomic) | 13.057 | 14.105–14.429 | 73.64–75.75 |
| `file.replace` (1 MiB, replace all) | 4.228 | 4.425–6.101 | 230.24–237.99 |
| Go shell (`printf x`) | 1.061 | 1.079–1.313 | 910.11–943.15 |

The C cases include one Executor process start and JSON stdin/stdout IPC per operation. The shell case remains a Go-native path. This is a sequential microbenchmark, not a concurrency/soak or full HTTP/MCP/OAuth benchmark. Run JSON artifacts were retained under `/tmp/run-1.json` through `/tmp/run-3.json` during this session; they are diagnostic artifacts, not release deliverables.


## Latest candidate benchmark after ACL/extattr metadata fingerprinting (2026-11-20)

This run is bound to the candidate C Executor after adding ACL and USER/SYSTEM extattr snapshots to atomic write and streaming replace. It supersedes the previous candidate benchmark table for this worktree.

- Environment: FreeBSD 15.1 amd64; Intel Xeon Platinum 8488C; 2 vCPU; 8 GiB visible RAM; Go 1.26.9.
- Filesystem: temporary 256 MiB mdconfig UFS (`newfs -U -m 0`); mounted only for the three benchmark runs, then unmounted and detached. Cleanup verified; no md device or mount remained.
- Three independent runs; 5 warmups + 100 timed samples per case per run; sequential execution; every case completed 100/100 samples with zero errors in every run.
- C Executor SHA-256: `528186c4279a97346ae903d9c47c1c22e6c6ffeb11e3d895088e8b6955e97a64`.
- Go GSM SHA-256: `d90aa4d99d5e9147c5f138897c05136c66ee0888b588ba0d635ff623f3609215`.
- admin-user SHA-256: `e7a01a7a594dc871cb2fa2150fc388ff132cc1845e08f8cbf5c228ec7a5bb98c`.
- Git HEAD: `a8fe9d05fa5f9c98ab0a473d5532803f0d5cfde1`; worktree dirty.
- Source SHA-256: `cmd/benchmark/main.go` `1afd342da2539d75b18ff92cf901f0a3670a38c42e7617d8f4576a02255b6187`; `internal/executor/executor.go` `ba1d7a7f0638ee75f03890fec7afd1e82f9bca8f8ff4a50e950aceea9e6d6db1`; `executor/c/executor_impl.inc` `797c802a21c99ff675beb21dfe0dabdfabb37fbf5593ded5c991a09b0e85e466`; `executor/c/Makefile` `4b5de1b307050d74e33156091e1b80d51d4fbbeacc237a60a82faab926dca77b`.

| Operation | Mean of run medians (ms) | P95 range (ms) | Throughput range (ops/s) |
|---|---:|---:|---:|
| `system.info` | 5.468 | 5.572–6.327 | 178.05–183.01 |
| `directory.list` (100 entries) | 1.529 | 1.854–2.006 | 535.67–640.97 |
| `file.read` (1 MiB) | 12.765 | 13.719–13.898 | 73.75–76.46 |
| `file.write` (1 MiB, direct) | 12.269 | 13.198–13.951 | 79.40–80.06 |
| `file.write` (1 MiB, atomic) | 13.139 | 13.915–14.098 | 74.24–75.64 |
| `file.replace` (1 MiB, replace all) | 4.293 | 4.430–6.367 | 223.77–236.59 |
| Go shell (`printf x`) | 1.052 | 1.156–1.347 | 878.95–967.69 |

Atomic write and replace medians are close to the immediately preceding candidate run (13.057 ms and 4.228 ms respectively); this small difference is within the observed run-to-run variability and is not a controlled proof of zero overhead. These are sequential microbenchmarks, not concurrency, soak, or full HTTP/MCP/OAuth measurements. Raw JSON reports are retained at `/tmp/kerno-metadata-bench-run-1.json` through `/tmp/kerno-metadata-bench-run-3.json` as diagnostic artifacts.

### Metadata-race validation associated with this candidate

- Test-only synchronization hooks are compiled only into `bin/host-executor-test` using `KERNO_TEST_HOOKS`; `bin/host-executor-candidate` was checked with `strings` and contains none of the test barrier environment-variable names.
- Both atomic operations were paused and concurrently mutated at `after-copy`, `after-fsync`, and `before-rename` checkpoints.
- POSIX-ACL UFS (`mount -o acls`): 18 cases passed across USER extattr, SYSTEM extattr and POSIX ACL; 6 NFSv4 ACL dialect-mismatch cases skipped.
- NFSv4-ACL UFS (`mount -o nfsv4acls`): 18 cases passed across USER extattr, SYSTEM extattr and NFSv4 ACL; 6 POSIX ACL dialect-mismatch cases skipped.
- Every passing case verified `ATOMIC_TARGET_CHANGED`, unchanged original file bytes, preserved concurrent metadata and no leftover temp file. Both temporary filesystems were unmounted and detached; no md devices or mount entries remained.
- The full `make test`, `make test-integration` against the dedicated `kerno_gsm_test_20261120` database, and full `go test -race -count=1 ./...` with that database passed. `go vet ./...`, `go mod verify`, `make build-candidate`, and `git diff --check` passed.
- Current host root and repository filesystem is UFS. No ZFS dataset was present in the test environment; ZFS ACL/extattr semantics and fingerprint behavior remain unverified.
- Residual risk: the final fingerprint/stat comparison and `rename` are not one atomic kernel operation; non-cooperating mutation in the final gap remains possible. SIGKILL/power-loss temp orphan behavior remains a separate open item.
