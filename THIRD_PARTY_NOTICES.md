# Third-party notices

KERNO's own source is offered under the MIT License in `LICENSE`. Dependencies retain their own copyrights and licenses; the project's MIT license does not relicense third-party components.

## Direct Go dependencies

- `github.com/modelcontextprotocol/go-sdk` v1.7.0 — consult the exact upstream `LICENSE` and any bundled notices for this version. The automated dependency report identifies the v1.7.0 module license as Apache-2.0; review the exact upstream release files and preserve its Apache notice and any applicable notices when redistributing.
- `github.com/jackc/pgx/v5` v5.7.4 — MIT License.
- `github.com/google/uuid` v1.6.0 — BSD 3-Clause License.
- `golang.org/x/crypto` v0.36.0 — Go Authors' BSD-style license.
- `golang.org/x/term` v0.30.0 — BSD 3-Clause License.

## Other Go modules

`go.mod` and `go.sum` pin the direct and transitive module versions, including `github.com/google/jsonschema-go`, `github.com/jackc/pgpassfile`, `github.com/jackc/pgservicefile`, `github.com/jackc/puddle/v2`, `github.com/segmentio/asm`, `github.com/segmentio/encoding`, `github.com/yosida95/uritemplate/v3`, `golang.org/x/oauth2`, `golang.org/x/sync`, `golang.org/x/sys`, `golang.org/x/text` and `golang.org/x/time`, plus their transitive dependencies. Consult the LICENSE/COPYING/NOTICE files distributed with the exact module versions before redistributing a binary or source bundle.

## System dependencies

- `json-c` — MIT License; installed from the target operating system's package repository.
- Go toolchain, C compiler, PostgreSQL client/server and operating-system utilities are system prerequisites, not vendored source in this repository. Each remains subject to its own license.

The generated [`docs/DEPENDENCY_LICENSES.csv`](docs/DEPENDENCY_LICENSES.csv) lists the licenses detected for Go packages used by the current source plus the system `json-c` dependency. The scanner warned that assembly/C sources cannot be fully inspected; review upstream license files manually before each release. This report is not a substitute for the complete license texts.
