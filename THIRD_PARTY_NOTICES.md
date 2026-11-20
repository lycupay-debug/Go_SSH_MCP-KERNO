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


## Bundled license texts

Exact upstream license texts for the production Go package dependencies reported by `go-licenses report ./...` are copied under `THIRD_PARTY_LICENSES/`, alongside the system `json-c` package license. Directory names include the module and pinned version. The current inventory is also summarized in `docs/DEPENDENCY_LICENSES.csv`.

The `github.com/modelcontextprotocol/go-sdk` v1.7.0 module has a licensing-transition `LICENSE` file. It includes the full Apache-2.0 license text, the MIT license text for contributions not yet relicensed, and a CC-BY-4.0 documentation notice. `go-licenses` classifies the compiled package as Apache-2.0. No separate `NOTICE` file was present in the downloaded v1.7.0 module tree inspected for this release candidate. The exact complete upstream `LICENSE` file is preserved at `THIRD_PARTY_LICENSES/github.com_modelcontextprotocol_go-sdk-v1.7.0/LICENSE`.

`go-licenses report ./...` was run against the current source. It warned that some assembly/C sources cannot be fully inspected for further dependencies; those warnings remain a manual-review limitation. `go mod download -json all` confirmed all 30 modules in the resolved module graph have a LICENSE/COPYING file in their exact cached source version. The bundled directory currently copies licenses for packages reported as used by `./...` plus `json-c`; it does not claim to include licenses for every test-only transitive module in the full module graph.

## Bundled license inventory

| Module / dependency | Version | Detected license | Bundled license text |
|---|---|---|---|
| `github.com/google/jsonschema-go` | `v0.4.3` | MIT | `THIRD_PARTY_LICENSES/github.com_google_jsonschema-go-v0.4.3/LICENSE` |
| `github.com/google/uuid` | `v1.6.0` | BSD-3-Clause | `THIRD_PARTY_LICENSES/github.com_google_uuid-v1.6.0/LICENSE` |
| `github.com/jackc/pgpassfile` | `v1.0.0` | MIT | `THIRD_PARTY_LICENSES/github.com_jackc_pgpassfile-v1.0.0/LICENSE` |
| `github.com/jackc/pgservicefile` | `v0.0.0-20240606120523-5a60cdf6a761` | MIT | `THIRD_PARTY_LICENSES/github.com_jackc_pgservicefile-v0.0.0-20240606120523-5a60cdf6a761/LICENSE` |
| `github.com/jackc/pgx/v5` | `v5.7.4` | MIT | `THIRD_PARTY_LICENSES/github.com_jackc_pgx_v5-v5.7.4/LICENSE` |
| `github.com/jackc/puddle/v2` | `v2.2.2` | MIT | `THIRD_PARTY_LICENSES/github.com_jackc_puddle_v2-v2.2.2/LICENSE` |
| `github.com/modelcontextprotocol/go-sdk` | `v1.7.0` | Apache-2.0 | `THIRD_PARTY_LICENSES/github.com_modelcontextprotocol_go-sdk-v1.7.0/LICENSE` |
| `github.com/segmentio/asm` | `v1.1.3` | MIT | `THIRD_PARTY_LICENSES/github.com_segmentio_asm-v1.1.3/LICENSE` |
| `github.com/segmentio/encoding` | `v0.5.4` | MIT | `THIRD_PARTY_LICENSES/github.com_segmentio_encoding-v0.5.4/LICENSE` |
| `github.com/yosida95/uritemplate/v3` | `v3.0.2` | BSD-3-Clause | `THIRD_PARTY_LICENSES/github.com_yosida95_uritemplate_v3-v3.0.2/LICENSE` |
| `golang.org/x/crypto` | `v0.36.0` | BSD-3-Clause | `THIRD_PARTY_LICENSES/golang.org_x_crypto-v0.36.0/LICENSE` |
| `golang.org/x/oauth2` | `v0.35.0` | BSD-3-Clause | `THIRD_PARTY_LICENSES/golang.org_x_oauth2-v0.35.0/LICENSE` |
| `golang.org/x/sync` | `v0.20.0` | BSD-3-Clause | `THIRD_PARTY_LICENSES/golang.org_x_sync-v0.20.0/LICENSE` |
| `golang.org/x/sys` | `v0.41.0` | BSD-3-Clause | `THIRD_PARTY_LICENSES/golang.org_x_sys-v0.41.0/LICENSE` |
| `golang.org/x/term` | `v0.30.0` | BSD-3-Clause | `THIRD_PARTY_LICENSES/golang.org_x_term-v0.30.0/LICENSE` |
| `golang.org/x/text` | `v0.24.0` | BSD-3-Clause | `THIRD_PARTY_LICENSES/golang.org_x_text-v0.24.0/LICENSE` |
| `golang.org/x/time` | `v0.15.0` | BSD-3-Clause | `THIRD_PARTY_LICENSES/golang.org_x_time-v0.15.0/LICENSE` |
| `json-c` | `0.19_1` | MIT | `THIRD_PARTY_LICENSES/json-c-0.19_1/LICENSE` |
