# KERNO — Go SSH MCP

KERNO 是一个基于 Go、C/cgo、PostgreSQL 与 Model Context Protocol (MCP) 的主机执行服务。它提供受 OAuth 保护的文件、服务、Shell、并行任务和数据库工具。

> **安全警告：** 这是高权限远程执行服务，不是沙箱。当前实现要求以 root 身份运行；`execute_shell`、`execute_parallel` 和 `database_query` 可以执行破坏性操作。只应部署在可信主机上，并只授权可信用户和客户端。不要直接暴露未经过 TLS 反向代理保护的监听端口。

## 支持的平台

| 平台 | 状态 | 说明 |
|---|---|---|
| FreeBSD 15.x amd64 | 当前开发和测试平台 | 已在 FreeBSD 15.1 amd64 上通过项目单元测试、C 执行器构建、`go mod verify` 和 `go vet`；安装流程以 FreeBSD 为目标 |
| Debian / Ubuntu Linux | 尚未正式支持 | 代码包含 FreeBSD 专用服务路径与命令假设。请勿将当前版本视为经过 Linux 验证；Linux 适配与 CI 通过前不要部署到生产环境 |
| 其他系统 | 未验证 | 不保证构建、服务管理或执行行为兼容 |

## 工具清单

所有工具都要求有效的 OAuth Bearer Token。具体输入由 MCP `tools/list` 的 schema 为准。

| 工具 | 输入 | 功能与风险 |
|---|---|---|
| `get_system_info` | 无 | 返回系统、版本、主机名、运行时间、磁盘、内存等信息 |
| `list_directory` | `path` | 列出目录项、类型、大小、权限及所有者信息 |
| `read_file` | `path`、可选 `max_bytes`（默认 200000，范围 1–2000000） | 读取文件内容；可能读取敏感文件，必须控制授权用户 |
| `write_file` | `path`、`content`、可选 `create_parents` | 创建或覆盖文件；按目标路径当前权限执行，不保证原子写入 |
| `replace_in_file` | `path`、`old_text`、`new_text`、可选 `replace_all` | 替换文件文本；默认仅替换第一次匹配 |
| `move_path` | `source`、`destination` | 移动或重命名路径；目标存在时可能覆盖 |
| `delete_path` | `path`、可选 `recursive` | 删除文件或目录；递归删除会造成不可逆的数据损失 |
| `get_service_status` | `service` | 查询系统服务状态；当前实现依赖 FreeBSD 服务管理约定 |
| `get_service_logs` | `path`、可选 `lines`（默认 100，范围 1–2000） | 读取指定日志文件末尾；日志可能包含敏感数据 |
| `execute_shell` | `command`、可选 `timeout_seconds`（默认 30，范围 1–300） | 通过系统 Shell 执行命令，返回退出码、标准输出和标准错误；拥有服务运行账户的系统权限 |
| `execute_parallel` | `tasks`（2–32 个独立任务）、可选 `max_parallel`（默认 8，最大 8） | 并行运行独立 Shell 任务；任务须使用不同工作目录，同一 Git 仓库须使用独立 worktree；包含超时、输出限制、清理和审计 |
| `database_query` | `sql`、可选 `database`、可选 `max_rows`（默认 100，范围 1–500） | 执行单条 PostgreSQL 语句，包括查询、增删改、DDL 和数据库管理操作；数据库角色权限决定实际影响范围 |

### 并行执行约束

- 每次请求最多 32 个任务，服务端并发上限为 8。
- 每个任务应使用独立工作目录；同一 Git 仓库的任务必须使用独立 worktree。
- 不要让并行任务同时修改同一文件、同一数据库记录或同一部署目标。
- 任务超时和输出限制不等同于安全沙箱；任务仍以服务进程的系统权限执行。

## 架构

- **Go**：MCP Streamable HTTP、OAuth、工具 schema、请求生命周期和审计。
- **C/cgo**：文件系统操作及独立 C 执行器；依赖 `json-c`。
- **PostgreSQL**：OAuth 用户、客户端、授权、令牌和审计相关数据。
- **有界并行工作池**：`execute_parallel` 在请求生命周期内调度任务，不提供持久化队列或作业调度器。

## 安装与配置

### 前置条件

- FreeBSD 15.x amd64（当前支持范围）
- Go 1.26.9 或与 `go.mod` 兼容的版本
- C 编译器、cgo 和 `json-c` 开发文件
- PostgreSQL 服务及一个专用数据库
- HTTPS 反向代理和一个由部署者控制的域名

### 从源码构建

```sh
pkg install -y go json-c postgresql17-client
make build
make test
go mod verify
go vet ./...
```

构建产物使用候选文件名，不会覆盖已部署的生产二进制。不要在生产主机上直接运行未经审核的测试分支。

### 一键安装

当前安装脚本仅支持 FreeBSD，并且会在执行前提示关键操作。先阅读脚本，再以 root 身份运行：

```sh
sh scripts/install.sh
```

脚本需要配置数据库连接、公开域名和监听端口，并在确认后安装依赖、构建候选程序、写入权限受限的配置文件和创建服务。TLS 证书及反向代理不由本项目自动配置。

安装器会要求数据库连接串。该数据库角色必须具备 OAuth schema 初始化所需权限；**当前 `database_query` 设计允许数据库管理语句，若使用 PostgreSQL 超级用户连接，则该工具也获得相应的高权限能力**。请使用独立数据库、评估权限，并仅向可信 OAuth 用户开放。不要将数据库 URL、OAuth 签名密钥或密码提交到 Git。

安装完成后，可用以下命令交互式创建或更新 OAuth 用户。密码会关闭终端回显，要求至少 14 字节，并且不会被程序记录到日志：

```sh
GO_SSH_MCP_CONFIG=/usr/local/etc/kerno.conf \
  /opt/kerno/bin/go-ssh-mcp-admin-user <username>
```

具体服务启用和反向代理步骤见 [部署说明](docs/DEPLOYMENT.md)。

## OAuth 授权范围

当前实现支持两个 scope：

- `go-ssh-mcp`：默认的 MCP 工具访问范围。
- `offline_access`：用于请求刷新令牌的长期访问能力；客户端是否使用它取决于客户端实现和授权请求。

范围清单与校验目前定义在 `internal/oauth/server.go`，包括 discovery 元数据、客户端注册、授权请求校验和授权页面。维护者可以自行修改，但必须同步调整允许范围校验、元数据、同意页面、令牌刷新行为和测试；不能只修改 `scopes_supported` 文本来声称实现了新权限。OAuth scope 是客户端授权范围，不是操作系统级沙箱或细粒度文件权限系统。

## 配置变量

`config/example.env` 是示例，不包含可用凭证。正式配置文件应由安装脚本创建并设置为 `0600` 权限。

- `LISTEN_ADDR`：监听地址；默认应仅绑定回环地址，例如 `127.0.0.1:8766`。
- `PUBLIC_ISSUER_URL`：OAuth issuer 的 HTTPS URL。
- `RESOURCE_URL`：MCP 资源 URL，通常以 `/mcp` 结尾。
- `DATABASE_URL`：PostgreSQL 连接串，含密码时属于敏感凭证。
- `C_EXECUTOR_PATH`：C 执行器的绝对路径。
- `OAUTH_SIGNING_KEY_FILE`：OAuth 签名密钥文件路径；必须限制文件权限并纳入安全备份。
- `AUDIT_LOG_PATH`：审计日志路径；需限制访问并规划轮转。
- `MAX_OUTPUT_BYTES`：工具输出上限。

## 安全边界与运维

1. 当前服务要求 root 身份运行，且执行器拥有广泛的主机操作权限。不要把它当作隔离容器或受限命令解释器。
2. `database_query` 允许修改数据和执行 DDL/管理语句。仅使用隔离数据库，并明确谁有权调用此工具。
3. OAuth 认证不能消除已授权用户滥用高权限工具的风险。部署者应使用 TLS、最小化授权用户、监控审计日志，并定期轮换凭证。
4. 示例配置不包含数据库密码；如数据库启用密码认证，请通过受保护的配置文件或环境变量提供密码，不要将其提交到 Git。
5. 不要把生产配置、`.env`、私钥、数据库备份、日志或含凭证的历史提交推送到公开仓库。
6. 公开发布版本不承诺 Linux 支持，直到 Linux 专用构建、集成测试和服务管理测试通过。

## 测试

```sh
make build
make test
go mod verify
go vet ./...
```

集成测试需要独立、可丢弃的测试数据库；**禁止将测试迁移或集成测试指向生产数据库**。更完整的验收条件见 [ACCEPTANCE](docs/ACCEPTANCE.md)。

更多文档：[架构](docs/ARCHITECTURE.md) · [OAuth 设计](docs/OAUTH.md) · [恢复指南](docs/RECOVERY.md) · [基准测试](docs/BENCHMARK.md) · [部署指南](docs/DEPLOYMENT.md) · [第三方许可证报告](docs/DEPENDENCY_LICENSES.csv)。

## 许可证与第三方依赖

项目代码按仓库中的 [MIT License](LICENSE) 发布。第三方依赖保留其各自的许可证与版权声明，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。MIT 许可证不意味着第三方代码、商标或品牌自动获得相同授权。

## 致谢

感谢 FreeBSD 社区提供的系统、工具链和文档，也感谢 OpenAI 对相关开发工具与 AI 协作生态的贡献。此致谢不表示 FreeBSD 项目或 OpenAI 对 KERNO 的认可、认证或背书。
