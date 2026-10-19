package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/config"
	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/executor"
	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/oauth"
	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/parallel"
)

// Tool input types preserve the established MCP tool contract.
type emptyInput struct{}
type pathInput struct {
	Path string `json:"path" jsonschema_description:"绝对或相对文件系统路径。"`
}
type readFileInput struct {
	Path     string `json:"path"`
	MaxBytes int    `json:"max_bytes,omitempty"`
}
type writeFileInput struct {
	Path          string `json:"path"`
	Content       string `json:"content"`
	CreateParents bool   `json:"create_parents,omitempty"`
}
type replaceFileInput struct {
	Path       string `json:"path"`
	OldText    string `json:"old_text"`
	NewText    string `json:"new_text"`
	ReplaceAll bool   `json:"replace_all,omitempty"`
}
type movePathInput struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}
type deletePathInput struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"`
}
type serviceInput struct {
	Service string `json:"service"`
}
type serviceLogsInput struct {
	Path  string `json:"path"`
	Lines int    `json:"lines,omitempty"`
}
type serviceControlInput struct {
	Service string `json:"service"`
	Action  string `json:"action"`
}
type commandInput struct {
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}
type parallelInput struct {
	Tasks       []parallel.Task `json:"tasks" jsonschema_description:"需要并行执行的独立任务；每个任务必须使用不同工作目录，Git 项目需使用独立 worktree。"`
	MaxParallel int             `json:"max_parallel,omitempty" jsonschema_description:"同时执行的任务上限，默认 8，最大 8。"`
}

type databaseInput struct {
	Database string `json:"database,omitempty" jsonschema_description:"目标数据库名；留空时使用 Go SSH MCP 默认数据库。"`
	SQL      string `json:"sql" jsonschema_description:"执行一条 PostgreSQL SQL 语句；支持查询、增删改、DDL 和数据库管理语句。"`
	MaxRows  int    `json:"max_rows,omitempty" jsonschema_description:"最多返回的行数，默认 100，最大 500。"`
}

type app struct {
	runner    *executor.Executor
	logger    *slog.Logger
	auditPath string
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("Go SSH MCP must run as root")
	}
	configPath := os.Getenv("GO_SSH_MCP_CONFIG")
	if configPath == "" {
		configPath = "/usr/local/etc/kerno.conf"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal(err)
	}
	key, err := loadSigningKey(cfg.OAuthSigningKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	poolCfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	runner := &executor.Executor{Path: cfg.CExecutorPath, Native: true, MaxOutputBytes: cfg.MaxOutputBytes}
	if len(os.Args) > 1 && os.Args[1] == "--check-config" {
		if _, err = os.Stat(cfg.CExecutorPath); err != nil {
			log.Fatal("C executor unavailable")
		}
		fmt.Printf("configuration OK; database reachable; OAuth signing key loaded; C executor available; synchronous tools and bounded parallel execution enabled\n")
		return
	}
	application := &app{runner: runner, logger: logger, auditPath: cfg.AuditLogPath}
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "KERNO MCP", Version: "1.0.0"}, &mcp.ServerOptions{Instructions: "管理主机的 KERNO MCP 服务。当前支持平台为 FreeBSD；工具名称、参数、默认值及返回结构与兼容实现保持一致。底层操作由 C 执行器完成，MCP 接口由 Go SDK 提供。所有请求均需有效 OAuth Bearer Token。execute_parallel 在服务进程内部使用有界并发执行独立任务，最大并行数为 8；每个任务必须使用独立工作目录，Git 仓库任务必须使用独立 worktree。"})

	mcp.AddTool(mcpServer, &mcp.Tool{Name: "get_system_info", Description: "获取 FreeBSD 版本、主机名、运行时间、磁盘、内存及运行时信息。"}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := application.call(ctx, "system.info", map[string]any{}, 30, actorFromContext(ctx))
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "list_directory", Description: "列出目录中的文件，返回类型、大小和权限。"}, func(ctx context.Context, req *mcp.CallToolRequest, in pathInput) (*mcp.CallToolResult, []map[string]any, error) {
		out, err := application.call(ctx, "directory.list", map[string]any{"path": in.Path}, 30, actorFromContext(ctx))
		if err != nil {
			return nil, nil, err
		}
		items, ok := out["entries"].([]any)
		if !ok {
			return nil, []map[string]any{}, nil
		}
		result := make([]map[string]any, 0, len(items))
		for _, v := range items {
			if m, ok := v.(map[string]any); ok {
				result = append(result, m)
			}
		}
		sort.SliceStable(result, func(i, j int) bool {
			return strings.ToLower(fmt.Sprint(result[i]["name"])) < strings.ToLower(fmt.Sprint(result[j]["name"]))
		})
		return nil, result, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "read_file", Description: "读取文件。max_bytes 范围为 1 至 2000000 字节。"}, func(ctx context.Context, req *mcp.CallToolRequest, in readFileInput) (*mcp.CallToolResult, map[string]any, error) {
		max := in.MaxBytes
		if max == 0 {
			max = 200000
		}
		if max < 1 || max > 2_000_000 {
			return nil, nil, fmt.Errorf("max_bytes 必须在 1 至 2000000 之间")
		}
		out, err := application.call(ctx, "file.read", map[string]any{"path": in.Path, "max_bytes": max}, 30, actorFromContext(ctx))
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "write_file", Description: "创建或覆盖 UTF-8 文本文件。覆盖现有文件前应先备份。"}, func(ctx context.Context, req *mcp.CallToolRequest, in writeFileInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := application.call(ctx, "file.write", map[string]any{"path": in.Path, "content": in.Content, "create_parents": in.CreateParents}, 60, actorFromContext(ctx))
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "replace_in_file", Description: "替换文件文本；默认只替换第一次出现的匹配项。"}, func(ctx context.Context, req *mcp.CallToolRequest, in replaceFileInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := application.call(ctx, "file.replace", map[string]any{"path": in.Path, "old_text": in.OldText, "new_text": in.NewText, "replace_all": in.ReplaceAll}, 60, actorFromContext(ctx))
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "move_path", Description: "移动或重命名文件、目录。目标路径已存在时可能发生覆盖。"}, func(ctx context.Context, req *mcp.CallToolRequest, in movePathInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := application.call(ctx, "file.move", map[string]any{"source": in.Source, "destination": in.Destination, "overwrite": true}, 60, actorFromContext(ctx))
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "delete_path", Description: "删除文件或目录；删除非空目录必须设置 recursive=true。"}, func(ctx context.Context, req *mcp.CallToolRequest, in deletePathInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := application.call(ctx, "file.delete", map[string]any{"path": in.Path, "recursive": in.Recursive}, 60, actorFromContext(ctx))
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "get_service_status", Description: "查询 FreeBSD rc.d 服务状态。"}, func(ctx context.Context, req *mcp.CallToolRequest, in serviceInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := application.call(ctx, "service.status", map[string]any{"service": in.Service}, 15, actorFromContext(ctx))
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "get_service_logs", Description: "读取日志文件最后若干行，最多 2000 行。"}, func(ctx context.Context, req *mcp.CallToolRequest, in serviceLogsInput) (*mcp.CallToolResult, map[string]any, error) {
		lines := in.Lines
		if lines == 0 {
			lines = 100
		}
		if lines < 1 || lines > 2000 {
			return nil, nil, errors.New("lines 必须在 1 至 2000 之间")
		}
		out, err := application.call(ctx, "logs.tail", map[string]any{"path": in.Path, "lines": lines}, 15, actorFromContext(ctx))
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "execute_shell", Description: "以 Root 权限执行 FreeBSD Shell 命令，返回退出码、标准输出和标准错误。"}, func(ctx context.Context, req *mcp.CallToolRequest, in commandInput) (*mcp.CallToolResult, map[string]any, error) {
		timeout := in.TimeoutSeconds
		if timeout == 0 {
			timeout = 30
		}
		if timeout < 1 || timeout > 300 {
			return nil, nil, errors.New("timeout_seconds 必须在 1 至 300 之间")
		}
		if strings.TrimSpace(in.Command) == "" {
			return nil, nil, errors.New("command 不能为空")
		}
		out, err := application.call(ctx, "shell.exec", map[string]any{"command": in.Command, "timeout_seconds": timeout}, timeout, actorFromContext(ctx))
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "execute_parallel", Description: "在 Go SSH MCP 服务内部并行执行 2 至 32 个独立 Shell 任务，最大并行数 8。每个任务必须使用不同工作目录；同一 Git 仓库的并行任务必须使用独立 git worktree。单任务超时 1 至 300 秒，输出上限约 1 MB，任务日志写入受限权限的服务器日志目录。"}, func(ctx context.Context, req *mcp.CallToolRequest, in parallelInput) (*mcp.CallToolResult, parallel.Summary, error) {
		out, err := application.executeParallel(ctx, in, actorFromContext(ctx))
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "database_query", Description: "使用 Go SSH MCP PostgreSQL 超级用户权限，在指定数据库执行单条 SQL。支持 SELECT/INSERT/UPDATE/DELETE、DDL 及数据库管理语句；最多返回 500 行。database 可指定集群内目标数据库，所有调用均要求 OAuth 身份认证并写入审计日志。"}, func(ctx context.Context, req *mcp.CallToolRequest, in databaseInput) (*mcp.CallToolResult, map[string]any, error) {
		actor := actorFromContext(ctx)
		if strings.TrimSpace(actor) == "" {
			return nil, nil, errors.New("authenticated OAuth user is required")
		}
		query := strings.TrimSpace(in.SQL)
		if query == "" {
			return nil, nil, errors.New("sql 不能为空")
		}
		maxRows := in.MaxRows
		if maxRows == 0 {
			maxRows = 100
		}
		if maxRows < 1 || maxRows > 500 {
			return nil, nil, errors.New("max_rows 必须在 1 至 500 之间")
		}
		started := time.Now()
		hash := sha256.Sum256([]byte(query))
		queryHash := hex.EncodeToString(hash[:])
		queryPool := pool
		var temporaryPool *pgxpool.Pool
		database := strings.TrimSpace(in.Database)
		if database == "" {
			database = pool.Config().ConnConfig.Database
		}
		if database != "" {
			if len(database) > 63 || strings.ContainsRune(database, 0) {
				return nil, nil, errors.New("database 名称长度必须不超过 63 字节且不能包含 NUL")
			}
			if database != pool.Config().ConnConfig.Database {
				databaseConfig, configErr := pgxpool.ParseConfig(cfg.DatabaseURL)
				if configErr != nil {
					return nil, nil, fmt.Errorf("parse database connection config: %w", configErr)
				}
				databaseConfig.ConnConfig.Database = database
				databaseConfig.MaxConns = 1
				targetPool, connectErr := pgxpool.NewWithConfig(ctx, databaseConfig)
				if connectErr != nil {
					entry := map[string]any{"actor": actor, "operation": "database.query", "database": database, "query_sha256": queryHash, "success": false, "error": connectErr.Error(), "duration_ms": time.Since(started).Milliseconds(), "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}
					if auditErr := writeAudit(cfg.AuditLogPath, entry); auditErr != nil {
						return nil, nil, fmt.Errorf("database connection failed (%v) and audit logging failed: %w", connectErr, auditErr)
					}
					return nil, nil, fmt.Errorf("connect target database: %w", connectErr)
				}
				temporaryPool = targetPool
				defer temporaryPool.Close()
				queryPool = temporaryPool
			}
		}
		rows, err := queryPool.Query(ctx, query)
		if err != nil {
			entry := map[string]any{"actor": actor, "operation": "database.query", "database": database, "query_sha256": queryHash, "success": false, "error": err.Error(), "duration_ms": time.Since(started).Milliseconds(), "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}
			if auditErr := writeAudit(cfg.AuditLogPath, entry); auditErr != nil {
				return nil, nil, fmt.Errorf("database query failed (%v) and audit logging failed: %w", err, auditErr)
			}
			return nil, nil, err
		}
		fields := rows.FieldDescriptions()
		columns := make([]string, 0, len(fields))
		for _, field := range fields {
			columns = append(columns, string(field.Name))
		}
		resultRows := make([][]any, 0)
		truncated := false
		for rows.Next() {
			if len(resultRows) >= maxRows {
				truncated = true
				break
			}
			values, valueErr := rows.Values()
			if valueErr != nil {
				rows.Close()
				return nil, nil, valueErr
			}
			resultRows = append(resultRows, values)
		}
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			entry := map[string]any{"actor": actor, "operation": "database.query", "database": database, "query_sha256": queryHash, "success": false, "error": rowErr.Error(), "duration_ms": time.Since(started).Milliseconds(), "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}
			if auditErr := writeAudit(cfg.AuditLogPath, entry); auditErr != nil {
				return nil, nil, fmt.Errorf("database result failed (%v) and audit logging failed: %w", rowErr, auditErr)
			}
			return nil, nil, rowErr
		}
		commandTag := rows.CommandTag().String()
		entry := map[string]any{"actor": actor, "operation": "database.query", "database": database, "query_sha256": queryHash, "success": true, "row_count": len(resultRows), "command_tag": commandTag, "truncated": truncated, "duration_ms": time.Since(started).Milliseconds(), "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}
		if auditErr := writeAudit(cfg.AuditLogPath, entry); auditErr != nil {
			return nil, nil, fmt.Errorf("database query succeeded but audit logging failed: %w", auditErr)
		}
		return nil, map[string]any{"database": database, "columns": columns, "rows": resultRows, "row_count": len(resultRows), "command_tag": commandTag, "truncated": truncated, "query_sha256": queryHash}, nil
	})

	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server { return mcpServer }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, DisableLocalhostProtection: true})
	resourceMetadataURL := ""
	if resourceURL, parseErr := url.Parse(cfg.ResourceURL); parseErr == nil && resourceURL.Scheme != "" && resourceURL.Host != "" {
		resourceMetadataURL = resourceURL.Scheme + "://" + resourceURL.Host + "/.well-known/oauth-protected-resource" + strings.TrimRight(resourceURL.EscapedPath(), "/")
	} else {
		log.Fatal("RESOURCE_URL must be an absolute URL")
	}
	authHandler := auth.RequireBearerToken(tokenVerifier(pool, cfg.ResourceURL), &auth.RequireBearerTokenOptions{ResourceMetadataURL: resourceMetadataURL, Scopes: []string{"go-ssh-mcp"}})
	mux := http.NewServeMux()
	mux.Handle("/mcp", authHandler(handler))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"status\":\"ok\",\"service\":\"Go_SSH_MCP\",\"execution_mode\":\"synchronous+bounded-parallel\",\"max_parallel\":8}"))
	})
	oauthServer := oauth.New(pool, cfg.PublicIssuerURL, cfg.ResourceURL, key)
	oauthServer.RegisterRoutes(mux)
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 0, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	logger.Info("Go_SSH_MCP starting", "listen", cfg.ListenAddr, "execution_mode", "synchronous+bounded-parallel", "max_parallel", parallel.MaxParallel, "tool_count", 12, "oauth_metadata_ready", true)
	if err = srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func (a *app) call(ctx context.Context, operation string, input map[string]any, timeoutSeconds int, actor string) (map[string]any, error) {
	if strings.TrimSpace(actor) == "" {
		return nil, errors.New("authenticated OAuth user is required")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	taskID := hex.EncodeToString(id[:])
	started := time.Now()
	executionTimeout := time.Duration(timeoutSeconds) * time.Second
	if operation == "shell.exec" {
		executionTimeout += 5 * time.Second
	}
	result, err := a.runner.Execute(ctx, taskID, operation, input, executionTimeout)
	entry := map[string]any{"actor": actor, "operation": operation, "duration_ms": time.Since(started).Milliseconds(), "success": err == nil, "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}
	for _, k := range []string{"path", "source", "destination", "service", "lines"} {
		if v, ok := input[k]; ok {
			entry[k] = v
		}
	}
	if err != nil {
		entry["error"] = err.Error()
		a.logger.Error("tool operation failed", "operation", operation, "actor", actor, "duration_ms", time.Since(started).Milliseconds(), "error", err)
		if auditErr := writeAudit(a.auditPath, entry); auditErr != nil {
			return nil, fmt.Errorf("operation failed (%v) and audit logging failed: %w", err, auditErr)
		}
		return nil, err
	}
	var out map[string]any
	if direct, ok := result.Value.(map[string]any); ok {
		out = direct
	} else if err = json.Unmarshal(result.Response.Result, &out); err != nil {
		entry["success"] = false
		entry["error"] = err.Error()
		if auditErr := writeAudit(a.auditPath, entry); auditErr != nil {
			return nil, fmt.Errorf("decode executor response (%v) and audit logging failed: %w", err, auditErr)
		}
		return nil, fmt.Errorf("decode C executor result: %w", err)
	}
	// Match Python tool response fields while retaining C exit status semantics.
	switch operation {
	case "directory.list":
		if items, ok := out["entries"].([]any); ok {
			sort.SliceStable(items, func(i, j int) bool {
				left, _ := items[i].(map[string]any)
				right, _ := items[j].(map[string]any)
				return strings.ToLower(fmt.Sprint(left["name"])) < strings.ToLower(fmt.Sprint(right["name"]))
			})
			out["entries"] = items
		}
	case "file.read":
		out = map[string]any{"path": out["path"], "content": out["content"], "truncated": out["truncated"]}
	case "shell.exec":
		if timedOut, _ := out["timed_out"].(bool); timedOut {
			stdout, _ := out["stdout"].(string)
			stderr, _ := out["stderr"].(string)
			out = map[string]any{"returncode": nil, "stdout": tailRunes(stdout, 30000), "stderr": tailRunes(stderr, 10000), "timed_out": true, "termination_signal": out["termination_signal"], "cleanup_complete": out["cleanup_complete"]}
			entry["timed_out"] = true
			entry["termination_signal"] = out["termination_signal"]
			entry["cleanup_complete"] = out["cleanup_complete"]
			entry["returncode"] = nil
			break
		}
		stdout, _ := out["stdout"].(string)
		stderr, _ := out["stderr"].(string)
		out = map[string]any{"returncode": out["returncode"], "stdout": tailRunes(stdout, 30000), "stderr": tailRunes(stderr, 10000), "timed_out": false}
		entry["returncode"] = out["returncode"]
		entry["timed_out"] = false
	case "service.status":
		out = map[string]any{"service": out["service"], "returncode": out["exit_code"], "stdout": out["stdout"], "stderr": out["stderr"]}
	case "logs.tail":
		stdout, _ := out["stdout"].(string)
		stderr, _ := out["stderr"].(string)
		out = map[string]any{"returncode": out["returncode"], "stdout": tailRunes(stdout, 30000), "stderr": tailRunes(stderr, 3000)}
	case "file.write":
		characters, ok := out["characters_written"]
		if !ok {
			content, _ := input["content"].(string)
			characters = utf8.RuneCountInString(content)
		}
		out = map[string]any{"success": true, "path": out["path"], "previously_existed": out["previously_existed"], "characters_written": characters}
	case "file.replace":
		if success, _ := out["success"].(bool); !success {
			out = map[string]any{"success": false, "reason": out["reason"]}
		} else {
			out = map[string]any{"success": true, "path": out["path"], "matches": out["matches"], "replacements": out["replacements"]}
		}
	case "file.move":
		out = map[string]any{"success": true, "result": out["result"]}
	case "system.info":
		delete(out, "python")
	case "file.delete":
		kind := "file_or_symlink"
		if out["kind"] == "directory" {
			kind = "directory"
		}
		out = map[string]any{"success": true, "path": out["path"], "kind": kind}
	}
	if auditErr := writeAudit(a.auditPath, entry); auditErr != nil {
		return nil, fmt.Errorf("operation completed but audit logging failed: %w", auditErr)
	}
	a.logger.Info("tool operation completed", "operation", operation, "actor", actor, "duration_ms", time.Since(started).Milliseconds())
	return out, nil
}

func (a *app) executeParallel(ctx context.Context, in parallelInput, actor string) (parallel.Summary, error) {
	if strings.TrimSpace(actor) == "" {
		return parallel.Summary{}, errors.New("authenticated OAuth user is required")
	}
	var auditMu sync.Mutex
	var auditErr error
	audit := func(event string, fields map[string]any) {
		entry := map[string]any{"actor": actor, "operation": event, "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}
		for key, value := range fields {
			entry[key] = value
		}
		if err := writeAudit(a.auditPath, entry); err != nil {
			auditMu.Lock()
			if auditErr == nil {
				auditErr = err
			}
			auditMu.Unlock()
			a.logger.Error("parallel task audit failed", "event", event, "error", err)
		}
	}
	started := time.Now()
	result, err := parallel.Run(ctx, parallel.Request{Tasks: in.Tasks, MaxParallel: in.MaxParallel}, "/var/log/go-ssh-mcp-parallel", audit)
	if err != nil {
		entry := map[string]any{"actor": actor, "operation": "execute_parallel", "success": false, "error": err.Error(), "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}
		if auditErr := writeAudit(a.auditPath, entry); auditErr != nil {
			return parallel.Summary{}, fmt.Errorf("parallel validation failed (%v) and audit logging failed: %w", err, auditErr)
		}
		return parallel.Summary{}, err
	}
	entry := map[string]any{"actor": actor, "operation": "execute_parallel", "success": true, "run_id": result.RunID, "task_count": result.TaskCount, "max_parallel": result.MaxParallel, "duration_ms": time.Since(started).Milliseconds(), "timestamp": time.Now().UTC().Format(time.RFC3339Nano)}
	if err = writeAudit(a.auditPath, entry); err != nil {
		return parallel.Summary{}, fmt.Errorf("parallel execution completed but audit logging failed: %w", err)
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditErr != nil {
		return result, fmt.Errorf("parallel execution completed but task audit logging failed: %w", auditErr)
	}
	a.logger.Info("parallel execution completed", "actor", actor, "run_id", result.RunID, "task_count", result.TaskCount, "max_parallel", result.MaxParallel, "duration_ms", time.Since(started).Milliseconds())
	return result, nil
}

func tailRunes(value string, max int) string {
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[len(runes)-max:])
}

func writeAudit(path string, entry map[string]any) error {
	if path == "" {
		path = "/var/log/kerno-audit.log"
	}
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return errors.New("audit log path must not be a symlink")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_APPEND|syscall.O_NOFOLLOW, 0640)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err = f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

func actorFromContext(ctx context.Context) string {
	if ti := auth.TokenInfoFromContext(ctx); ti != nil && ti.UserID != "" {
		return ti.UserID
	}
	return ""
}
func tokenVerifier(pool *pgxpool.Pool, resourceURL string) auth.TokenVerifier {
	return func(ctx context.Context, token string, req *http.Request) (*auth.TokenInfo, error) {
		sum := sha256.Sum256([]byte(token))
		hash := hex.EncodeToString(sum[:])
		var userID string
		var scopes []string
		var expires time.Time
		var resource string
		err := pool.QueryRow(ctx, `SELECT a.user_id::text,a.scopes,a.expires_at,a.resource FROM oauth.access_tokens a JOIN oauth.users u ON u.id=a.user_id JOIN oauth.clients c ON c.client_id=a.client_id WHERE a.token_hash=$1 AND a.revoked_at IS NULL AND a.expires_at>now() AND u.is_enabled=TRUE AND c.is_enabled=TRUE`, hash).Scan(&userID, &scopes, &expires, &resource)
		if err != nil {
			return nil, auth.ErrInvalidToken
		}
		if resource != resourceURL {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: userID, Scopes: scopes, Expiration: expires}, nil
	}
}
func loadSigningKey(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("OAuth signing key unavailable: %w", err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("OAuth signing key must be a regular file with mode 0600")
	}
	if stat, ok := st.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
		return nil, errors.New("OAuth signing key must be owned by root")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) < 32 {
		return nil, errors.New("OAuth signing key must contain at least 32 bytes")
	}
	return key, nil
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
