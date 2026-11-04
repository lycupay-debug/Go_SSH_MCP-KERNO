package main

// Remote SSH MCP surface.
//
// Responsibility: define and register remote target, credential, and SSH execution tools.
// Dependencies: the remote Store, MCP SDK, and OAuth token context helpers.
// Collaboration: main registers the established local-management tools, then calls
// registerRemoteTools; each handler delegates ownership checks and SSH behavior to
// internal/remote and records security-relevant operations in its audit store.
// Side effects: PostgreSQL reads/writes, audit writes, and outbound SSH execution.
// This file does not alter local host-management tools or their root execution model.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/remote"
)

type remoteTargetInput struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	HostKey  string `json:"host_key" jsonschema_description:"SSH host 公钥，OpenSSH authorized_keys 格式；必须通过独立可信渠道核验后提交。"`
}
type remoteTargetIDInput struct {
	TargetID string `json:"target_id"`
}
type remoteCredentialInput struct {
	TargetID   string `json:"target_id"`
	Name       string `json:"name"`
	PrivateKey string `json:"private_key" jsonschema_description:"SSH 私钥原文；按系统配置明文保存于 PostgreSQL，仅凭 remote:ssh:manage 权限访问。"`
	Passphrase string `json:"passphrase,omitempty" jsonschema_description:"可选私钥口令；如提供，同样明文保存在 PostgreSQL。"`
}
type remoteCredentialIDInput struct {
	CredentialID string `json:"credential_id"`
}
type remoteCredentialListInput struct {
	TargetID string `json:"target_id"`
}
type remoteSetDefaultCredentialInput struct {
	TargetID     string `json:"target_id"`
	CredentialID string `json:"credential_id"`
}
type remoteExecInput struct {
	TargetID       string `json:"target_id"`
	CredentialID   string `json:"credential_id,omitempty" jsonschema_description:"可选；省略时使用此目标当前设置的默认凭证。"`
	Command        string `json:"command"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

var errRemoteScopeRequired = errors.New("OAuth token requires remote:ssh:manage scope")

func protectedResourceMetadataURL(resourceURL string) (string, error) {
	parsed, err := url.Parse(resourceURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("RESOURCE_URL must be an absolute URL")
	}
	return parsed.Scheme + "://" + parsed.Host + "/.well-known/oauth-protected-resource" + strings.TrimRight(parsed.EscapedPath(), "/"), nil
}

func remoteToolSecurityMeta() mcp.Meta {
	return mcp.Meta{
		"securitySchemes": []any{
			map[string]any{"type": "oauth2", "scopes": []string{"go-ssh-mcp", "remote:ssh:manage"}},
		},
	}
}

func remoteScopeChallengeResult(resourceMetadataURL string) *mcp.CallToolResult {
	challenge := fmt.Sprintf(
		`Bearer resource_metadata=%q, error="insufficient_scope", scope="go-ssh-mcp remote:ssh:manage", error_description="This remote SSH tool requires the remote:ssh:manage OAuth scope"`,
		resourceMetadataURL,
	)
	return &mcp.CallToolResult{
		Meta:    mcp.Meta{"mcp/www_authenticate": []string{challenge}},
		Content: []mcp.Content{&mcp.TextContent{Text: "OAuth authorization must be upgraded to include remote:ssh:manage."}},
		IsError: true,
	}
}

func remoteActor(ctx context.Context) (remote.Actor, error) {
	return remoteActorFromTokenInfo(auth.TokenInfoFromContext(ctx))
}

func remoteActorFromTokenInfo(ti *auth.TokenInfo) (remote.Actor, error) {
	if ti == nil || ti.UserID == "" {
		return remote.Actor{}, errors.New("authenticated OAuth user is required")
	}
	allowed := false
	for _, scope := range ti.Scopes {
		if scope == "remote:ssh:manage" {
			allowed = true
			break
		}
	}
	if !allowed {
		return remote.Actor{}, errRemoteScopeRequired
	}
	clientID, _ := ti.Extra["client_id"].(string)
	return remote.Actor{UserID: ti.UserID, ClientID: clientID}, nil
}
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// auditRemoteOperation records a remote tool result without recording command text or secrets.
// The caller supplies only bounded metadata and, where applicable, a command hash.
func auditRemoteOperation(ctx context.Context, store *remote.Store, actor remote.Actor, targetID, credentialID, operation string, operationErr error, details map[string]any) error {
	if details == nil {
		details = make(map[string]any)
	}
	details["error"] = errorText(operationErr)
	outcome := "success"
	if operationErr != nil {
		outcome = "failure"
	}
	if err := store.Audit(ctx, actor, targetID, credentialID, operation, outcome, details); err != nil {
		return fmt.Errorf("%s audit failed: %w", operation, err)
	}
	return nil
}

// registerRemoteTools adds only the remote SSH tool family; local tools are untouched.
func registerRemoteTools(mcpServer *mcp.Server, application *app, resourceMetadataURL string) {
	// Remote SSH tools are isolated from execute_shell and require an explicit OAuth scope.
	mcp.AddTool(mcpServer, &mcp.Tool{Meta: remoteToolSecurityMeta(), Name: "remote_target_create", Description: "登记远端 SSH 目标。必须提交通过可信独立渠道核验的 SSH Host 公钥；目标归属于当前 OAuth 用户。"}, func(ctx context.Context, req *mcp.CallToolRequest, in remoteTargetInput) (*mcp.CallToolResult, *remote.Target, error) {
		actor, err := remoteActor(ctx)
		if err != nil {
			if errors.Is(err, errRemoteScopeRequired) {
				return remoteScopeChallengeResult(resourceMetadataURL), nil, nil
			}
			return nil, nil, err
		}
		out, err := application.remote.CreateTarget(ctx, actor, remote.TargetInput{Name: in.Name, Host: in.Host, Port: in.Port, Username: in.Username, HostKey: in.HostKey})
		if auditErr := auditRemoteOperation(ctx, application.remote, actor, out.ID, "", "target.create", err, map[string]any{"host": in.Host, "port": in.Port, "username": in.Username}); auditErr != nil {
			return nil, nil, auditErr
		}
		return nil, &out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Meta: remoteToolSecurityMeta(), Name: "remote_target_list", Description: "列出当前 OAuth 用户登记的远端 SSH 目标。"}, func(ctx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, []remote.Target, error) {
		actor, err := remoteActor(ctx)
		if err != nil {
			if errors.Is(err, errRemoteScopeRequired) {
				return remoteScopeChallengeResult(resourceMetadataURL), nil, nil
			}
			return nil, nil, err
		}
		out, err := application.remote.ListTargets(ctx, actor)
		if auditErr := auditRemoteOperation(ctx, application.remote, actor, "", "", "target.list", err, map[string]any{"count": len(out)}); auditErr != nil {
			return nil, nil, auditErr
		}
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Meta: remoteToolSecurityMeta(), Name: "remote_target_delete", Description: "删除当前 OAuth 用户拥有的远端 SSH 目标及其 SSH 凭证。"}, func(ctx context.Context, req *mcp.CallToolRequest, in remoteTargetIDInput) (*mcp.CallToolResult, map[string]any, error) {
		actor, err := remoteActor(ctx)
		if err != nil {
			if errors.Is(err, errRemoteScopeRequired) {
				return remoteScopeChallengeResult(resourceMetadataURL), nil, nil
			}
			return nil, nil, err
		}
		err = application.remote.DeleteTarget(ctx, actor, in.TargetID)
		if auditErr := auditRemoteOperation(ctx, application.remote, actor, "", "", "target.delete", err, map[string]any{"target_id": in.TargetID}); auditErr != nil {
			return nil, nil, auditErr
		}
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"deleted": true, "target_id": in.TargetID}, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Meta: remoteToolSecurityMeta(), Name: "remote_credential_create", Description: "为当前用户的远端目标保存 SSH 私钥。私钥原文写入 PostgreSQL，响应仅返回凭证元数据。"}, func(ctx context.Context, req *mcp.CallToolRequest, in remoteCredentialInput) (*mcp.CallToolResult, *remote.CredentialInfo, error) {
		actor, err := remoteActor(ctx)
		if err != nil {
			if errors.Is(err, errRemoteScopeRequired) {
				return remoteScopeChallengeResult(resourceMetadataURL), nil, nil
			}
			return nil, nil, err
		}
		out, err := application.remote.SaveCredential(ctx, actor, in.TargetID, in.Name, in.PrivateKey, in.Passphrase)
		auditTargetID := out.TargetID
		if auditErr := auditRemoteOperation(ctx, application.remote, actor, auditTargetID, out.ID, "credential.create", err, map[string]any{"requested_target_id": in.TargetID, "credential_name": in.Name}); auditErr != nil {
			return nil, nil, auditErr
		}
		return nil, &out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Meta: remoteToolSecurityMeta(), Name: "remote_credential_list", Description: "列出指定远端目标的 SSH 凭证元数据，不返回私钥或口令。显示当前默认凭证。"}, func(ctx context.Context, req *mcp.CallToolRequest, in remoteCredentialListInput) (*mcp.CallToolResult, []remote.CredentialInfo, error) {
		actor, err := remoteActor(ctx)
		if err != nil {
			if errors.Is(err, errRemoteScopeRequired) {
				return remoteScopeChallengeResult(resourceMetadataURL), nil, nil
			}
			return nil, nil, err
		}
		out, err := application.remote.ListCredentials(ctx, actor, in.TargetID)
		auditTargetID := in.TargetID
		if _, parseErr := uuid.Parse(auditTargetID); parseErr != nil {
			auditTargetID = ""
		}
		if auditErr := auditRemoteOperation(ctx, application.remote, actor, auditTargetID, "", "credential.list", err, map[string]any{"count": len(out)}); auditErr != nil {
			return nil, nil, auditErr
		}
		return nil, out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Meta: remoteToolSecurityMeta(), Name: "remote_credential_set_default", Description: "将指定目标下一个已启用的 SSH 凭证设为默认凭证；同一目标最多只有一个默认凭证。"}, func(ctx context.Context, req *mcp.CallToolRequest, in remoteSetDefaultCredentialInput) (*mcp.CallToolResult, map[string]any, error) {
		actor, err := remoteActor(ctx)
		if err != nil {
			if errors.Is(err, errRemoteScopeRequired) {
				return remoteScopeChallengeResult(resourceMetadataURL), nil, nil
			}
			return nil, nil, err
		}
		err = application.remote.SetDefaultCredential(ctx, actor, in.TargetID, in.CredentialID)
		auditTargetID, auditCredentialID := in.TargetID, in.CredentialID
		if _, parseErr := uuid.Parse(auditTargetID); parseErr != nil {
			auditTargetID = ""
		}
		if _, parseErr := uuid.Parse(auditCredentialID); parseErr != nil {
			auditCredentialID = ""
		}
		if auditErr := auditRemoteOperation(ctx, application.remote, actor, auditTargetID, auditCredentialID, "credential.set_default", err, nil); auditErr != nil {
			return nil, nil, auditErr
		}
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{"updated": true, "target_id": in.TargetID, "credential_id": in.CredentialID}, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Meta: remoteToolSecurityMeta(), Name: "remote_credential_read", Description: "读取当前用户拥有的 SSH 凭证，包含 PostgreSQL 中保存的私钥原文。调用需要 remote:ssh:manage 权限并写入审计。"}, func(ctx context.Context, req *mcp.CallToolRequest, in remoteCredentialIDInput) (*mcp.CallToolResult, *remote.Credential, error) {
		actor, err := remoteActor(ctx)
		if err != nil {
			if errors.Is(err, errRemoteScopeRequired) {
				return remoteScopeChallengeResult(resourceMetadataURL), nil, nil
			}
			return nil, nil, err
		}
		out, err := application.remote.ReadCredential(ctx, actor, in.CredentialID)
		if auditErr := auditRemoteOperation(ctx, application.remote, actor, out.TargetID, out.ID, "credential.read", err, map[string]any{"requested_credential_id": in.CredentialID}); auditErr != nil {
			return nil, nil, fmt.Errorf("credential read audit failed; secret withheld: %w", auditErr)
		}
		return nil, &out, err
	})
	mcp.AddTool(mcpServer, &mcp.Tool{Meta: remoteToolSecurityMeta(), Name: "remote_ssh_exec", Description: "通过已登记目标执行远端命令。默认使用目标的默认 SSH 凭证；可选 credential_id 用于临时指定其他凭证。严格校验固定 Host Key；命令最长 16 KiB、超时最长 300 秒、输出每流最多 1 MiB。"}, func(ctx context.Context, req *mcp.CallToolRequest, in remoteExecInput) (*mcp.CallToolResult, *remote.ExecResult, error) {
		actor, err := remoteActor(ctx)
		if err != nil {
			if errors.Is(err, errRemoteScopeRequired) {
				return remoteScopeChallengeResult(resourceMetadataURL), nil, nil
			}
			return nil, nil, err
		}
		timeout := in.TimeoutSeconds
		if timeout == 0 {
			timeout = 30
		}
		if timeout < 1 || timeout > 300 {
			return nil, nil, errors.New("timeout_seconds 必须在 1 至 300 之间")
		}
		out, err := application.remote.Execute(ctx, actor, in.TargetID, in.CredentialID, in.Command, time.Duration(timeout)*time.Second)
		sum := sha256.Sum256([]byte(in.Command))
		auditTargetID := in.TargetID
		if _, parseErr := uuid.Parse(auditTargetID); parseErr != nil {
			auditTargetID = ""
		}
		if auditErr := auditRemoteOperation(ctx, application.remote, actor, auditTargetID, out.CredentialID, "ssh.exec", err, map[string]any{"command_sha256": hex.EncodeToString(sum[:]), "exit_code": out.ExitCode, "duration_ms": out.DurationMS}); auditErr != nil {
			return nil, nil, auditErr
		}
		return nil, &out, err
	})

}
