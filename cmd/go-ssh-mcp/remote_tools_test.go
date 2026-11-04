// Package main tests the isolated remote SSH MCP tool registry and its OAuth contracts.
package main

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRegisterRemoteToolsExposesEightScopedRemoteTools(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "remote-tools-test", Version: "1"}, nil)
	registerRemoteTools(server, &app{}, "https://example.invalid/.well-known/oauth-protected-resource/mcp")

	client := mcp.NewClient(&mcp.Implementation{Name: "remote-tools-test-client", Version: "1"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	clientSession, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	listed, err := clientSession.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"remote_target_create":          false,
		"remote_target_list":            false,
		"remote_target_delete":          false,
		"remote_credential_create":      false,
		"remote_credential_list":        false,
		"remote_credential_set_default": false,
		"remote_credential_read":        false,
		"remote_ssh_exec":               false,
	}
	if len(listed.Tools) != len(want) {
		t.Fatalf("registered %d remote tools, want %d", len(listed.Tools), len(want))
	}
	var execSchema map[string]any
	for _, tool := range listed.Tools {
		if _, ok := want[tool.Name]; !ok {
			t.Fatalf("unexpected tool in remote registration module: %q", tool.Name)
		}
		want[tool.Name] = true
		schemes, ok := tool.Meta["securitySchemes"].([]any)
		if !ok || len(schemes) != 1 {
			t.Errorf("remote tool %q has invalid OAuth security metadata: %#v", tool.Name, tool.Meta)
			continue
		}
		scheme, ok := schemes[0].(map[string]any)
		if !ok || scheme["type"] != "oauth2" {
			t.Errorf("remote tool %q is missing its OAuth2 security scheme: %#v", tool.Name, schemes[0])
			continue
		}
		scopes, ok := scheme["scopes"].([]any)
		if !ok || len(scopes) != 2 || scopes[0] != "go-ssh-mcp" || scopes[1] != "remote:ssh:manage" {
			t.Errorf("remote tool %q has unexpected OAuth scopes: %#v", tool.Name, scheme["scopes"])
		}
		if tool.Name == "remote_ssh_exec" {
			execSchema, _ = tool.InputSchema.(map[string]any)
		}
	}
	if execSchema == nil {
		t.Fatal("remote_ssh_exec input schema is missing")
	}
	properties, ok := execSchema["properties"].(map[string]any)
	if !ok || properties["credential_id"] == nil {
		t.Fatalf("remote_ssh_exec must expose optional credential_id: %#v", execSchema)
	}
	required, _ := execSchema["required"].([]any)
	for _, field := range required {
		if field == "credential_id" {
			t.Fatal("credential_id must remain optional so the target default can be selected")
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("remote tool %q was not registered", name)
		}
	}
}
