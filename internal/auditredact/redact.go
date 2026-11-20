// Package auditredact applies defense-in-depth filtering to structured audit metadata.
package auditredact

import "strings"

// Map returns a sanitized copy. Raw commands, SQL, file contents, credentials,
// tokens, authentication material, and process output are never retained.
// One-way command/query hashes remain available for correlation.
func Map(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		if sensitiveKey(key) {
			continue
		}
		out[key] = valueOf(value)
	}
	return out
}

func sensitiveKey(raw string) bool {
	key := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(raw))
	switch key {
	case "command_sha256", "query_sha256", "client_name_sha256", "credential_name_sha256":
		return false
	}
	for _, fragment := range []string{
		"password", "passwd", "passphrase", "private_key", "secret", "client_name", "credential_name",
		"access_token", "refresh_token", "authorization_code", "code_verifier",
		"bearer", "cookie", "csrf", "authorization", "stdout", "stderr",
		"command", "content", "sql", "query", "token", "host_key_data",
		"key_material", "session_id", "signed_request", "database_url", "connection_string", "dsn", "api_key", "access_key", "signing_key",
	} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func valueOf(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return Map(typed)
	case map[string]string:
		out := make(map[string]string, len(typed))
		for key, item := range typed {
			if !sensitiveKey(key) {
				out[key] = item
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, valueOf(item))
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, Map(item))
		}
		return out
	default:
		return value
	}
}
