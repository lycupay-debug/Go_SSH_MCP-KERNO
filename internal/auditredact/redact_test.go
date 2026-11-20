package auditredact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMapDropsSecretMaterialAndRetainsOneWayHashes(t *testing.T) {
	input := map[string]any{
		"actor":                  "user-1",
		"password":               "PASSWORD_SENTINEL",
		"password_hash":          "PASSWORD_HASH_SENTINEL",
		"private_key":            "PRIVATE_KEY_SENTINEL",
		"passphrase":             "PASSPHRASE_SENTINEL",
		"access_token":           "ACCESS_TOKEN_SENTINEL",
		"refresh_token":          "REFRESH_TOKEN_SENTINEL",
		"authorization_code":     "AUTH_CODE_SENTINEL",
		"cookie":                 "COOKIE_SENTINEL",
		"command":                "COMMAND_SENTINEL",
		"stdout":                 "STDOUT_SENTINEL",
		"content":                "FILE_CONTENT_SENTINEL",
		"sql":                    "SQL_SENTINEL",
		"database_url":           "DATABASE_URL_SENTINEL",
		"connection_string":      "CONNECTION_STRING_SENTINEL",
		"dsn":                    "DSN_SENTINEL",
		"api_key":                "API_KEY_SENTINEL",
		"access_key":             "ACCESS_KEY_SENTINEL",
		"signing_key":            "SIGNING_KEY_SENTINEL",
		"command_sha256":         "command-hash",
		"query_sha256":           "query-hash",
		"client_name":            "CLIENT_NAME_SENTINEL",
		"client_name_sha256":     "client-name-hash",
		"credential_name":        "CREDENTIAL_NAME_SENTINEL",
		"credential_name_sha256": "credential-name-hash",
		"nested":                 map[string]any{"bearer_token": "NESTED_TOKEN_SENTINEL", "safe": "retained"},
		"array":                  []any{map[string]any{"private_key": "ARRAY_KEY_SENTINEL", "id": "credential-1"}},
	}
	encoded, err := json.Marshal(Map(input))
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, sentinel := range []string{"PASSWORD_SENTINEL", "PASSWORD_HASH_SENTINEL", "PRIVATE_KEY_SENTINEL", "PASSPHRASE_SENTINEL", "ACCESS_TOKEN_SENTINEL", "REFRESH_TOKEN_SENTINEL", "AUTH_CODE_SENTINEL", "COOKIE_SENTINEL", "COMMAND_SENTINEL", "STDOUT_SENTINEL", "FILE_CONTENT_SENTINEL", "SQL_SENTINEL", "NESTED_TOKEN_SENTINEL", "ARRAY_KEY_SENTINEL", "CLIENT_NAME_SENTINEL", "CREDENTIAL_NAME_SENTINEL", "DATABASE_URL_SENTINEL", "CONNECTION_STRING_SENTINEL", "DSN_SENTINEL", "API_KEY_SENTINEL", "ACCESS_KEY_SENTINEL", "SIGNING_KEY_SENTINEL"} {
		if strings.Contains(text, sentinel) {
			t.Errorf("sanitized audit data contains %s: %s", sentinel, text)
		}
	}
	for _, retained := range []string{"user-1", "credential-1", "command-hash", "query-hash", "client-name-hash", "credential-name-hash", "retained"} {
		if !strings.Contains(text, retained) {
			t.Errorf("sanitized audit data lost allowed value %s: %s", retained, text)
		}
	}
}
