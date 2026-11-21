package main

import (
	"net/http"
	"strings"
)

// initialOAuthScopeChallenge adds the remote-management scope to the first
// resource-server challenge while leaving the global middleware's base-scope
// enforcement unchanged. This lets new clients request both scopes up front
// without invalidating existing base-scope tokens for local tools.
func initialOAuthScopeChallenge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&scopeChallengeResponseWriter{ResponseWriter: w}, r)
	})
}

type scopeChallengeResponseWriter struct {
	http.ResponseWriter
}

func (w *scopeChallengeResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *scopeChallengeResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *scopeChallengeResponseWriter) WriteHeader(status int) {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		values := w.Header().Values("WWW-Authenticate")
		if len(values) > 0 {
			w.Header().Del("WWW-Authenticate")
			for _, value := range values {
				w.Header().Add("WWW-Authenticate", includeRemoteManagementScope(value))
			}
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func includeRemoteManagementScope(challenge string) string {
	const scopeMarker = "scope=\""
	start := strings.Index(challenge, scopeMarker)
	if start < 0 {
		return challenge
	}
	valueStart := start + len(scopeMarker)
	valueEndOffset := strings.IndexByte(challenge[valueStart:], '"')
	if valueEndOffset < 0 {
		return challenge
	}
	valueEnd := valueStart + valueEndOffset
	scopes := strings.Fields(challenge[valueStart:valueEnd])
	hasBase, hasRemote := false, false
	for _, scope := range scopes {
		switch scope {
		case "go-ssh-mcp":
			hasBase = true
		case "remote:ssh:manage":
			hasRemote = true
		}
	}
	if !hasBase || hasRemote {
		return challenge
	}
	scopes = append(scopes, "remote:ssh:manage")
	return challenge[:valueStart] + strings.Join(scopes, " ") + challenge[valueEnd:]
}
