package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

const scopeName = "go-ssh-mcp"

type Server struct {
	Pool       *pgxpool.Pool
	Issuer     string
	Resource   string
	SigningKey []byte
	mu         sync.Mutex
	rates      map[string]rateWindow
}

type rateWindow struct {
	Start time.Time
	Count int
}

type signedRequest struct {
	ClientID    string   `json:"client_id"`
	RedirectURI string   `json:"redirect_uri"`
	Challenge   string   `json:"challenge"`
	State       string   `json:"state"`
	Scopes      []string `json:"scopes"`
	Resource    string   `json:"resource"`
	Expires     int64    `json:"exp"`
}

type clientRegistration struct {
	ClientName              string   `json:"client_name"`
	ApplicationType         string   `json:"application_type"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
}

func (s *Server) endpoint(path string) string { return strings.TrimRight(s.Issuer, "/") + path }
func (s *Server) localEndpoint(path string) string {
	u, err := url.Parse(s.Issuer)
	if err != nil {
		return path
	}
	return strings.TrimRight(u.EscapedPath(), "/") + path
}

func New(pool *pgxpool.Pool, issuer, resource string, key []byte) *Server {
	return &Server{Pool: pool, Issuer: strings.TrimRight(issuer, "/"), Resource: resource, SigningKey: key, rates: map[string]rateWindow{}}
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.protectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authorizationServerMetadata)
	mux.HandleFunc("POST /register", s.registerClient)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /consent", s.consent)
	mux.HandleFunc("POST /consent", s.consent)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("POST /revoke", s.revoke)
}

func (s *Server) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{"resource": s.Resource, "authorization_servers": []string{s.Issuer}, "scopes_supported": []string{scopeName, "offline_access"}, "bearer_methods_supported": []string{"header"}})
}
func (s *Server) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": s.Issuer, "authorization_endpoint": s.endpoint("/authorize"), "token_endpoint": s.endpoint("/token"),
		"registration_endpoint": s.endpoint("/register"), "revocation_endpoint": s.endpoint("/revoke"),
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported": []string{scopeName, "offline_access"},
	})
}

func (s *Server) registerClient(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate("register:"+clientIP(r), 30, time.Hour) {
		w.Header().Set("Retry-After", "3600")
		oauthError(w, http.StatusTooManyRequests, "rate_limited", "Too many client registrations")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var in clientRegistration
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "Invalid JSON client metadata")
		return
	}
	if in.TokenEndpointAuthMethod != "" && in.TokenEndpointAuthMethod != "none" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "Only public clients are supported")
		return
	}
	if in.ApplicationType == "" {
		in.ApplicationType = "web"
	}
	if in.ApplicationType != "web" && in.ApplicationType != "native" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "application_type must be web or native")
		return
	}
	if len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > 20 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "At least one redirect URI is required")
		return
	}
	seen := map[string]bool{}
	for _, raw := range in.RedirectURIs {
		if seen[raw] || !validRedirectURI(raw) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "Redirect URIs must be absolute HTTPS or loopback HTTP URIs without fragments")
			return
		}
		seen[raw] = true
	}
	if in.Scope == "" {
		in.Scope = scopeName
	}
	if !scopeSubset(strings.Fields(in.Scope), []string{scopeName, "offline_access"}) {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "Unsupported scope")
		return
	}
	if len(in.GrantTypes) == 0 {
		in.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(in.ResponseTypes) == 0 {
		in.ResponseTypes = []string{"code"}
	}
	for _, g := range in.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "Unsupported grant type")
			return
		}
	}
	for _, v := range in.ResponseTypes {
		if v != "code" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "Unsupported response type")
			return
		}
	}
	id, err := randomToken(24)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "Could not create client")
		return
	}
	in.TokenEndpointAuthMethod = "none"
	metadata := map[string]any{"client_id": id, "client_name": in.ClientName, "application_type": in.ApplicationType, "redirect_uris": in.RedirectURIs, "token_endpoint_auth_method": "none", "grant_types": in.GrantTypes, "response_types": in.ResponseTypes, "scope": in.Scope}
	raw, _ := json.Marshal(metadata)
	_, err = s.Pool.Exec(r.Context(), `INSERT INTO oauth.clients(client_id,metadata,is_enabled) VALUES($1,$2::jsonb,TRUE)`, id, string(raw))
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "Could not register client")
		return
	}
	s.audit(r.Context(), "client.registered", "success", "", id, map[string]any{"client_name": in.ClientName, "redirect_uri_count": len(in.RedirectURIs)})
	metadata["client_id_issued_at"] = time.Now().Unix()
	writeJSON(w, http.StatusCreated, metadata)
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Fragment != "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" && u.Host != "" {
		return true
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if strings.EqualFold(host, "localhost") {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	}
	return false
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID, redirectURI := q.Get("client_id"), q.Get("redirect_uri")
	if q.Get("response_type") != "code" || clientID == "" || redirectURI == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "response_type=code, client_id and redirect_uri are required")
		return
	}
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43 || len(q.Get("code_challenge")) > 128 {
		oauthError(w, http.StatusBadRequest, "invalid_request", "PKCE S256 is required")
		return
	}
	if q.Get("state") == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "state is required")
		return
	}
	var enabled bool
	var metadataRaw []byte
	err := s.Pool.QueryRow(r.Context(), `SELECT metadata,is_enabled FROM oauth.clients WHERE client_id=$1`, clientID).Scan(&metadataRaw, &enabled)
	if err != nil || !enabled {
		oauthError(w, http.StatusBadRequest, "invalid_client", "Unknown or disabled client")
		return
	}
	var meta map[string]any
	if json.Unmarshal(metadataRaw, &meta) != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client", "Invalid client metadata")
		return
	}
	var redirects []string
	b, _ := json.Marshal(meta["redirect_uris"])
	_ = json.Unmarshal(b, &redirects)
	matched := false
	for _, u := range redirects {
		if u == redirectURI {
			matched = true
			break
		}
	}
	if !matched {
		oauthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri does not exactly match registered metadata")
		return
	}
	scopes := strings.Fields(q.Get("scope"))
	if len(scopes) == 0 {
		scopes = []string{scopeName}
	}
	if !scopeSubset(scopes, []string{scopeName, "offline_access"}) {
		redirectWithError(w, redirectURI, "invalid_scope", q.Get("state"), s.Issuer)
		return
	}
	resource := q.Get("resource")
	if resource == "" {
		resource = s.Resource
	}
	if resource != s.Resource {
		redirectWithError(w, redirectURI, "invalid_target", q.Get("state"), s.Issuer)
		return
	}
	p := signedRequest{ClientID: clientID, RedirectURI: redirectURI, Challenge: q.Get("code_challenge"), State: q.Get("state"), Scopes: scopes, Resource: resource, Expires: time.Now().Add(10 * time.Minute).Unix()}
	signed, err := s.sign(p)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "Could not create authorization request")
		return
	}
	http.Redirect(w, r, s.localEndpoint("/login")+"?request="+url.QueryEscape(signed), http.StatusSeeOther)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	signed := r.URL.Query().Get("request")
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_request", "Invalid form")
			return
		}
		signed = r.Form.Get("request")
	}
	p, err := s.verify(signed)
	if err != nil {
		htmlPage(w, http.StatusBadRequest, "授权请求无效", "请从 MCP 客户端重新发起连接。")
		return
	}
	var enabled bool
	if err = s.Pool.QueryRow(r.Context(), `SELECT is_enabled FROM oauth.clients WHERE client_id=$1`, p.ClientID).Scan(&enabled); err != nil || !enabled {
		htmlPage(w, http.StatusBadRequest, "授权请求无效", "客户端不存在或已停用。")
		return
	}
	if r.Method == http.MethodGet {
		if userID := s.sessionUser(r); userID != "" {
			http.Redirect(w, r, s.localEndpoint("/consent")+"?request="+url.QueryEscape(signed), http.StatusSeeOther)
			return
		}
		nonce, _ := randomToken(32)
		http.SetCookie(w, &http.Cookie{Name: "go_ssh_mcp_login_csrf", Value: nonce, Path: "/", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		htmlPage(w, http.StatusOK, "登录 Go_SSH_MCP", loginForm(signed, nonce, ""))
		return
	}
	cookie, err := r.Cookie("go_ssh_mcp_login_csrf")
	if err != nil || !constantEqual(cookie.Value, r.Form.Get("login_csrf")) {
		htmlPage(w, http.StatusBadRequest, "登录请求已失效", "请刷新页面后重试。")
		return
	}
	username, password := r.Form.Get("username"), r.Form.Get("password")
	rateKey := "login:" + clientIP(r) + ":" + username
	if !s.allowRate(rateKey, 10, 15*time.Minute) {
		w.Header().Set("Retry-After", "900")
		htmlPage(w, http.StatusTooManyRequests, "尝试次数过多", "请稍后再试。")
		return
	}
	var userID, hash string
	err = s.Pool.QueryRow(r.Context(), `SELECT id::text,password_hash FROM oauth.users WHERE username=$1 AND is_enabled=TRUE`, username).Scan(&userID, &hash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		s.audit(r.Context(), "login.failed", "denied", "", p.ClientID, map[string]any{"username": username, "ip": clientIP(r)})
		htmlPage(w, http.StatusUnauthorized, "登录失败", loginForm(signed, cookie.Value, "用户名或密码错误。"))
		return
	}
	s.resetRate(rateKey)
	s.audit(r.Context(), "login.succeeded", "success", userID, p.ClientID, map[string]any{"ip": clientIP(r)})
	sessionToken, _ := randomToken(48)
	csrf, _ := randomToken(32)
	_, err = s.Pool.Exec(r.Context(), `INSERT INTO oauth.sessions(id,session_hash,csrf_hash,user_id,expires_at) VALUES(gen_random_uuid(),$1,$2,$3,now()+interval '8 hours')`, hashToken(sessionToken), hashToken(csrf), userID)
	if err != nil {
		htmlPage(w, http.StatusInternalServerError, "登录失败", "无法建立登录会话。")
		return
	}
	_, _ = s.Pool.Exec(r.Context(), `UPDATE oauth.users SET last_login_at=now() WHERE id=$1`, userID)
	http.SetCookie(w, &http.Cookie{Name: "go_ssh_mcp_session", Value: sessionToken, Path: "/", MaxAge: 8 * 3600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "go_ssh_mcp_csrf", Value: csrf, Path: "/", MaxAge: 8 * 3600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "go_ssh_mcp_login_csrf", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, s.localEndpoint("/consent")+"?request="+url.QueryEscape(signed), http.StatusSeeOther)
}

func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	signed := r.URL.Query().Get("request")
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_request", "Invalid form")
			return
		}
		signed = r.Form.Get("request")
	}
	p, err := s.verify(signed)
	if err != nil {
		htmlPage(w, http.StatusBadRequest, "授权请求无效", "请重新从 MCP 客户端发起连接。")
		return
	}
	userID := s.sessionUser(r)
	if userID == "" {
		http.Redirect(w, r, s.localEndpoint("/login")+"?request="+url.QueryEscape(signed), http.StatusSeeOther)
		return
	}
	var clientName string
	var enabled bool
	err = s.Pool.QueryRow(r.Context(), `SELECT COALESCE(metadata->>'client_name',client_id),is_enabled FROM oauth.clients WHERE client_id=$1`, p.ClientID).Scan(&clientName, &enabled)
	if err != nil || !enabled {
		htmlPage(w, http.StatusBadRequest, "授权请求无效", "客户端不存在或已停用。")
		return
	}
	if r.Method == http.MethodGet {
		var csrfHash string
		if err = s.Pool.QueryRow(r.Context(), `SELECT csrf_hash FROM oauth.sessions WHERE session_hash=$1 AND user_id=$2 AND expires_at>now()`, hashTokenCookie(r, "go_ssh_mcp_session"), userID).Scan(&csrfHash); err != nil {
			http.Redirect(w, r, s.localEndpoint("/login")+"?request="+url.QueryEscape(signed), http.StatusSeeOther)
			return
		}
		csrfCookie, _ := r.Cookie("go_ssh_mcp_csrf")
		if csrfCookie == nil || !constantEqual(hashToken(csrfCookie.Value), csrfHash) {
			htmlPage(w, http.StatusForbidden, "安全验证失败", "请重新登录。")
			return
		}
		htmlPage(w, http.StatusOK, "授权 MCP 客户端", consentForm(signed, csrfCookie.Value, html.EscapeString(clientName), html.EscapeString(strings.Join(p.Scopes, " "))))
		return
	}
	csrfCookie, err := r.Cookie("go_ssh_mcp_csrf")
	if err != nil || !constantEqual(csrfCookie.Value, r.Form.Get("csrf_token")) || !s.validSessionCSRF(r, userID, csrfCookie.Value) {
		htmlPage(w, http.StatusForbidden, "安全验证失败", "请重新登录并重试。")
		return
	}
	if r.Form.Get("decision") != "approve" {
		s.audit(r.Context(), "consent.denied", "denied", userID, p.ClientID, map[string]any{"scopes": p.Scopes})
		redirectWithError(w, p.RedirectURI, "access_denied", p.State, s.Issuer)
		return
	}
	code, err := randomToken(48)
	if err != nil {
		htmlPage(w, http.StatusInternalServerError, "授权失败", "无法生成授权码。")
		return
	}
	_, err = s.Pool.Exec(r.Context(), `INSERT INTO oauth.authorization_codes(id,code_hash,client_id,user_id,redirect_uri,code_challenge,scopes,resource,expires_at)
		VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,now()+interval '5 minutes')`, hashToken(code), p.ClientID, userID, p.RedirectURI, p.Challenge, p.Scopes, p.Resource)
	if err != nil {
		htmlPage(w, http.StatusInternalServerError, "授权失败", "无法保存授权码。")
		return
	}
	_, _ = s.Pool.Exec(r.Context(), `INSERT INTO oauth.consents(id,user_id,client_id,scopes,granted_at) VALUES(gen_random_uuid(),$1,$2,$3,now())
		ON CONFLICT(user_id,client_id) DO UPDATE SET scopes=EXCLUDED.scopes,granted_at=now()`, userID, p.ClientID, p.Scopes)
	s.audit(r.Context(), "consent.granted", "success", userID, p.ClientID, map[string]any{"scopes": p.Scopes, "resource": p.Resource})
	target := appendQuery(p.RedirectURI, map[string]string{"code": code, "state": p.State, "iss": s.Issuer})
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if !s.allowRate("token:"+clientIP(r), 120, time.Minute) {
		w.Header().Set("Retry-After", "60")
		oauthError(w, http.StatusTooManyRequests, "rate_limited", "Too many token requests")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "Invalid form body")
		return
	}
	if requestedResource := r.Form.Get("resource"); requestedResource != "" && requestedResource != s.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource does not match this MCP server")
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r)
	case "refresh_token":
		s.refresh(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "Unsupported grant_type")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request) {
	clientID, code, redirectURI := r.Form.Get("client_id"), r.Form.Get("code"), r.Form.Get("redirect_uri")
	if clientID == "" || code == "" || redirectURI == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "client_id, code and redirect_uri are required")
		return
	}
	verifier := r.Form.Get("code_verifier")
	if len(verifier) < 43 || len(verifier) > 128 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "Invalid PKCE verifier")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		oauthError(w, 500, "server_error", "Database error")
		return
	}
	defer tx.Rollback(r.Context())
	var codeID, userID, storedRedirect, storedChallenge, resource string
	var scopes []string
	var expires time.Time
	var enabled bool
	err = tx.QueryRow(r.Context(), `SELECT c.id::text,c.user_id::text,c.redirect_uri,c.code_challenge,c.scopes,c.resource,c.expires_at,cl.is_enabled
		FROM oauth.authorization_codes c JOIN oauth.clients cl ON cl.client_id=c.client_id
		JOIN oauth.users u ON u.id=c.user_id
		WHERE c.code_hash=$1 AND c.client_id=$2 AND c.exchanged_at IS NULL AND u.is_enabled=TRUE FOR UPDATE OF c`, hashToken(code), clientID).Scan(&codeID, &userID, &storedRedirect, &storedChallenge, &scopes, &resource, &expires, &enabled)
	if err != nil || !enabled || time.Now().After(expires) || storedRedirect != redirectURI || storedChallenge != challenge || resource != s.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "Authorization code, redirect URI, PKCE verifier or resource is invalid")
		return
	}
	tag, err := tx.Exec(r.Context(), `UPDATE oauth.authorization_codes SET exchanged_at=now() WHERE id=$1 AND exchanged_at IS NULL`, codeID)
	if err != nil || tag.RowsAffected() != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "Authorization code has already been used")
		return
	}
	pair, err := s.issuePair(r.Context(), tx, clientID, userID, scopes, resource, "")
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "Could not issue tokens")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "Could not commit token issuance")
		return
	}
	s.audit(r.Context(), "token.issued", "success", userID, clientID, map[string]any{"grant_type": "authorization_code", "scopes": scopes, "resource": resource})
	writeToken(w, pair, scopes)
}

type tokenPair struct {
	Access  string
	Refresh string
	Expires int
}

func (s *Server) issuePair(ctx context.Context, tx pgx.Tx, clientID, userID string, scopes []string, resource, familyID string) (tokenPair, error) {
	pair := tokenPair{Expires: 900}
	var err error
	pair.Access, err = randomToken(48)
	if err != nil {
		return pair, err
	}
	pair.Refresh, err = randomToken(48)
	if err != nil {
		return pair, err
	}
	if familyID == "" {
		familyID = uuid.NewString()
		_, err = tx.Exec(ctx, `INSERT INTO oauth.refresh_token_families(id,client_id,user_id,created_at) VALUES($1,$2,$3,now())`, familyID, clientID, userID)
		if err != nil {
			return pair, err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO oauth.access_tokens(id,token_hash,client_id,user_id,scopes,resource,family_id,expires_at)
		VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6,now()+interval '15 minutes')`, hashToken(pair.Access), clientID, userID, scopes, resource, familyID)
	if err != nil {
		return pair, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO oauth.refresh_tokens(id,token_hash,family_id,client_id,user_id,scopes,resource,expires_at)
		VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6,now()+interval '30 days')`, hashToken(pair.Refresh), familyID, clientID, userID, scopes, resource)
	if err != nil {
		return pair, err
	}
	return pair, nil
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	clientID, token := r.Form.Get("client_id"), r.Form.Get("refresh_token")
	if clientID == "" || token == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "client_id and refresh_token are required")
		return
	}
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		oauthError(w, 500, "server_error", "Database error")
		return
	}
	defer tx.Rollback(r.Context())
	var id, familyID, userID, resource string
	var scopes []string
	var rotated, revoked *time.Time
	var expires time.Time
	err = tx.QueryRow(r.Context(), `SELECT r.id::text,r.family_id::text,r.user_id::text,r.resource,r.scopes,r.rotated_at,r.revoked_at,r.expires_at
		FROM oauth.refresh_tokens r JOIN oauth.clients c ON c.client_id=r.client_id JOIN oauth.users u ON u.id=r.user_id
		WHERE r.token_hash=$1 AND r.client_id=$2 AND c.is_enabled=TRUE AND u.is_enabled=TRUE FOR UPDATE OF r`, hashToken(token), clientID).Scan(&id, &familyID, &userID, &resource, &scopes, &rotated, &revoked, &expires)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "Refresh token is invalid")
		return
	}
	if rotated != nil {
		_, _ = tx.Exec(r.Context(), `UPDATE oauth.refresh_token_families SET revoked_at=COALESCE(revoked_at,now()),reuse_detected_at=COALESCE(reuse_detected_at,now()) WHERE id=$1`, familyID)
		_, _ = tx.Exec(r.Context(), `UPDATE oauth.refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1`, familyID)
		_, _ = tx.Exec(r.Context(), `UPDATE oauth.access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1`, familyID)
		_ = tx.Commit(r.Context())
		s.audit(r.Context(), "refresh_token.reuse_detected", "denied", userID, clientID, map[string]any{"family_id": familyID})
		oauthError(w, http.StatusBadRequest, "invalid_grant", "Refresh-token reuse detected; token family revoked")
		return
	}
	if revoked != nil || time.Now().After(expires) || resource != s.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "Refresh token is expired or revoked")
		return
	}
	tag, err := tx.Exec(r.Context(), `UPDATE oauth.refresh_tokens SET rotated_at=now() WHERE id=$1 AND rotated_at IS NULL AND revoked_at IS NULL`, id)
	if err != nil || tag.RowsAffected() != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "Refresh token already rotated")
		return
	}
	pair, err := s.issuePair(r.Context(), tx, clientID, userID, scopes, resource, familyID)
	if err != nil {
		oauthError(w, 500, "server_error", "Could not rotate tokens")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		oauthError(w, 500, "server_error", "Could not commit token rotation")
		return
	}
	s.audit(r.Context(), "token.refreshed", "success", userID, clientID, map[string]any{"scopes": scopes, "resource": resource})
	writeToken(w, pair, scopes)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "Invalid form")
		return
	}
	token := r.Form.Get("token")
	if token == "" {
		oauthError(w, 400, "invalid_request", "token is required")
		return
	}
	hash := hashToken(token)
	tx, err := s.Pool.Begin(r.Context())
	if err != nil {
		oauthError(w, 500, "server_error", "Database error")
		return
	}
	defer tx.Rollback(r.Context())
	var familyID string
	err = tx.QueryRow(r.Context(), `UPDATE oauth.access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE token_hash=$1 RETURNING COALESCE(family_id::text,'')`, hash).Scan(&familyID)
	if err != nil {
		err = tx.QueryRow(r.Context(), `SELECT family_id::text FROM oauth.refresh_tokens WHERE token_hash=$1`, hash).Scan(&familyID)
		if err != nil {
			_ = tx.Commit(r.Context())
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	if familyID != "" {
		_, _ = tx.Exec(r.Context(), `UPDATE oauth.refresh_token_families SET revoked_at=COALESCE(revoked_at,now()) WHERE id=$1`, familyID)
		_, _ = tx.Exec(r.Context(), `UPDATE oauth.refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1`, familyID)
		_, _ = tx.Exec(r.Context(), `UPDATE oauth.access_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE family_id=$1`, familyID)
	}
	if err = tx.Commit(r.Context()); err != nil {
		oauthError(w, 500, "server_error", "Could not revoke token")
		return
	}
	s.audit(r.Context(), "token.revoked", "success", "", "", map[string]any{"family_id": familyID})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) sessionUser(r *http.Request) string {
	cookie, err := r.Cookie("go_ssh_mcp_session")
	if err != nil {
		return ""
	}
	var id string
	err = s.Pool.QueryRow(r.Context(), `SELECT user_id::text FROM oauth.sessions WHERE session_hash=$1 AND expires_at>now()`, hashToken(cookie.Value)).Scan(&id)
	if err != nil {
		return ""
	}
	return id
}
func (s *Server) validSessionCSRF(r *http.Request, userID, csrf string) bool {
	cookie, err := r.Cookie("go_ssh_mcp_session")
	if err != nil {
		return false
	}
	var ok bool
	err = s.Pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM oauth.sessions WHERE session_hash=$1 AND csrf_hash=$2 AND user_id=$3 AND expires_at>now())`, hashToken(cookie.Value), hashToken(csrf), userID).Scan(&ok)
	return err == nil && ok
}

func (s *Server) validSession(r *http.Request, userID string) bool {
	cookie, err := r.Cookie("go_ssh_mcp_session")
	if err != nil {
		return false
	}
	var ok bool
	err = s.Pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM oauth.sessions WHERE session_hash=$1 AND user_id=$2 AND expires_at>now())`, hashToken(cookie.Value), userID).Scan(&ok)
	return err == nil && ok
}
func hashTokenCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return hashToken(c.Value)
}

func (s *Server) sign(p signedRequest) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, s.SigningKey)
	_, _ = mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func (s *Server) verify(token string) (signedRequest, error) {
	var p signedRequest
	parts := strings.Split(token, ".")
	if len(parts) != 2 || len(s.SigningKey) < 32 {
		return p, errors.New("invalid signed request")
	}
	mac := hmac.New(sha256.New, s.SigningKey)
	_, _ = mac.Write([]byte(parts[0]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return p, errors.New("invalid signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	if time.Now().Unix() > p.Expires || p.ClientID == "" || p.RedirectURI == "" || p.Resource != s.Resource {
		return p, errors.New("expired or mismatched request")
	}
	return p, nil
}

func (s *Server) audit(ctx context.Context, event, outcome, userID, clientID string, details map[string]any) {
	raw, err := json.Marshal(details)
	if err != nil {
		raw = []byte("{}")
	}
	_, _ = s.Pool.Exec(ctx, `INSERT INTO oauth.audit_log(event_type,outcome,user_id,client_id,details) VALUES($1,$2,NULLIF($3,'')::uuid,NULLIF($4,''),$5::jsonb)`, event, outcome, userID, clientID, string(raw))
}
func (s *Server) allowRate(key string, limit int, window time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	entry := s.rates[key]
	if entry.Start.IsZero() || now.Sub(entry.Start) >= window {
		entry = rateWindow{Start: now, Count: 0}
	}
	if entry.Count >= limit {
		s.rates[key] = entry
		return false
	}
	entry.Count++
	s.rates[key] = entry
	return true
}
func (s *Server) resetRate(key string) { s.mu.Lock(); delete(s.rates, key); s.mu.Unlock() }
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
			if net.ParseIP(forwarded) != nil {
				return forwarded
			}
		}
	}
	return host
}

func writeToken(w http.ResponseWriter, p tokenPair, scopes []string) {
	writeJSON(w, http.StatusOK, map[string]any{"access_token": p.Access, "token_type": "Bearer", "expires_in": p.Expires, "refresh_token": p.Refresh, "scope": strings.Join(scopes, " ")})
}
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func hashToken(v string) string      { sum := sha256.Sum256([]byte(v)); return hex.EncodeToString(sum[:]) }
func constantEqual(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }
func scopeSubset(requested, allowed []string) bool {
	if len(requested) == 0 {
		return false
	}
	m := map[string]bool{}
	for _, s := range allowed {
		m[s] = true
	}
	for _, s := range requested {
		if !m[s] {
			return false
		}
	}
	return true
}
func redirectWithError(w http.ResponseWriter, redirectURI, code, state, issuer string) {
	target := appendQuery(redirectURI, map[string]string{"error": code, "state": state, "iss": issuer})
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}
func appendQuery(raw string, values map[string]string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for k, v := range values {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func oauthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}
func htmlPage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><html lang='zh-CN'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>%s</title><body style='font:16px system-ui;max-width:560px;margin:48px auto;padding:0 20px'><h1>%s</h1>%s</body></html>", html.EscapeString(title), html.EscapeString(title), body)
}
func loginForm(request, csrf, message string) string {
	return fmt.Sprintf("<p>%s</p><form method='post'><input type='hidden' name='request' value='%s'><input type='hidden' name='login_csrf' value='%s'><label>用户名<br><input name='username' required autocomplete='username' style='width:100%%;padding:10px'></label><br><br><label>密码<br><input type='password' name='password' required autocomplete='current-password' style='width:100%%;padding:10px'></label><br><br><button type='submit'>登录并继续</button></form>", html.EscapeString(message), html.EscapeString(request), html.EscapeString(csrf))
}
func consentForm(request, csrf, client, scopes string) string {
	return fmt.Sprintf("<p><strong>%s</strong> 请求访问此主机的 MCP 工具。</p><p>权限范围：<code>%s</code></p><p>该授权允许执行已注册的主机操作。请仅批准可信客户端。</p><form method='post'><input type='hidden' name='request' value='%s'><input type='hidden' name='csrf_token' value='%s'><button name='decision' value='approve'>批准授权</button> <button name='decision' value='deny'>拒绝</button></form>", client, scopes, html.EscapeString(request), html.EscapeString(csrf))
}

var _ = pgx.ErrNoRows
