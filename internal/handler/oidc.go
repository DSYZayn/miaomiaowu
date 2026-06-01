package handler

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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"miaomiaowu/internal/auth"
	"miaomiaowu/internal/logger"
	"miaomiaowu/internal/storage"
)

const oidcStateCookieName = "oidc_auth_state"

type oidcConfig struct {
	IssuerURL           string
	ClientID            string
	ClientSecret        string
	RedirectURL         string
	Scopes              []string
	SessionSecret       string
	AllowedEmailDomains map[string]struct{}
	AllowedUsers        map[string]struct{}
	PostLoginRedirect   string
	AllowInsecureHTTP   bool
}

func loadOIDCConfigFromEnv() oidcConfig {
	cfg := oidcConfig{
		IssuerURL:         strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL")),
		ClientID:          strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
		ClientSecret:      strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET")),
		RedirectURL:       strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URL")),
		SessionSecret:     strings.TrimSpace(os.Getenv("OIDC_SESSION_SECRET")),
		PostLoginRedirect: strings.TrimSpace(os.Getenv("OIDC_POST_LOGIN_REDIRECT")),
		AllowInsecureHTTP: envBool("OIDC_ALLOW_INSECURE_HTTP"),
	}
	if cfg.PostLoginRedirect == "" {
		cfg.PostLoginRedirect = "/"
	}

	rawScopes := strings.TrimSpace(os.Getenv("OIDC_SCOPES"))
	if rawScopes == "" {
		rawScopes = "openid profile email"
	}
	cfg.Scopes = strings.Fields(strings.ReplaceAll(rawScopes, ",", " "))
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}

	cfg.AllowedEmailDomains = parseCSVSet(os.Getenv("ALLOWED_EMAIL_DOMAINS"))
	cfg.AllowedUsers = parseCSVSet(os.Getenv("ALLOWED_USERS"))
	return cfg
}

func (c oidcConfig) Enabled() bool {
	return c.IssuerURL != "" && c.ClientID != "" && c.RedirectURL != "" && c.SessionSecret != ""
}

func parseCSVSet(raw string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		item := strings.ToLower(strings.TrimSpace(part))
		if item != "" {
			set[item] = struct{}{}
		}
	}
	return set
}

type oidcStatePayload struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	ExpiresAt    int64  `json:"expires_at"`
}

type oidcClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Picture           string `json:"picture"`
	Nonce             string `json:"nonce"`
}

type OIDCAuthHandler struct {
	repo      *storage.TrafficRepository
	tokens    *auth.TokenStore
	cfg       oidcConfig
	oauth2Cfg *oauth2.Config
	verifier  *oidc.IDTokenVerifier
}

func NewOIDCAuthHandler(repo *storage.TrafficRepository, tokens *auth.TokenStore) *OIDCAuthHandler {
	return &OIDCAuthHandler{
		repo:   repo,
		tokens: tokens,
		cfg:    loadOIDCConfigFromEnv(),
	}
}

func (h *OIDCAuthHandler) Enabled() bool {
	return h != nil && h.cfg.Enabled()
}

func (h *OIDCAuthHandler) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.ensureReady(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		if err := h.requireSecureRequest(r); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		payload := oidcStatePayload{
			State:        mustRandomString(32),
			Nonce:        mustRandomString(32),
			CodeVerifier: mustRandomString(64),
			ExpiresAt:    time.Now().Add(5 * time.Minute).Unix(),
		}
		signed, err := signOIDCStatePayload(payload, h.cfg.SessionSecret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     oidcStateCookieName,
			Value:    signed,
			Path:     "/auth/callback",
			HttpOnly: true,
			Secure:   isSecureCookieRequest(r),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   300,
		})

		challenge := pkceChallenge(payload.CodeVerifier)
		authURL := h.oauth2Cfg.AuthCodeURL(
			payload.State,
			oidc.Nonce(payload.Nonce),
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

func (h *OIDCAuthHandler) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.ensureReady(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		if err := h.requireSecureRequest(r); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if gotErr := strings.TrimSpace(r.URL.Query().Get("error")); gotErr != "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("oidc authorize failed: %s", gotErr))
			return
		}

		code := strings.TrimSpace(r.URL.Query().Get("code"))
		state := strings.TrimSpace(r.URL.Query().Get("state"))
		if code == "" || state == "" {
			writeError(w, http.StatusBadRequest, errors.New("missing code or state"))
			return
		}

		cookie, err := r.Cookie(oidcStateCookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errors.New("oidc state cookie not found"))
			return
		}
		payload, err := verifyOIDCStatePayload(cookie.Value, h.cfg.SessionSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}
		if payload.ExpiresAt < time.Now().Unix() {
			writeError(w, http.StatusUnauthorized, errors.New("oidc state expired"))
			return
		}
		if payload.State != state {
			writeError(w, http.StatusUnauthorized, errors.New("oidc state mismatch"))
			return
		}
		clearOIDCStateCookie(w, r)

		token, err := h.oauth2Cfg.Exchange(r.Context(), code, oauth2.SetAuthURLParam("code_verifier", payload.CodeVerifier))
		if err != nil {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("oidc token exchange failed: %w", err))
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok || strings.TrimSpace(rawIDToken) == "" {
			writeError(w, http.StatusUnauthorized, errors.New("id_token not found"))
			return
		}

		idToken, err := h.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("verify id_token failed: %w", err))
			return
		}

		var claims oidcClaims
		if err := idToken.Claims(&claims); err != nil {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("decode id_token claims failed: %w", err))
			return
		}
		if claims.Nonce != payload.Nonce {
			writeError(w, http.StatusUnauthorized, errors.New("oidc nonce mismatch"))
			return
		}
		if !h.allowUser(claims) {
			writeError(w, http.StatusForbidden, errors.New("user is not allowed"))
			return
		}

		user, err := h.ensureLocalUser(r.Context(), claims)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !user.IsActive {
			writeError(w, http.StatusForbidden, errors.New("user is disabled"))
			return
		}
		if _, err := h.repo.GetOrCreateUserToken(r.Context(), user.Username); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		sessionToken, expiry, err := h.tokens.IssueWithTTL(user.Username, 24*time.Hour)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if err := h.repo.CreateSession(r.Context(), sessionToken, user.Username, expiry); err != nil {
			logger.Warn("[OIDC] 会话持久化失败", "username", user.Username, "error", err)
		}
		setAuthCookies(w, r, sessionToken, expiry)
		http.Redirect(w, r, h.cfg.PostLoginRedirect, http.StatusFound)
	})
}

func (h *OIDCAuthHandler) LogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("only GET/POST are supported"))
			return
		}

		token := strings.TrimSpace(r.Header.Get(auth.AuthHeader))
		if token == "" {
			token = strings.TrimSpace(r.URL.Query().Get("token"))
		}
		if token == "" {
			if c, err := r.Cookie(getSessionCookieName()); err == nil {
				token = strings.TrimSpace(c.Value)
			}
		}
		if token != "" {
			h.tokens.Revoke(token)
			_ = h.repo.DeleteSession(r.Context(), token)
		}

		clearAuthCookies(w, r)
		clearOIDCStateCookie(w, r)

		if r.Method == http.MethodPost || strings.Contains(r.Header.Get("Accept"), "application/json") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}

func (h *OIDCAuthHandler) StatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"oidc_enabled": h.Enabled()})
	})
}

func (h *OIDCAuthHandler) ensureReady(ctx context.Context) error {
	if h == nil || h.repo == nil || h.tokens == nil {
		return errors.New("oidc handler not initialized")
	}
	if !h.cfg.Enabled() {
		return errors.New("oidc is not configured")
	}
	if h.oauth2Cfg != nil && h.verifier != nil {
		return nil
	}
	provider, err := oidc.NewProvider(ctx, h.cfg.IssuerURL)
	if err != nil {
		return fmt.Errorf("init oidc provider: %w", err)
	}
	h.oauth2Cfg = &oauth2.Config{
		ClientID:     h.cfg.ClientID,
		ClientSecret: h.cfg.ClientSecret,
		RedirectURL:  h.cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       h.cfg.Scopes,
	}
	h.verifier = provider.Verifier(&oidc.Config{ClientID: h.cfg.ClientID})
	return nil
}

func (h *OIDCAuthHandler) requireSecureRequest(r *http.Request) error {
	if h == nil || h.cfg.AllowInsecureHTTP || !h.cfg.Enabled() {
		return nil
	}
	if isSecureCookieRequest(r) {
		return nil
	}
	return errors.New("oidc requires https. set TRUST_PROXY_HEADERS=true behind reverse proxy")
}

func (h *OIDCAuthHandler) allowUser(c oidcClaims) bool {
	if len(h.cfg.AllowedUsers) > 0 {
		candidates := []string{c.Email, c.PreferredUsername, c.Subject}
		allowed := false
		for _, item := range candidates {
			if _, ok := h.cfg.AllowedUsers[strings.ToLower(strings.TrimSpace(item))]; ok {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	if len(h.cfg.AllowedEmailDomains) > 0 {
		email := strings.ToLower(strings.TrimSpace(c.Email))
		at := strings.LastIndex(email, "@")
		if at <= 0 || at >= len(email)-1 {
			return false
		}
		domain := email[at+1:]
		if _, ok := h.cfg.AllowedEmailDomains[domain]; !ok {
			return false
		}
	}
	return true
}

func (h *OIDCAuthHandler) ensureLocalUser(ctx context.Context, claims oidcClaims) (storage.User, error) {
	username := resolveOIDCUsername(claims)
	user, err := h.repo.GetUser(ctx, username)
	if err != nil {
		if !errors.Is(err, storage.ErrUserNotFound) {
			return storage.User{}, err
		}
		password := mustRandomString(32)
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if hashErr != nil {
			return storage.User{}, hashErr
		}
		nickname := strings.TrimSpace(claims.Name)
		if nickname == "" {
			nickname = username
		}
		if createErr := h.repo.CreateUser(ctx, username, strings.TrimSpace(claims.Email), nickname, string(hash), storage.RoleUser, "oidc user"); createErr != nil {
			return storage.User{}, createErr
		}
		user, err = h.repo.GetUser(ctx, username)
		if err != nil {
			return storage.User{}, err
		}
	}

	update := storage.UserProfileUpdate{
		Email:     strings.TrimSpace(claims.Email),
		Nickname:  strings.TrimSpace(claims.Name),
		AvatarURL: strings.TrimSpace(claims.Picture),
	}
	if update.Nickname == "" {
		update.Nickname = user.Nickname
	}
	if update.Email != user.Email || update.Nickname != user.Nickname || update.AvatarURL != user.AvatarURL {
		_ = h.repo.UpdateUserProfile(ctx, username, update)
		user, _ = h.repo.GetUser(ctx, username)
	}
	return user, nil
}

func resolveOIDCUsername(c oidcClaims) string {
	seed := strings.TrimSpace(c.Subject)
	if seed == "" {
		seed = strings.TrimSpace(c.Email)
	}
	if seed == "" {
		seed = strings.TrimSpace(c.PreferredUsername)
	}
	sum := sha256.Sum256([]byte(seed))
	return "oidc_" + hex.EncodeToString(sum[:8])
}

func signOIDCStatePayload(payload oidcStatePayload, secret string) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(raw)
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifyOIDCStatePayload(value, secret string) (oidcStatePayload, error) {
	var payload oidcStatePayload
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 2 {
		return payload, errors.New("invalid oidc state cookie")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return payload, errors.New("invalid oidc state payload")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return payload, errors.New("invalid oidc state signature")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(raw)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return payload, errors.New("invalid oidc state signature")
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, errors.New("invalid oidc state content")
	}
	return payload, nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func mustRandomString(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func clearOIDCStateCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/auth/callback",
		HttpOnly: true,
		Secure:   isSecureCookieRequest(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}
