package handler

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"miaomiaowu/internal/auth"
)

func setAuthCookies(w http.ResponseWriter, r *http.Request, token string, expiry time.Time) {
	if w == nil || strings.TrimSpace(token) == "" {
		return
	}

	secure := isSecureCookieRequest(r)
	maxAge := int(time.Until(expiry).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}

	http.SetCookie(w, &http.Cookie{
		Name:     getSessionCookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		Expires:  expiry,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     auth.LegacyTokenCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		Expires:  expiry,
	})
}

func clearAuthCookies(w http.ResponseWriter, r *http.Request) {
	if w == nil {
		return
	}
	secure := isSecureCookieRequest(r)
	cookies := []string{getSessionCookieName(), auth.LegacyTokenCookieName}
	for _, name := range cookies {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: name != auth.LegacyTokenCookieName,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
		})
	}
}

func getSessionCookieName() string {
	if value := strings.TrimSpace(os.Getenv("SESSION_COOKIE_NAME")); value != "" {
		return value
	}
	return auth.DefaultSessionCookieName
}

func isSecureCookieRequest(r *http.Request) bool {
	if enabled, ok := parseBoolEnv("COOKIE_SECURE"); ok {
		return enabled
	}
	if r != nil && r.TLS != nil {
		return true
	}
	if !envBool("TRUST_PROXY_HEADERS") || r == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func envBool(name string) bool {
	value, _ := parseBoolEnv(name)
	return value
}

func parseBoolEnv(name string) (bool, bool) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return false, false
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, false
	}
	return parsed, true
}
