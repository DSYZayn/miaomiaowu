package handler

import "testing"

func TestSignAndVerifyOIDCStatePayload(t *testing.T) {
	secret := "test-secret"
	input := oidcStatePayload{
		State:        "state",
		Nonce:        "nonce",
		CodeVerifier: "verifier",
		ExpiresAt:    12345,
	}

	signed, err := signOIDCStatePayload(input, secret)
	if err != nil {
		t.Fatalf("sign payload: %v", err)
	}

	got, err := verifyOIDCStatePayload(signed, secret)
	if err != nil {
		t.Fatalf("verify payload: %v", err)
	}
	if got.State != input.State || got.Nonce != input.Nonce || got.CodeVerifier != input.CodeVerifier {
		t.Fatalf("payload mismatch: %#v", got)
	}

	if _, err := verifyOIDCStatePayload(signed+"x", secret); err == nil {
		t.Fatalf("expected tampered payload to fail")
	}
}

func TestAllowUser(t *testing.T) {
	h := &OIDCAuthHandler{
		cfg: oidcConfig{
			AllowedUsers:        map[string]struct{}{"alice@example.com": {}},
			AllowedEmailDomains: map[string]struct{}{"example.com": {}},
		},
	}

	if !h.allowUser(oidcClaims{Email: "alice@example.com"}) {
		t.Fatalf("expected user to be allowed")
	}
	if h.allowUser(oidcClaims{Email: "bob@example.com"}) {
		t.Fatalf("expected user to be denied by allowed users")
	}
}

func TestResolveOIDCUsernameStable(t *testing.T) {
	a := resolveOIDCUsername(oidcClaims{Subject: "sub-1"})
	b := resolveOIDCUsername(oidcClaims{Subject: "sub-1"})
	c := resolveOIDCUsername(oidcClaims{Subject: "sub-2"})
	if a != b {
		t.Fatalf("expected stable username")
	}
	if a == c {
		t.Fatalf("expected different subject to yield different username")
	}
}
