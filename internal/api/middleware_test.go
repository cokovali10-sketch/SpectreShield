//go:build linux

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func generateTestToken(secret string, payload map[string]interface{}) string {
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return headerB64 + "." + payloadB64 + "." + sigB64
}

func TestValidToken(t *testing.T) {
	secret := "test-secret-key-12345"
	auth := NewAuthMiddleware("", secret)

	token := generateTestToken(secret, map[string]interface{}{
		"sub": "user1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	if !auth.validateToken(token) {
		t.Error("expected valid token to pass validation")
	}
}

func TestInvalidSignature(t *testing.T) {
	secret := "test-secret-key-12345"
	wrongSecret := "wrong-secret-key"
	auth := NewAuthMiddleware("", secret)

	token := generateTestToken(wrongSecret, map[string]interface{}{
		"sub": "user1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	if auth.validateToken(token) {
		t.Error("expected token with wrong signature to fail validation")
	}
}

func TestExpiredToken(t *testing.T) {
	secret := "test-secret-key-12345"
	auth := NewAuthMiddleware("", secret)

	token := generateTestToken(secret, map[string]interface{}{
		"sub": "user1",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	if auth.validateToken(token) {
		t.Error("expected expired token to fail validation")
	}
}

func TestTokenWithoutExpiry(t *testing.T) {
	secret := "test-secret-key-12345"
	auth := NewAuthMiddleware("", secret)

	token := generateTestToken(secret, map[string]interface{}{
		"sub": "user1",
	})

	if !auth.validateToken(token) {
		t.Error("expected token without expiry to pass validation (no expiry = never expires)")
	}
}

func TestMalformedToken(t *testing.T) {
	secret := "test-secret-key-12345"
	auth := NewAuthMiddleware("", secret)

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dots", "abc123"},
		{"one dot", "abc.123"},
		{"two dots only", "abc.123."},
		{"four dots", "abc.123.456.789"},
		{"garbage", "not-a-jwt-token-at-all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if auth.validateToken(tt.token) {
				t.Errorf("expected malformed token to fail validation: %s", tt.name)
			}
		})
	}
}

func TestEmptySecret(t *testing.T) {
	auth := NewAuthMiddleware("", "")

	token := generateTestToken("any-secret", map[string]interface{}{
		"sub": "user1",
	})

	if auth.validateToken(token) {
		t.Error("expected token validation to fail with empty secret")
	}
}

func TestAlgorithmConfusion(t *testing.T) {
	secret := "test-secret-key-12345"
	auth := NewAuthMiddleware("", secret)

	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user1"}`))

	token := noneHeader + "." + payload + "."
	if auth.validateToken(token) {
		t.Error("expected 'none' algorithm token to fail validation")
	}
}

func TestKeyTooShort(t *testing.T) {
	shortSecret := "a"
	auth := NewAuthMiddleware("", shortSecret)

	token := generateTestToken(shortSecret, map[string]interface{}{
		"sub": "user1",
	})

	if !auth.validateToken(token) {
		t.Error("expected token with short secret to still validate (HMAC accepts any key length)")
	}
}

func TestTokenReplay(t *testing.T) {
	secret := "test-secret-key-12345"
	auth := NewAuthMiddleware("", secret)

	token := generateTestToken(secret, map[string]interface{}{
		"sub": "user1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	for i := 0; i < 5; i++ {
		if !auth.validateToken(token) {
			t.Errorf("expected token to validate on attempt %d (replay should work without nonce)", i)
		}
	}
}

func TestPublicPathsBypassAuth(t *testing.T) {
	auth := NewAuthMiddleware("", "secret")

	publicPaths := []string{"/api/health", "/api/config"}
	for _, path := range publicPaths {
		if !auth.isPublicPath(path) {
			t.Errorf("expected %s to be a public path", path)
		}
	}

	privatePaths := []string{"/api/threats", "/api/scan", "/api/quarantine"}
	for _, path := range privatePaths {
		if auth.isPublicPath(path) {
			t.Errorf("expected %s to NOT be a public path", path)
		}
	}
}

func TestAPIKeyValidation(t *testing.T) {
	auth := NewAuthMiddleware("test-api-key-12345", "")

	if !auth.validateAPIKey("test-api-key-12345") {
		t.Error("expected valid API key to pass")
	}

	if auth.validateAPIKey("wrong-key") {
		t.Error("expected wrong API key to fail")
	}

	if auth.validateAPIKey("") {
		t.Error("expected empty API key to fail")
	}
}

func TestAPIKeyWithoutDB(t *testing.T) {
	auth := NewAuthMiddleware("test-key", "")

	if auth.validateAPIKey("test-key") {
		t.Error("expected API key validation to fail without DB (security: don't accept keys without verification)")
	}
}

func TestBase64Padding(t *testing.T) {
	secret := "test-secret"
	auth := NewAuthMiddleware("", secret)

	token := generateTestToken(secret, map[string]interface{}{
		"sub": "user1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	if !auth.validateToken(token) {
		t.Error("expected token with proper base64 padding to validate")
	}
}
