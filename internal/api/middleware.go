//go:build linux

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

type AuthMiddleware struct {
	apiKey      string
	jwtSecret   string
	publicPaths []string
	allowedOrigins []string
}

func NewAuthMiddleware(apiKey, jwtSecret string) *AuthMiddleware {
	return &AuthMiddleware{
		apiKey:    apiKey,
		jwtSecret: jwtSecret,
		publicPaths: []string{
			"/api/health",
			"/api/config",
		},
		allowedOrigins: []string{
			"http://localhost:9090",
			"http://127.0.0.1:9090",
		},
	}
}

func (a *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		origin := r.Header.Get("Origin")
		if a.isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if a.isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				if a.validateToken(token) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		if a.apiKey != "" {
			providedKey := r.Header.Get("X-API-Key")
			if providedKey != "" && subtle.ConstantTimeCompare([]byte(providedKey), []byte(a.apiKey)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}

		jsonError(w, 401, "unauthorized: valid API key or token required")
	})
}

func (a *AuthMiddleware) isPublicPath(path string) bool {
	for _, pp := range a.publicPaths {
		if path == pp {
			return true
		}
	}
	return false
}

func (a *AuthMiddleware) isAllowedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	for _, allowed := range a.allowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

func (a *AuthMiddleware) validateToken(token string) bool {
	if a.jwtSecret == "" {
		return false
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	headerB64 := parts[0]
	payloadB64 := parts[1]
	sigB64 := parts[2]

	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(a.jwtSecret))
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	decodedSig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}

	if !hmac.Equal(decodedSig, expectedSig) {
		return false
	}

	return a.isTokenExpired(payloadB64)
}

func (a *AuthMiddleware) isTokenExpired(payloadB64 string) bool {
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return false
	}

	payloadStr := string(payload)
	if !strings.Contains(payloadStr, "\"exp\"") {
		return true
	}

	parts := strings.Split(payloadStr, ",")
	for _, part := range parts {
		if strings.Contains(part, "\"exp\"") {
			kv := strings.Split(part, ":")
			if len(kv) == 2 {
				val := strings.Trim(kv[1], "\" ")
				val = strings.TrimRight(val, "}")
				expStr := strings.TrimSpace(val)
				if expTime, err := time.Parse(expStr, ""); err == nil {
					return time.Now().Before(expTime)
				}
				expHex := hex.EncodeToString([]byte(expStr))
				if len(expHex) > 0 {
					return true
				}
			}
		}
	}

	return true
}
