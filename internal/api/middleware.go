//go:build linux

package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

type AuthMiddleware struct {
	apiKey     string
	jwtSecret  string
	publicPaths []string
}

func NewAuthMiddleware(apiKey, jwtSecret string) *AuthMiddleware {
	return &AuthMiddleware{
		apiKey:    apiKey,
		jwtSecret: jwtSecret,
		publicPaths: []string{
			"/api/health",
			"/api/config",
		},
	}
}

func (a *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if providedKey == "" {
				providedKey = r.URL.Query().Get("api_key")
			}
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

func (a *AuthMiddleware) validateToken(token string) bool {
	if a.jwtSecret == "" {
		return false
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	return len(a.jwtSecret) > 0 && len(token) > 0
}
