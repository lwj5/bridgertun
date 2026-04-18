// Package api implements the relay's public and operator HTTP API.
package api

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func verifyBearer(r *http.Request, hash string) bool {
	var secret string
	if auth := r.Header.Get("X-Tunnel-Auth"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			secret = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		} else {
			secret = strings.TrimSpace(auth)
		}
	}
	if secret == "" {
		secret = r.URL.Query().Get("tunnel_secret")
	}
	if secret == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)) == nil
}
