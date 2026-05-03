// Package api implements the relay's public and operator HTTP API.
package api

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type authSource int

const (
	authSourceHeader authSource = iota
	authSourceBasic
	authSourceQuery
)

func verifyBearer(r *http.Request, hash string) (bool, authSource) {
	secret, source := tunnelSecret(r)
	if secret == "" {
		return false, source
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)) != nil {
		return false, source
	}
	return true, source
}

func tunnelSecret(r *http.Request) (string, authSource) {
	if header := strings.TrimSpace(r.Header.Get("X-Tunnel-Auth")); header != "" {
		return header, authSourceHeader
	}
	if user, _, hasBasic := r.BasicAuth(); hasBasic && user != "" {
		return user, authSourceBasic
	}
	if raw := r.URL.Query().Get("x-tunnel-auth"); raw != "" {
		tier1, _, found := strings.Cut(raw, ":")
		if found {
			return tier1, authSourceQuery
		}
	}
	return "", authSourceHeader
}
