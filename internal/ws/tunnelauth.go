package ws

import (
	"errors"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// ParseTunnelAuth extracts the bcrypt hash from X-Tunnel-Secret-Hash and
// validates its format. Returns the hash string on success.
func ParseTunnelAuth(h http.Header) (string, error) {
	hash := strings.TrimSpace(h.Get("X-Tunnel-Secret-Hash"))
	if hash == "" {
		return "", errors.New("X-Tunnel-Secret-Hash header is required")
	}
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return "", errors.New("X-Tunnel-Secret-Hash: not a valid bcrypt hash")
	}
	return hash, nil
}
