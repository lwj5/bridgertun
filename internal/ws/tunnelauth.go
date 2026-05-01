package ws

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// maxBcryptCost is the highest bcrypt work factor the relay will accept from
// an agent. Every proxied request re-runs bcrypt verification, so an
// uncapped cost turns authentication into a CPU amplification vector.
// Cost 14 is ~1.6 s on modern hardware — well above what real agents need
// (the reference agent uses cost 10) while blocking malicious high-cost hashes.
const maxBcryptCost = 14

// ParseTunnelAuth extracts the bcrypt hash from X-Tunnel-Secret-Hash and
// validates its format. Returns the hash string on success.
func ParseTunnelAuth(h http.Header) (string, error) {
	hash := strings.TrimSpace(h.Get("X-Tunnel-Secret-Hash"))
	if hash == "" {
		return "", errors.New("X-Tunnel-Secret-Hash header is required")
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return "", errors.New("X-Tunnel-Secret-Hash: not a valid bcrypt hash")
	}
	if cost > maxBcryptCost {
		return "", fmt.Errorf("X-Tunnel-Secret-Hash: bcrypt cost %d exceeds maximum of %d", cost, maxBcryptCost)
	}
	return hash, nil
}
