package ws

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func mustHash(t *testing.T, secret string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

// spoofBcryptCost replaces the cost field in an existing bcrypt hash string so
// bcrypt.Cost() returns the desired value without re-deriving the hash.
// ParseTunnelAuth only calls bcrypt.Cost(), so this is sufficient for testing
// cost-limit logic without paying the actual work-factor cost.
func spoofBcryptCost(t *testing.T, hash string, cost int) string {
	t.Helper()
	// bcrypt format: $2a$NN$<rest>  — split into ["", "2a", "NN", "<rest>"]
	parts := strings.SplitN(hash, "$", 4)
	if len(parts) != 4 {
		t.Fatalf("unexpected bcrypt format: %q", hash)
	}
	parts[2] = fmt.Sprintf("%02d", cost)
	return strings.Join(parts, "$")
}

func TestParseTunnelAuth_BearerHash(t *testing.T) {
	hash := mustHash(t, "supersecret")
	got, err := ParseTunnelAuth(http.Header{"X-Tunnel-Secret-Hash": {hash}})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != hash {
		t.Fatalf("hash mismatch")
	}
}

func TestParseTunnelAuth_RejectsInvalidHash(t *testing.T) {
	h := http.Header{"X-Tunnel-Secret-Hash": {"not-a-bcrypt-hash"}}
	if _, err := ParseTunnelAuth(h); err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestParseTunnelAuth_MissingHashRejected(t *testing.T) {
	_, err := ParseTunnelAuth(http.Header{})
	if err == nil {
		t.Fatal("expected error for missing X-Tunnel-Secret-Hash, got nil")
	}
}

func TestParseTunnelAuth_RejectsExcessiveCost(t *testing.T) {
	t.Parallel()
	// Spoof cost to maxBcryptCost+1 so we don't pay the actual work-factor.
	hash := spoofBcryptCost(t, mustHash(t, "secret"), maxBcryptCost+1)
	_, err := ParseTunnelAuth(http.Header{"X-Tunnel-Secret-Hash": {hash}})
	if err == nil {
		t.Fatalf("expected error for cost > %d, got nil", maxBcryptCost)
	}
}

func TestParseTunnelAuth_AcceptsMaxCost(t *testing.T) {
	t.Parallel()
	// Spoof cost to exactly maxBcryptCost — should be accepted.
	hash := spoofBcryptCost(t, mustHash(t, "secret"), maxBcryptCost)
	got, err := ParseTunnelAuth(http.Header{"X-Tunnel-Secret-Hash": {hash}})
	if err != nil {
		t.Fatalf("unexpected error at cost %d: %v", maxBcryptCost, err)
	}
	if got != hash {
		t.Fatalf("returned hash mismatch")
	}
}
