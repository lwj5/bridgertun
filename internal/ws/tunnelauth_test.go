package ws

import (
	"net/http"
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
