package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func mustTunnelHash(t *testing.T, secret string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword() error = %v", err)
	}
	return string(hash)
}

func TestVerifyBearerAcceptsAuthorizationHeader(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Tunnel-Auth", "Bearer relay-secret")

	if !verifyBearer(request, mustTunnelHash(t, "relay-secret")) {
		t.Fatal("verifyBearer() = false, want true")
	}
}

func TestVerifyBearerFallsBackToQuerySecret(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/?tunnel_secret=relay-secret", nil)

	if !verifyBearer(request, mustTunnelHash(t, "relay-secret")) {
		t.Fatal("verifyBearer() = false, want true")
	}
}

func TestVerifyBearerRejectsWrongSecret(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Tunnel-Auth", "wrong-secret")

	if verifyBearer(request, mustTunnelHash(t, "relay-secret")) {
		t.Fatal("verifyBearer() = true, want false")
	}
}
