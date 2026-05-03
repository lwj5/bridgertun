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
	request.Header.Set("X-Tunnel-Auth", "relay-secret")

	ok, source := verifyBearer(request, mustTunnelHash(t, "relay-secret"))
	if !ok {
		t.Fatal("verifyBearer() ok = false, want true")
	}
	if source != authSourceHeader {
		t.Fatalf("verifyBearer() source = %v, want authSourceHeader", source)
	}
}

func TestVerifyBearerFallsBackToQuerySecret(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/?x-tunnel-auth=relay-secret:agent-token", nil)

	ok, source := verifyBearer(request, mustTunnelHash(t, "relay-secret"))
	if !ok {
		t.Fatal("verifyBearer() ok = false, want true")
	}
	if source != authSourceQuery {
		t.Fatalf("verifyBearer() source = %v, want authSourceQuery", source)
	}
}

func TestVerifyBearerRejectsWrongSecret(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Tunnel-Auth", "wrong-secret")

	if ok, _ := verifyBearer(request, mustTunnelHash(t, "relay-secret")); ok {
		t.Fatal("verifyBearer() ok = true, want false")
	}
}

func TestVerifyBearerAcceptsBasicAuthUsername(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.SetBasicAuth("relay-secret", "agent-token-ignored-here")

	ok, source := verifyBearer(request, mustTunnelHash(t, "relay-secret"))
	if !ok {
		t.Fatal("verifyBearer() ok = false, want true")
	}
	if source != authSourceBasic {
		t.Fatalf("verifyBearer() source = %v, want authSourceBasic", source)
	}
}

func TestVerifyBearerHeaderTakesPrecedenceOverBasic(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Tunnel-Auth", "relay-secret")
	request.SetBasicAuth("some-other-username", "agent-token")

	ok, source := verifyBearer(request, mustTunnelHash(t, "relay-secret"))
	if !ok {
		t.Fatal("verifyBearer() ok = false, want true")
	}
	if source != authSourceHeader {
		t.Fatalf("verifyBearer() source = %v, want authSourceHeader when header present", source)
	}
}

func TestVerifyBearerBasicTakesPrecedenceOverQuery(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/?x-tunnel-auth=relay-secret", nil)
	request.SetBasicAuth("wrong-basic-username", "agent-token")

	// Basic is non-empty but does not match the hash; per priority semantics
	// we must NOT fall through to query.
	if ok, _ := verifyBearer(request, mustTunnelHash(t, "relay-secret")); ok {
		t.Fatal("verifyBearer() ok = true; expected Basic to win and fail without falling back to query")
	}
}

func TestVerifyBearerRejectsWrongBasicUsername(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.SetBasicAuth("not-the-secret", "")

	if ok, _ := verifyBearer(request, mustTunnelHash(t, "relay-secret")); ok {
		t.Fatal("verifyBearer() ok = true, want false for wrong Basic username")
	}
}
