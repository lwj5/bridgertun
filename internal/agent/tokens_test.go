package agent

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestNewSessionTokensGeneratesDistinctSecretsAndMatchingHash(t *testing.T) {
	t.Parallel()

	tokens, err := newSessionTokens(bcrypt.MinCost)
	if err != nil {
		t.Fatalf("newSessionTokens() error = %v", err)
	}
	if tokens.RelayToken == "" || tokens.AgentToken == "" || tokens.RelayTokenHash == "" {
		t.Fatal("expected all token fields to be populated")
	}
	if tokens.RelayToken == tokens.AgentToken {
		t.Fatal("relay and agent tokens should differ")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(tokens.RelayTokenHash), []byte(tokens.RelayToken)); err != nil {
		t.Fatalf("relay token hash does not match relay token: %v", err)
	}
}

func TestRandomTokenUsesRawURLEncoding(t *testing.T) {
	t.Parallel()

	token, err := randomToken()
	if err != nil {
		t.Fatalf("randomToken() error = %v", err)
	}
	if strings.Contains(token, "=") {
		t.Fatalf("token %q contains padding", token)
	}
	if len(token) != 43 {
		t.Fatalf("len(token) = %d, want 43", len(token))
	}
}
