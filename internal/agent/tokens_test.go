package agent

import (
	"net/url"
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

func TestFormatOperatorBlockIncludesExamples(t *testing.T) {
	t.Parallel()

	tokens := &sessionTokens{
		RelayToken: testRelayToken,
		AgentToken: testAgentToken,
	}

	got := formatOperatorBlock("session-123", "https://relay.example.com/v1/tunnel/session-123/", tokens)

	checks := []string{
		"session      : session-123",
		"tunnel       : https://relay.example.com/v1/tunnel/session-123/",
		"relay token  : relay-token",
		"agent token  : agent-token",
		"example url  : https://relay.example.com/v1/tunnel/session-123/?x-tunnel-auth=relay-token%3Aagent-token",
		"example headers:",
		"X-Tunnel-Auth: relay-token",
		"X-Tunnel-Agent-Auth: agent-token",
	}

	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Fatalf("formatOperatorBlock() missing %q in output %q", want, got)
		}
	}
}

func TestTunnelURLWithCredentialsPreservesExistingQuery(t *testing.T) {
	t.Parallel()

	tokens := &sessionTokens{
		RelayToken: testRelayToken,
		AgentToken: testAgentToken,
	}

	got := tunnelURLWithCredentials("https://relay.example.com/v1/tunnel/session-123/events?stream=1", tokens)
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", got, err)
	}

	query := parsed.Query()
	if query.Get("stream") != "1" {
		t.Fatalf("stream query = %q, want 1", query.Get("stream"))
	}
	if got, want := query.Get("x-tunnel-auth"), testRelayToken+":"+testAgentToken; got != want {
		t.Fatalf("x-tunnel-auth = %q, want %q", got, want)
	}
}

func TestExampleHeaders(t *testing.T) {
	t.Parallel()

	headers := exampleHeaders(&sessionTokens{RelayToken: testRelayToken, AgentToken: testAgentToken})
	if got := headers.Get("X-Tunnel-Auth"); got != testRelayToken {
		t.Fatalf("X-Tunnel-Auth = %q, want relay-token", got)
	}
	if got := headers.Get("X-Tunnel-Agent-Auth"); got != testAgentToken {
		t.Fatalf("X-Tunnel-Agent-Auth = %q, want agent-token", got)
	}
}
