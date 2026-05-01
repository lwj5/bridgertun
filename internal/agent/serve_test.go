package agent

import (
	"context"
	"net/url"
	"testing"

	"github.com/lwj5/bridgertun/internal/wire"
)

const (
	testAgentToken  = "agent-token"
	testRelayToken  = "relay-token"
	testAccessToken = "token"
)

func TestVerifyAgentTokenUsesCaseInsensitiveHeaderLookup(t *testing.T) {
	t.Parallel()

	envelope := &wire.Envelope{Headers: map[string][]string{
		"x-tunnel-agent-auth": {testAgentToken},
	}}

	if !verifyAgentToken(envelope, testAgentToken) {
		t.Fatal("verifyAgentToken() = false, want true")
	}
}

func TestCleanedHeadersStripsRelayInternalHeaders(t *testing.T) {
	t.Parallel()

	cleaned := cleanedHeaders(map[string][]string{
		"Host":                      {"example.com"},
		"X-Tunnel-Agent-Auth":       {"secret"},
		"X-Tunnel-Session-Internal": {"session-1"},
		"content-type":              {"application/json"},
	})

	if cleaned.Get("Host") != "" {
		t.Fatalf("Host header survived cleaning: %v", cleaned.Values("Host"))
	}
	if cleaned.Get("X-Tunnel-Agent-Auth") != "" {
		t.Fatalf("X-Tunnel-Agent-Auth survived cleaning: %v", cleaned.Values("X-Tunnel-Agent-Auth"))
	}
	if cleaned.Get("X-Tunnel-Session-Internal") != "" {
		t.Fatalf("X-Tunnel-Session-Internal survived cleaning: %v", cleaned.Values("X-Tunnel-Session-Internal"))
	}
	if got := cleaned.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}
}

func TestBuildLocalURLStripsAgentSecret(t *testing.T) {
	t.Parallel()

	got, err := buildLocalURL("http://127.0.0.1:3000/", "/api/events?agent_secret=topsecret&foo=bar")
	if err != nil {
		t.Fatalf("buildLocalURL() error = %v", err)
	}

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse returned url: %v", err)
	}
	if parsed.Path != "/api/events" {
		t.Fatalf("Path = %q, want %q", parsed.Path, "/api/events")
	}
	if parsed.Query().Get("agent_secret") != "" {
		t.Fatalf("agent_secret survived in query: %q", parsed.RawQuery)
	}
	if parsed.Query().Get("foo") != "bar" {
		t.Fatalf("foo query = %q, want %q", parsed.Query().Get("foo"), "bar")
	}
}

func TestTrySendReturnsFalseWhenContextIsCanceledAndBufferIsFull(t *testing.T) {
	t.Parallel()

	ch := make(chan *wire.Envelope, 1)
	ch <- &wire.Envelope{ID: "existing", Type: wire.TypeResponseChunk}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if ok := trySend(ctx, ch, &wire.Envelope{ID: "next", Type: wire.TypeResponseChunk}); ok {
		t.Fatal("trySend() = true, want false")
	}
}
