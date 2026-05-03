package agent

import (
	"context"
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
