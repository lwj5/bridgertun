package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/lwj5/bridgertun/internal/registry"
	"github.com/lwj5/bridgertun/internal/wire"
)

const (
	testAgentToken        = "agenttoken"
	testSessionID         = "session-1"
	testTunnelSecretQuery = "tunnel_secret=relaytoken"
)

func TestStripTunnelAuthQuery(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		mustHas []string
		mustNot []string
	}{
		{
			name:    "drops tunnel_secret and agent_secret",
			raw:     testTunnelSecretQuery + "&agent_secret=agenttoken&foo=bar",
			mustHas: []string{"foo=bar"},
			mustNot: []string{testTunnelSecretQuery, "agent_secret=agenttoken"},
		},
		{
			name:    "drops agent secret when no tunnel secret",
			raw:     "agent_secret=agenttoken&foo=bar",
			mustHas: []string{"foo=bar"},
			mustNot: []string{"agent_secret=agenttoken"},
		},
		{
			name:    "only tunnel secret yields empty",
			raw:     testTunnelSecretQuery,
			mustHas: nil,
			mustNot: []string{testTunnelSecretQuery},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripTunnelAuthQuery(tc.raw)

			parsed, err := url.ParseQuery(got)
			if err != nil {
				t.Fatalf("re-parse %q: %v", got, err)
			}
			if _, ok := parsed["tunnel_secret"]; ok {
				t.Fatalf("tunnel_secret survived stripping: %q", got)
			}
			if _, ok := parsed["agent_secret"]; ok {
				t.Fatalf("agent_secret survived stripping: %q", got)
			}

			for _, s := range tc.mustHas {
				if !strings.Contains(got, s) {
					t.Errorf("missing %q in %q", s, got)
				}
			}
			for _, s := range tc.mustNot {
				if strings.Contains(got, s) {
					t.Errorf("forbidden %q in %q", s, got)
				}
			}
		})
	}
}

func TestStripTunnelAuthQuery_Empty(t *testing.T) {
	if got := stripTunnelAuthQuery(""); got != "" {
		t.Fatalf("empty in, got %q", got)
	}
}

func TestFilteredHeaders_PreservesAgentAuthHeader(t *testing.T) {
	in := http.Header{
		"Authorization":       {"Bearer relaytoken"},
		"X-Tunnel-Auth":       {"relaytoken"},
		"X-Tunnel-Agent-Auth": {testAgentToken},
		"Content-Type":        {"application/json"},
		"Connection":          {"close"},
	}

	out := filteredHeaders(in)

	if got := out["Authorization"]; len(got) != 1 || got[0] != "Bearer relaytoken" {
		t.Errorf("Authorization should have been preserved: %v", got)
	}
	if got := out["X-Tunnel-Auth"]; len(got) != 1 || got[0] != "relaytoken" {
		t.Errorf("X-Tunnel-Auth should have been preserved: %v", got)
	}
	if _, ok := out["Connection"]; ok {
		t.Errorf("hop-by-hop Connection should have been stripped")
	}
	if got := out["X-Tunnel-Agent-Auth"]; len(got) != 1 || got[0] != testAgentToken {
		t.Errorf("X-Tunnel-Agent-Auth not preserved: %v", got)
	}
	if got := out["Content-Type"]; len(got) != 1 || got[0] != "application/json" {
		t.Errorf("Content-Type not preserved: %v", got)
	}
}

func TestAgentSecretFromQuery(t *testing.T) {
	t.Run("extracts agent secret", func(t *testing.T) {
		if got := agentSecretFromQuery("foo=bar&agent_secret=agenttoken"); got != testAgentToken {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("empty when missing", func(t *testing.T) {
		if got := agentSecretFromQuery("foo=bar"); got != "" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("empty on parse failure", func(t *testing.T) {
		if got := agentSecretFromQuery("%zz"); got != "" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestFirstHeaderValue(t *testing.T) {
	h := map[string][]string{
		"x-tunnel-agent-auth": {testAgentToken},
	}
	if got := firstHeaderValue(h, "X-Tunnel-Agent-Auth"); got != testAgentToken {
		t.Fatalf("got %q", got)
	}
}

type timeoutRegistry struct {
	tunnelAuthHash string
}

func (timeoutRegistry) Register(context.Context, *registry.SessionInfo, registry.LocalSender) error {
	panic("unexpected Register call")
}

func (timeoutRegistry) Unregister(context.Context, string) error {
	panic("unexpected Unregister call")
}

func (timeoutRegistry) Detach(context.Context, string) error {
	panic("unexpected Detach call")
}

func (r timeoutRegistry) Lookup(context.Context, string) (*registry.SessionInfo, error) {
	return &registry.SessionInfo{SessionID: testSessionID, TunnelAuthHash: r.tunnelAuthHash}, nil
}

//nolint:ireturn // Test stub matches the registry interface.
func (timeoutRegistry) Dispatch(
	context.Context,
	string,
	*wire.Envelope,
) (registry.ProxyStream, error) {
	return timeoutProxyStream{}, nil
}

func (timeoutRegistry) List(context.Context, registry.Filter) ([]*registry.SessionInfo, error) {
	panic("unexpected List call")
}

func (timeoutRegistry) ForceClose(context.Context, string) error {
	panic("unexpected ForceClose call")
}

func (timeoutRegistry) Close() error {
	return nil
}

type timeoutProxyStream struct{}

func (timeoutProxyStream) Receive(ctx context.Context) (*wire.Envelope, error) {
	<-ctx.Done()
	return nil, fmt.Errorf("receive canceled: %w", ctx.Err())
}

func (timeoutProxyStream) Cancel() {}

func (timeoutProxyStream) Close() error { return nil }

func TestProxyHandlerTimesOutBeforeFirstResponseFrame(t *testing.T) {
	t.Parallel()

	handler := newProxyHandler(Config{
		MaxRequestBodyBytes: 1 << 20,
		ProxyRequestTimeout: 10 * time.Millisecond,
		StreamIdleTimeout:   time.Second,
	}, timeoutRegistry{tunnelAuthHash: mustTunnelHash(t, "relay-secret")})
	router := chi.NewRouter()
	router.Handle("/v1/tunnel/{sessionID}", handler)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/tunnel/"+testSessionID, nil)
	request.Header.Set("X-Tunnel-Auth", "relay-secret")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusGatewayTimeout)
	}
	if !strings.Contains(recorder.Body.String(), "upstream response timeout") {
		t.Fatalf("body = %q, want timeout message", recorder.Body.String())
	}
}
