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
	testAgentToken    = "agenttoken"
	testSessionID     = "session-1"
	testTunnelAuthQuery = "x-tunnel-auth=relaytoken"
)

func TestStripTunnelAuthQuery(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		mustHas []string
		mustNot []string
	}{
		{
			name:    "drops x-tunnel-auth with both tiers",
			raw:     "x-tunnel-auth=relaytoken%3Aagenttoken&foo=bar",
			mustHas: []string{"foo=bar"},
			mustNot: []string{"x-tunnel-auth"},
		},
		{
			name:    "drops x-tunnel-auth with tier-1 only",
			raw:     testTunnelAuthQuery + "&foo=bar",
			mustHas: []string{"foo=bar"},
			mustNot: []string{"x-tunnel-auth"},
		},
		{
			name:    "only x-tunnel-auth yields empty",
			raw:     testTunnelAuthQuery,
			mustHas: nil,
			mustNot: []string{"x-tunnel-auth"},
		},
		{
			name:    "no x-tunnel-auth is unchanged",
			raw:     "foo=bar",
			mustHas: []string{"foo=bar"},
			mustNot: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripTunnelAuthQuery(tc.raw)

			parsed, err := url.ParseQuery(got)
			if err != nil {
				t.Fatalf("re-parse %q: %v", got, err)
			}
			if _, ok := parsed[tunnelAuthQueryKey]; ok {
				t.Fatalf("%s survived stripping: %q", tunnelAuthQueryKey, got)
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

func TestAgentTokenFromQuery(t *testing.T) {
	t.Run("extracts agent token from combined value", func(t *testing.T) {
		if got := agentTokenFromQuery("x-tunnel-auth=relaytoken%3A" + testAgentToken); got != testAgentToken {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("empty when no colon in value", func(t *testing.T) {
		if got := agentTokenFromQuery("x-tunnel-auth=relaytoken"); got != "" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("empty when key absent", func(t *testing.T) {
		if got := agentTokenFromQuery("foo=bar"); got != "" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("empty on parse failure", func(t *testing.T) {
		if got := agentTokenFromQuery("%zz"); got != "" {
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

func (timeoutRegistry) Detach(context.Context, string, registry.LocalSender) error {
	panic("unexpected Detach call")
}

//nolint:ireturn // Registry interface requires returning LocalSender.
func (timeoutRegistry) LocalSenderFor(string) (registry.LocalSender, bool) {
	return nil, false
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
	request.Header.Set("X-Tunnel-Agent-Auth", testAgentToken)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusGatewayTimeout)
	}
	if !strings.Contains(recorder.Body.String(), "upstream response timeout") {
		t.Fatalf("body = %q, want timeout message", recorder.Body.String())
	}
}

// captureRegistry snapshots the envelope passed to Dispatch and replies with
// an immediate response_end so the proxy returns 200 quickly.
type captureRegistry struct {
	tunnelAuthHash string
	captured       *wire.Envelope
}

func (captureRegistry) Register(context.Context, *registry.SessionInfo, registry.LocalSender) error {
	panic("unexpected Register call")
}
func (captureRegistry) Unregister(context.Context, string) error { panic("unexpected Unregister call") }
func (captureRegistry) Detach(context.Context, string, registry.LocalSender) error {
	panic("unexpected Detach call")
}

//nolint:ireturn // Registry interface requires returning LocalSender.
func (captureRegistry) LocalSenderFor(string) (registry.LocalSender, bool) { return nil, false }

func (r *captureRegistry) Lookup(context.Context, string) (*registry.SessionInfo, error) {
	return &registry.SessionInfo{SessionID: testSessionID, TunnelAuthHash: r.tunnelAuthHash}, nil
}

//nolint:ireturn // Test stub matches the registry interface.
func (r *captureRegistry) Dispatch(_ context.Context, _ string, envelope *wire.Envelope) (registry.ProxyStream, error) {
	r.captured = envelope
	return &endProxyStream{}, nil
}
func (captureRegistry) List(context.Context, registry.Filter) ([]*registry.SessionInfo, error) {
	panic("unexpected List call")
}
func (captureRegistry) ForceClose(context.Context, string) error { panic("unexpected ForceClose call") }
func (captureRegistry) Close() error                             { return nil }

type endProxyStream struct {
	sent bool
}

func (s *endProxyStream) Receive(ctx context.Context) (*wire.Envelope, error) {
	if !s.sent {
		s.sent = true
		return &wire.Envelope{Type: wire.TypeResponseEnd, EOF: true}, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*endProxyStream) Cancel()      {}
func (*endProxyStream) Close() error { return nil }

func newCaptureHandler(t *testing.T) (*proxyHandler, *captureRegistry, http.Handler) {
	t.Helper()
	reg := &captureRegistry{tunnelAuthHash: mustTunnelHash(t, "relay-secret")}
	handler := newProxyHandler(Config{
		MaxRequestBodyBytes: 1 << 20,
		ProxyRequestTimeout: time.Second,
		StreamIdleTimeout:   time.Second,
	}, reg)
	router := chi.NewRouter()
	router.Handle("/v1/tunnel/{sessionID}", handler)
	router.Handle("/v1/tunnel/{sessionID}/*", handler)
	return handler, reg, router
}

func TestProxyHandlerAcceptsBasicAuthAndPromotesPasswordToAgentHeader(t *testing.T) {
	t.Parallel()

	_, reg, router := newCaptureHandler(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/tunnel/"+testSessionID+"/api", nil)
	request.SetBasicAuth("relay-secret", testAgentToken)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if reg.captured == nil {
		t.Fatal("Dispatch was not called")
	}
	if got := firstHeaderValue(reg.captured.Headers, "X-Tunnel-Agent-Auth"); got != testAgentToken {
		t.Fatalf("X-Tunnel-Agent-Auth = %q, want %q", got, testAgentToken)
	}
	if _, ok := reg.captured.Headers["Authorization"]; ok {
		t.Fatalf("Authorization header survived to envelope: %v", reg.captured.Headers["Authorization"])
	}
}

func TestProxyHandlerKeepsUnrelatedBasicAuthorizationHeader(t *testing.T) {
	t.Parallel()

	_, reg, router := newCaptureHandler(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/tunnel/"+testSessionID+"/api", nil)
	request.Header.Set("X-Tunnel-Auth", "relay-secret")
	request.Header.Set("X-Tunnel-Agent-Auth", testAgentToken)
	// Caller's own Basic auth — for the local service, not the relay.
	request.SetBasicAuth("local-service-user", "local-service-pass")
	// SetBasicAuth overwrites Authorization but leaves X-Tunnel-Auth alone.

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if reg.captured == nil {
		t.Fatal("Dispatch was not called")
	}
	auth := firstHeaderValue(reg.captured.Headers, "Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("Authorization = %q, want Basic header to be preserved when relay used X-Tunnel-Auth headers", auth)
	}
}

func TestProxyHandlerKeepsBearerAuthorizationHeader(t *testing.T) {
	t.Parallel()

	_, reg, router := newCaptureHandler(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/tunnel/"+testSessionID+"/api", nil)
	request.Header.Set("X-Tunnel-Auth", "relay-secret")
	request.Header.Set("X-Tunnel-Agent-Auth", testAgentToken)
	request.Header.Set("Authorization", "Bearer local-service-jwt")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if reg.captured == nil {
		t.Fatal("Dispatch was not called")
	}
	if got := firstHeaderValue(reg.captured.Headers, "Authorization"); got != "Bearer local-service-jwt" {
		t.Fatalf("Authorization = %q, want Bearer header preserved", got)
	}
}

func TestProxyHandlerHeaderTier1DoesNotPromoteBasicPasswordToTier2(t *testing.T) {
	t.Parallel()

	_, reg, router := newCaptureHandler(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/tunnel/"+testSessionID+"/api", nil)
	request.Header.Set("X-Tunnel-Auth", "relay-secret")
	request.Header.Set("X-Tunnel-Agent-Auth", testAgentToken)
	// Basic password is unrelated to the agent token; it must not be promoted
	// into X-Tunnel-Agent-Auth when tier-1 came from a header.
	request.SetBasicAuth("ignored-user", "stale-basic-password")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if got := firstHeaderValue(reg.captured.Headers, "X-Tunnel-Agent-Auth"); got != testAgentToken {
		t.Fatalf("X-Tunnel-Agent-Auth = %q, want %q (explicit header must be kept; Basic password must not be promoted)", got, testAgentToken)
	}
	// Authorization is preserved because tier-1 did not consume it.
	if _, ok := reg.captured.Headers["Authorization"]; !ok {
		t.Fatal("Authorization header was stripped, want preserved when tier-1 came from X-Tunnel-Auth")
	}
}

func TestProxyHandlerStripsTier1HeaderBeforeForwarding(t *testing.T) {
	t.Parallel()

	_, reg, router := newCaptureHandler(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/tunnel/"+testSessionID+"/api", nil)
	request.Header.Set("X-Tunnel-Auth", "relay-secret")
	request.Header.Set("X-Tunnel-Agent-Auth", testAgentToken)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if _, ok := reg.captured.Headers["X-Tunnel-Auth"]; ok {
		t.Fatalf("X-Tunnel-Auth survived to envelope: %v", reg.captured.Headers["X-Tunnel-Auth"])
	}
}

func TestProxyHandlerRejectsRequestWithoutAgentToken(t *testing.T) {
	t.Parallel()

	_, reg, router := newCaptureHandler(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/tunnel/"+testSessionID+"/api", nil)
	request.Header.Set("X-Tunnel-Auth", "relay-secret")
	// No X-Tunnel-Agent-Auth, no Basic password, no query — tier-2 missing.

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if reg.captured != nil {
		t.Fatal("Dispatch was called for a request missing the agent token")
	}
}

func TestProxyHandlerQueryTier1PromotesAgentSecretToTier2(t *testing.T) {
	t.Parallel()

	_, reg, router := newCaptureHandler(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet,
		"/v1/tunnel/"+testSessionID+"/api?x-tunnel-auth=relay-secret%3A"+testAgentToken,
		nil,
	)

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if got := firstHeaderValue(reg.captured.Headers, "X-Tunnel-Agent-Auth"); got != testAgentToken {
		t.Fatalf("X-Tunnel-Agent-Auth = %q, want %q", got, testAgentToken)
	}
}

func TestProxyHandlerStripsOnlyConsumedBasicAuthorizationValue(t *testing.T) {
	t.Parallel()

	_, reg, router := newCaptureHandler(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/tunnel/"+testSessionID+"/api", nil)
	// Tier 1 + tier 2 via Basic, then additional Authorization values for the
	// local service (a Bearer and an unrelated Basic). Only the relay's own
	// Basic value should be stripped; the rest must survive.
	request.SetBasicAuth("relay-secret", testAgentToken)
	request.Header.Add("Authorization", "Bearer local-service-jwt")
	request.Header.Add("Authorization", "Basic bG9jYWw6c2VydmljZQ==")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	values := reg.captured.Headers["Authorization"]
	want := []string{"Bearer local-service-jwt", "Basic bG9jYWw6c2VydmljZQ=="}
	if len(values) != len(want) {
		t.Fatalf("Authorization = %v, want %v", values, want)
	}
	for i, value := range values {
		if value != want[i] {
			t.Fatalf("Authorization[%d] = %q, want %q (full slice %v)", i, value, want[i], values)
		}
	}
}

func TestProxyHandlerExplicitTier2HeaderWinsOverBasicPassword(t *testing.T) {
	t.Parallel()

	_, reg, router := newCaptureHandler(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/tunnel/"+testSessionID+"/api", nil)
	request.Header.Set("X-Tunnel-Agent-Auth", testAgentToken)
	request.SetBasicAuth("relay-secret", "stale-basic-password")

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if got := firstHeaderValue(reg.captured.Headers, "X-Tunnel-Agent-Auth"); got != testAgentToken {
		t.Fatalf("X-Tunnel-Agent-Auth = %q, want %q (explicit header must win)", got, testAgentToken)
	}
	// Tier 1 came from Basic, so Authorization was consumed and stripped.
	if _, ok := reg.captured.Headers["Authorization"]; ok {
		t.Fatalf("Authorization header survived: %v", reg.captured.Headers["Authorization"])
	}
}
