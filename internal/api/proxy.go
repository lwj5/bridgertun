package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/lwj5/bridgertun/internal/registry"
	"github.com/lwj5/bridgertun/internal/wire"
)

// hopByHop is the set of HTTP headers we do NOT forward into the tunnel
// (RFC 7230 section 6.1 plus common proxy hops).
var hopByHop = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"host":                true,
	"content-length":      true,
}

type proxyHandler struct {
	cfg      Config
	registry registry.Registry
}

func newProxyHandler(cfg Config, registry registry.Registry) *proxyHandler {
	return &proxyHandler{cfg: cfg, registry: registry}
}

//nolint:gocyclo // Request/response proxying is inherently branch-heavy across auth, stream, and error paths.
func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	sessionLogger := log.Ctx(r.Context()).With().Str("session", sessionID).Logger()

	info, err := h.registry.Lookup(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		http.Error(w, "registry error", http.StatusBadGateway)
		return
	}

	ok, tier1Source := verifyBearer(r, info.TunnelAuthHash)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	// Build the path the agent's local service will see: strip /v1/tunnel/{id}.
	prefix := "/v1/tunnel/" + sessionID
	tunnelPath := strings.TrimPrefix(r.URL.Path, prefix)
	if tunnelPath == "" {
		tunnelPath = "/"
	}
	if rq := stripTunnelAuthQuery(r.URL.RawQuery); rq != "" {
		tunnelPath += "?" + rq
	}

	headers := filteredHeaders(r.Header)
	// Tier-1 credential is for the relay only; never forward it to the agent.
	delete(headers, "X-Tunnel-Auth")
	if firstHeaderValue(headers, "X-Tunnel-Agent-Auth") == "" {
		switch tier1Source {
		case authSourceBasic:
			if _, basicPassword, hasBasic := r.BasicAuth(); hasBasic && basicPassword != "" {
				headers["X-Tunnel-Agent-Auth"] = []string{basicPassword}
			}
		case authSourceQuery:
			if querySecret := agentTokenFromQuery(r.URL.RawQuery); querySecret != "" {
				headers["X-Tunnel-Agent-Auth"] = []string{querySecret}
			}
		case authSourceHeader:
			// Tier 2 must come from its own X-Tunnel-Agent-Auth header when
			// tier 1 was a header — Basic password and query are not promoted.
		}
	}
	if firstHeaderValue(headers, "X-Tunnel-Agent-Auth") == "" {
		http.Error(w, "missing agent token", http.StatusUnauthorized)
		return
	}
	// Authorization may carry the Basic-auth tier-1 credential we just
	// consumed. Drop only that exact value — additional Authorization
	// headers (e.g. a Bearer for the local service) belong to the
	// downstream and must survive.
	if tier1Source == authSourceBasic {
		consumed := r.Header.Get("Authorization")
		values := headers["Authorization"]
		filtered := make([]string, 0, len(values))
		removed := false
		for _, value := range values {
			if !removed && value == consumed {
				removed = true
				continue
			}
			filtered = append(filtered, value)
		}
		if len(filtered) == 0 {
			delete(headers, "Authorization")
		} else {
			headers["Authorization"] = filtered
		}
	}
	if ip := clientIP(r, h.cfg.TrustedProxies); ip != "" {
		headers["X-Forwarded-For"] = append(headers["X-Forwarded-For"], ip)
	}
	headers["X-Forwarded-Host"] = []string{r.Host}
	if r.TLS != nil {
		headers["X-Forwarded-Proto"] = []string{"https"}
	} else {
		headers["X-Forwarded-Proto"] = []string{"http"}
	}
	// Pass the session id to the owning node (consumed by registry; stripped before reaching the agent).
	headers["X-Tunnel-Session-Internal"] = []string{sessionID}

	envelope := &wire.Envelope{
		Type:    wire.TypeRequest,
		Method:  r.Method,
		Path:    tunnelPath,
		Headers: headers,
		Body:    body,
	}

	dispatchCtx, cancel := context.WithCancel(r.Context())
	defer cancel()

	ps, err := h.registry.Dispatch(dispatchCtx, sessionID, envelope)
	if err != nil {
		sessionLogger.Warn().Err(err).Msg("dispatch")
		http.Error(w, "tunnel dispatch error", http.StatusBadGateway)
		return
	}
	defer func() { _ = ps.Close() }()

	// If the caller goes away, cancel upstream.
	go func() {
		<-r.Context().Done()
		ps.Cancel()
	}()

	flusher, _ := w.(http.Flusher)
	wroteHead := false
	awaitingFirstFrame := true
	requestTimeout := time.NewTimer(h.cfg.ProxyRequestTimeout)
	defer requestTimeout.Stop()
	idleTimer := time.NewTimer(h.cfg.StreamIdleTimeout)
	defer idleTimer.Stop()
	resetIdle := func() {
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(h.cfg.StreamIdleTimeout)
	}

	type recvResult struct {
		env *wire.Envelope
		err error
	}
	recvCh := make(chan recvResult)
	go func() {
		defer close(recvCh)
		for {
			env, err := ps.Receive(dispatchCtx)
			select {
			case recvCh <- recvResult{env, err}:
			case <-dispatchCtx.Done():
				return
			}
			if err != nil && !errors.Is(err, registry.ErrBlockTimeout) {
				return
			}
		}
	}()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-requestTimeout.C:
			sessionLogger.Warn().Dur("wait", h.cfg.ProxyRequestTimeout).Msg("upstream response timeout")
			http.Error(w, "upstream response timeout", http.StatusGatewayTimeout)
			return
		case <-idleTimer.C:
			sessionLogger.Warn().Msg("stream idle timeout")
			if !wroteHead {
				http.Error(w, "upstream idle timeout", http.StatusGatewayTimeout)
			}
			return
		case res, ok := <-recvCh:
			if !ok {
				return
			}
			if res.err != nil {
				if errors.Is(res.err, io.EOF) {
					return
				}
				if errors.Is(res.err, registry.ErrBlockTimeout) {
					// block timeout — wait for next frame without resetting idle
					continue
				}
				sessionLogger.Warn().Err(res.err).Msg("stream receive")
				if !wroteHead {
					http.Error(w, "upstream error", http.StatusBadGateway)
				}
				return
			}
			if awaitingFirstFrame {
				awaitingFirstFrame = false
				if !requestTimeout.Stop() {
					select {
					case <-requestTimeout.C:
					default:
					}
				}
			}
			resetIdle()
			env := res.env
			switch env.Type {
			case wire.TypeResponseHead:
				for k, vs := range env.Headers {
					if hopByHop[strings.ToLower(k)] {
						continue
					}
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				status := env.Status
				if status == 0 {
					status = http.StatusOK
				}
				w.WriteHeader(status)
				wroteHead = true
				if flusher != nil {
					flusher.Flush()
				}
			case wire.TypeResponseChunk:
				if !wroteHead {
					w.WriteHeader(http.StatusOK)
					wroteHead = true
				}
				if len(env.Body) > 0 {
					if _, err := w.Write(env.Body); err != nil {
						return
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
			case wire.TypeResponseEnd:
				return
			case wire.TypeError:
				sessionLogger.Warn().Str("err", env.Error).Msg("agent error")
				if !wroteHead {
					http.Error(w, "agent error: "+env.Error, http.StatusBadGateway)
				}
				return
			}
		}
	}
}

const tunnelAuthQueryKey = "x-tunnel-auth"

// stripTunnelAuthQuery removes the x-tunnel-auth credential query param from
// the forwarded query string. Both tiers are encoded in that single key so
// only one key needs stripping.
func stripTunnelAuthQuery(raw string) string {
	if raw == "" {
		return ""
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return raw
	}
	if _, ok := values[tunnelAuthQueryKey]; !ok {
		return raw
	}
	values.Del(tunnelAuthQueryKey)
	return values.Encode()
}

// agentTokenFromQuery extracts the tier-2 agent token from the x-tunnel-auth
// query param. The value format is "<tier1>:<tier2>"; returns empty when no
// colon is present.
func agentTokenFromQuery(raw string) string {
	if raw == "" {
		return ""
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return ""
	}
	_, agentToken, found := strings.Cut(values.Get(tunnelAuthQueryKey), ":")
	if !found {
		return ""
	}
	return agentToken
}

func filteredHeaders(in http.Header) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, vs := range in {
		if hopByHop[strings.ToLower(k)] {
			continue
		}
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func firstHeaderValue(h map[string][]string, name string) string {
	if h == nil {
		return ""
	}
	if vs, ok := h[http.CanonicalHeaderKey(name)]; ok && len(vs) > 0 {
		return vs[0]
	}
	for k, vs := range h {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// clientIP returns the caller's IP. X-Forwarded-For is honored only when the
// immediate peer (RemoteAddr) is in the trusted-proxies list; otherwise XFF
// is ignored to prevent spoofed source IPs from being forwarded to the agent.
func clientIP(r *http.Request, trusted []*net.IPNet) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && peerIsTrusted(peer, trusted) {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	return peer
}

func peerIsTrusted(peer string, trusted []*net.IPNet) bool {
	if len(trusted) == 0 {
		return false
	}
	ip := net.ParseIP(peer)
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
