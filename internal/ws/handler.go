package ws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/lwj5/bridgertun/internal/auth"
	"github.com/lwj5/bridgertun/internal/httpjson"
	"github.com/lwj5/bridgertun/internal/registry"
	"github.com/lwj5/bridgertun/internal/wire"
)

// HandlerConfig holds the ws handler's runtime parameters.
type HandlerConfig struct {
	AllowedOrigins    []string
	PingInterval      time.Duration
	PongTimeout       time.Duration
	StreamIdleTimeout time.Duration
	OIDCIssuerURL     string
	OIDCAgentClientID string
}

// ResumeHeader is the request header an agent sets at WebSocket upgrade time
// to request that the server resume a prior session rather than minting a new
// one. The server validates that the JWT subject matches the stored session
// before honoring the hint.
const ResumeHeader = "X-Tunnel-Resume-Session"

const (
	localEvictTimeout  = 2 * time.Second
	remoteEvictTimeout = 500 * time.Millisecond
)

// Handler is the HTTP handler for the agent WebSocket endpoint.
type Handler struct {
	config   HandlerConfig
	verifier *auth.Verifier
	registry registry.Registry
	baseURL  string
}

// NewHandler returns a Handler wired to the given config, verifier, registry, and relay base URL.
func NewHandler(
	config HandlerConfig,
	verifier *auth.Verifier,
	registry registry.Registry,
	relayBaseURL string,
) *Handler {
	return &Handler{config: config, verifier: verifier, registry: registry, baseURL: relayBaseURL}
}

type agentDiscoveryResponse struct {
	IssuerURL string `json:"issuer_url"`
	ClientID  string `json:"client_id"`
}

// ServeAgentConfig handles GET /v1/agent/config. No auth required — returns
// the OIDC issuer and client ID the agent needs to acquire a token.
func (h *Handler) ServeAgentConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	httpjson.Write(r.Context(), w, http.StatusOK, agentDiscoveryResponse{
		IssuerURL: h.config.OIDCIssuerURL,
		ClientID:  h.config.OIDCAgentClientID,
	})
}

// ServeHTTP handles GET /v1/agent/connect. The agent must present a valid
// OIDC JWT via the Authorization header.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestLogger := log.Ctx(r.Context())
	rawAuthorization := r.Header.Get("Authorization")
	if rawAuthorization == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	verifyCtx, verifyCancel := context.WithTimeout(r.Context(), 5*time.Second)
	principal, err := h.verifier.Verify(verifyCtx, rawAuthorization)
	verifyCancel()
	if err != nil {
		requestLogger.Warn().Err(err).Msg("jwt verify")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	tunnelAuth, err := ParseTunnelAuth(r.Header)
	if err != nil {
		http.Error(w, "tunnel auth: "+err.Error(), http.StatusBadRequest)
		return
	}

	acceptOptions := &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled}
	if len(h.config.AllowedOrigins) > 0 {
		acceptOptions.OriginPatterns = h.config.AllowedOrigins
	} else {
		// No allowlist configured — accept any Origin and rely on bearer auth
		// plus the ingress for CSWSH protection.
		acceptOptions.InsecureSkipVerify = true
	}
	// Resolve the session ID before upgrading: resume hints that fail subject
	// auth should return an HTTP error, which is only possible before Accept.
	resumeHint := strings.TrimSpace(r.Header.Get(ResumeHeader))
	sessionID, resumed, err := h.resolveSessionID(r.Context(), resumeHint, principal)
	if err != nil {
		var resumeErr *resumeError
		if errors.As(err, &resumeErr) {
			http.Error(w, resumeErr.message, resumeErr.status)
			return
		}
		requestLogger.Error().Err(err).Msg("resolve session id")
		http.Error(w, "resume lookup failed", http.StatusServiceUnavailable)
		return
	}
	sessionLogger := requestLogger.With().Str("session", sessionID).Logger()

	webSocketConn, err := websocket.Accept(w, r, acceptOptions)
	if err != nil {
		requestLogger.Warn().Err(err).Msg("ws accept")
		return
	}

	conn := NewConnection(sessionID, principal, webSocketConn, ConnectionOptions{
		PingInterval: h.config.PingInterval,
		PongTimeout:  h.config.PongTimeout,
		IdleTimeout:  h.config.StreamIdleTimeout,
	})

	sessionInfo := &registry.SessionInfo{
		SessionID:      sessionID,
		Subject:        principal.Subject,
		Username:       principal.Username,
		Tenant:         principal.Tenant,
		ConnectedAt:    time.Now(),
		TunnelAuthHash: tunnelAuth,
	}
	if err := h.registry.Register(r.Context(), sessionInfo, conn); err != nil {
		sessionLogger.Error().Err(err).Msg("registry register")
		_ = webSocketConn.Close(websocket.StatusInternalError, "registry unavailable")
		return
	}

	// Send hello so the agent learns its sessionID + relay URL. If this
	// fails the session is unusable; tear down so we don't leave a zombie
	// registered.
	hello := &wire.Envelope{
		ID:        sessionID,
		Type:      wire.TypeHello,
		TunnelURL: h.baseURL + "/v1/tunnel/" + sessionID + "/",
	}
	if err := conn.Send(r.Context(), hello); err != nil {
		sessionLogger.Warn().Err(err).Msg("send hello")
		conn.Close("hello send failed")
		detachCtx, detachCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		if detachErr := h.registry.Detach(detachCtx, sessionID, conn); detachErr != nil {
			sessionLogger.Warn().Err(detachErr).Msg("registry detach after hello failure")
		}
		detachCancel()
		return
	}

	sessionLogger.Info().
		Str("sub", principal.Subject).
		Str("tenant", principal.Tenant).
		Bool("resumed", resumed).
		Msg("agent connected")

	conn.Run(r.Context())

	// Cleanup. r.Context() is already canceled by the time Run returns, so
	// derive the cleanup deadline from a non-canceled parent. Use Detach
	// instead of Unregister so the agent can reconnect within the grace
	// window and resume with the same session ID. Pass conn so Detach can
	// guard against tearing down a replacement connection on the same node.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := h.registry.Detach(cleanupCtx, sessionID, conn); err != nil {
		sessionLogger.Warn().Err(err).Msg("registry detach")
	}
	sessionLogger.Info().Msg("agent disconnected")
}

// resumeError carries an HTTP status plus message back to ServeHTTP so the
// upgrade handshake can fail cleanly before the WebSocket is accepted.
type resumeError struct {
	status  int
	message string
}

func (e *resumeError) Error() string { return e.message }

// resolveSessionID picks the session ID for an incoming agent connection.
// If the agent supplied a valid resume hint that matches an existing session
// owned by the same principal, the prior owner is evicted and the same ID is
// returned. Otherwise a fresh UUID is minted.
func (h *Handler) resolveSessionID(
	ctx context.Context,
	hint string,
	principal *auth.Principal,
) (string, bool, error) {
	if hint == "" {
		return uuid.NewString(), false, nil
	}
	if _, err := uuid.Parse(hint); err != nil {
		return "", false, &resumeError{status: http.StatusBadRequest, message: "invalid resume session id"}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	sessionInfo, err := h.registry.Lookup(lookupCtx, hint)
	cancel()
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			log.Ctx(ctx).Info().Str("session", hint).Msg("resume hint expired; minting new session")
			return uuid.NewString(), false, nil
		}
		return "", false, fmt.Errorf("registry lookup: %w", err)
	}
	if sessionInfo.Subject != principal.Subject {
		return "", false, &resumeError{status: http.StatusForbidden, message: "session belongs to another principal"}
	}

	h.evictPriorOwner(ctx, sessionInfo)
	log.Ctx(ctx).Info().
		Str("session", hint).
		Str("prev_node", sessionInfo.NodeID).
		Str("state", sessionInfo.State).
		Msg("resuming session")
	return hint, true, nil
}

// evictPriorOwner makes sure any lingering connection for a resumed session
// is closed before the caller re-registers. If the session was already
// detached, nothing to do.
func (h *Handler) evictPriorOwner(ctx context.Context, sessionInfo *registry.SessionInfo) {
	if sessionInfo.State == registry.SessionStateDetached {
		return
	}

	// Grab the prior local sender's Done channel before closing it.
	// For local sessions we can block on Done() instead of sleeping;
	// for remote sessions we fall back to the pubsub settle delay.
	priorSender, isLocal := h.registry.LocalSenderFor(sessionInfo.SessionID)

	// Ask the owner (local or remote) to close its WebSocket. ForceClose
	// handles both cases by publishing a pubsub message to the owning node
	// when it isn't us.
	evictCtx, cancel := context.WithTimeout(ctx, localEvictTimeout)
	defer cancel()
	if err := h.registry.ForceClose(evictCtx, sessionInfo.SessionID); err != nil {
		log.Ctx(ctx).Warn().Err(err).Str("session", sessionInfo.SessionID).Msg("evict prior owner")
	}

	if isLocal {
		// Wait for the local owner's goroutine to finish so its deferred
		// Detach runs before we call Register. Sender-aware Detach is the
		// correctness guard; this wait makes eviction deterministic.
		select {
		case <-priorSender.Done():
		case <-evictCtx.Done():
		}
	} else {
		// Remote evictions cross a pubsub hop; brief settle is sufficient.
		select {
		case <-time.After(remoteEvictTimeout):
		case <-ctx.Done():
		}
	}
}
