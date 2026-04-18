package api

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lwj5/bridgertun/internal/auth"
	"github.com/lwj5/bridgertun/internal/registry"
	"github.com/valkey-io/valkey-go"
)

// Config holds the API server's runtime parameters.
type Config struct {
	OIDCIssuerURL       string
	OIDCAgentClientID   string
	MaxRequestBodyBytes int64
	TrustedProxies      []*net.IPNet
	StreamIdleTimeout   time.Duration
}

type agentDiscoveryResponse struct {
	IssuerURL string `json:"issuer_url"`
	ClientID  string `json:"client_id"`
}

// NewRouter builds the HTTP router that serves public proxy routes, operator
// routes, and health checks.
func NewRouter(cfg Config, registry registry.Registry, verifier *auth.Verifier, rdb valkey.Client) http.Handler {
	r := chi.NewRouter()

	proxyHandler := newProxyHandler(cfg, registry)
	operatorHandler := newOperatorHandler(registry, verifier)

	// Proxy routes — per-session auth middleware runs inside proxyH.ServeHTTP.
	r.Handle("/v1/tunnel/{sessionID}/*", proxyHandler)
	r.Handle("/v1/tunnel/{sessionID}", proxyHandler)

	// Operator routes — OIDC scope auth.
	r.Route("/v1/sessions", func(r chi.Router) {
		r.Use(operatorHandler.requireOperator)
		r.Get("/", operatorHandler.listSessions)
		r.Get("/{sessionID}", operatorHandler.getSession)
		r.Delete("/{sessionID}", operatorHandler.deleteSession)
	})

	// Agent discovery — public, no auth required.
	r.Get("/v1/agent/config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, agentDiscoveryResponse{
			IssuerURL: cfg.OIDCIssuerURL,
			ClientID:  cfg.OIDCAgentClientID,
		})
	})

	// Health.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := rdb.Do(ctx, rdb.B().Ping().Build()).Error(); err != nil {
			http.Error(w, "valkey down", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	return r
}
