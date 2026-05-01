package api

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/valkey-io/valkey-go"

	"github.com/lwj5/bridgertun/internal/auth"
	"github.com/lwj5/bridgertun/internal/httpmiddleware"
	"github.com/lwj5/bridgertun/internal/registry"
)

// Config holds the API server's runtime parameters.
type Config struct {
	MaxRequestBodyBytes int64
	ProxyRequestTimeout time.Duration
	TrustedProxies      []*net.IPNet
	StreamIdleTimeout   time.Duration
}

// NewRouter builds the HTTP router that serves public proxy routes, operator
// routes, and health checks.
func NewRouter(cfg Config, registry registry.Registry, verifier *auth.Verifier, rdb valkey.Client) http.Handler {
	r := chi.NewRouter()
	httpmiddleware.Register(r)

	proxyHandler := newProxyHandler(cfg, registry)
	operatorHandler := newOperatorHandler(registry, verifier)

	// Proxy routes — streaming responses, so no request timeout. Per-session
	// auth middleware runs inside proxyHandler.ServeHTTP.
	r.Handle("/v1/tunnel/{sessionID}/*", proxyHandler)
	r.Handle("/v1/tunnel/{sessionID}", proxyHandler)

	// Operator and health routes — bounded request lifetime.
	r.Group(func(r chi.Router) {
		r.Use(middleware.Timeout(60 * time.Second))

		r.Route("/v1/sessions", func(r chi.Router) {
			r.Use(operatorHandler.requireOperator)
			r.Get("/", operatorHandler.listSessions)
			r.Get("/{sessionID}", operatorHandler.getSession)
			r.Delete("/{sessionID}", operatorHandler.deleteSession)
		})

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
	})

	return r
}
