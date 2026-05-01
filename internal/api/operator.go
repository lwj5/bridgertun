package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/lwj5/bridgertun/internal/auth"
	"github.com/lwj5/bridgertun/internal/httpjson"
	"github.com/lwj5/bridgertun/internal/log"
	"github.com/lwj5/bridgertun/internal/registry"
)

type operatorHandler struct {
	registry registry.Registry
	verifier *auth.Verifier
}

func newOperatorHandler(registry registry.Registry, v *auth.Verifier) *operatorHandler {
	return &operatorHandler{registry: registry, verifier: v}
}

// requireOperator validates an OIDC bearer token and requires the
// `tunnel:operator` scope.
func (h *operatorHandler) requireOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")
		if raw == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		principal, err := h.verifier.Verify(ctx, raw)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !hasScope(principal.Scopes, "tunnel:operator") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func (h *operatorHandler) listSessions(w http.ResponseWriter, r *http.Request) {
	filter := registry.Filter{
		Subject: r.URL.Query().Get("sub"),
		Tenant:  r.URL.Query().Get("tenant"),
	}
	sessions, err := h.registry.List(r.Context(), filter)
	if err != nil {
		log.L().Warn().Err(err).Msg("list sessions")
		http.Error(w, "registry error", http.StatusBadGateway)
		return
	}
	// The registry may return pointers to its internal state; copy each
	// entry before redacting so we don't clobber the cached record.
	redacted := make([]registry.SessionInfo, 0, len(sessions))
	for _, info := range sessions {
		if info == nil {
			continue
		}
		entry := *info
		entry.TunnelAuthHash = ""
		redacted = append(redacted, entry)
	}
	httpjson.Write(w, http.StatusOK, redacted)
}

func (h *operatorHandler) getSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	info, err := h.registry.Lookup(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "registry error", http.StatusBadGateway)
		return
	}
	redacted := *info
	redacted.TunnelAuthHash = ""
	httpjson.Write(w, http.StatusOK, redacted)
}

func (h *operatorHandler) deleteSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	if err := h.registry.ForceClose(r.Context(), sessionID); err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "registry error", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
