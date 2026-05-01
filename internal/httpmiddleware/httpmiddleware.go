// Package httpmiddleware provides the standard middleware stack used by the
// relay's HTTP servers.
package httpmiddleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
)

func Register(router chi.Router) {
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(hlog.NewHandler(log.Logger))
	router.Use(hlog.RemoteAddrHandler("ip"))
	router.Use(hlog.UserAgentHandler("user_agent"))
	router.Use(hlog.RequestIDHandler("request_id", "Request-Id"))
	router.Use(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Send()
	}))
	router.Use(middleware.Recoverer)
}
