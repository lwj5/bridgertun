// Package httpmiddleware provides the standard middleware stack used by the
// relay's HTTP servers.
package httpmiddleware

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
)

// Register attaches the standard middleware stack to router.
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
			Str("url", sanitizeURL(r.URL)).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Send()
	}))
	router.Use(middleware.Recoverer)
}

// sanitizeURL returns the URL as a string with the x-tunnel-auth credential
// query parameter masked so tunnel credentials never appear in access logs.
func sanitizeURL(u *url.URL) string {
	if u.RawQuery == "" {
		return u.String()
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		// Unparseable query: redact entirely rather than risk logging raw credentials.
		clone := *u
		clone.RawQuery = "redacted"
		return clone.String()
	}
	redacted := false
	for key := range values {
		if strings.EqualFold(key, "x-tunnel-auth") {
			values[key] = []string{"***"}
			redacted = true
		}
	}
	if !redacted {
		return u.String()
	}
	clone := *u
	// values.Encode() percent-encodes '*' as '%2A'; restore the literal '***'
	// so the placeholder is human-readable in logs.
	clone.RawQuery = strings.ReplaceAll(values.Encode(), "%2A%2A%2A", "***")
	return clone.String()
}
