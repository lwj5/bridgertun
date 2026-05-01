// Package httpjson provides helpers for writing JSON HTTP responses.
package httpjson

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
)

// Write encodes payload as JSON, sets the Content-Type header, and writes
// the given status code. Encoding failures are logged but not surfaced to
// the caller, since the response headers are already committed.
func Write(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Warn().Err(err).Msg("encode response")
	}
}
