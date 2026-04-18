// Package log configures and exposes the global zerolog logger.
package log

import (
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var initOnce sync.Once

// Init configures the global zerolog logger with the given level. It writes
// JSON to stderr and is intended to be called exactly once at process start;
// subsequent calls are no-ops to avoid racing with goroutines that already
// hold a reference to the global logger.
func Init(level string) {
	initOnce.Do(func() {
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
		parsedLevel, err := zerolog.ParseLevel(strings.ToLower(level))
		if err != nil {
			parsedLevel = zerolog.InfoLevel
		}
		zerolog.SetGlobalLevel(parsedLevel)
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
		if err != nil {
			log.Warn().Str("requested", level).Msg("unknown log level, defaulting to info")
		}
	})
}

// L returns the global zerolog logger.
func L() *zerolog.Logger {
	return &log.Logger
}
