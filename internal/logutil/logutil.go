// Package logutil configures the global zerolog logger.
package logutil

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var initOnce sync.Once

// Init configures the global zerolog logger with the given level. It writes
// JSON to stderr and is intended to be called exactly once at process start;
// subsequent calls are no-ops to avoid racing with goroutines that already
// hold a reference to the global logger.
func Init(level string) {
	initLogger(level, false)
}

// InitConsole configures the global zerolog logger for human-readable console
// output. It is intended for interactive binaries like the reference agent.
func InitConsole(level string) {
	initLogger(level, true)
}

func initLogger(level string, useConsole bool) {
	initOnce.Do(func() {
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
		parsedLevel, err := zerolog.ParseLevel(strings.ToLower(level))
		if err != nil {
			parsedLevel = zerolog.InfoLevel
		}
		zerolog.SetGlobalLevel(parsedLevel)

		loggerOutput := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339} //nolint:exhaustruct
		if useConsole {
			log.Logger = zerolog.New(loggerOutput).
				Level(parsedLevel).
				With().
				Timestamp().
				Caller().
				Logger()
		} else {
			log.Logger = zerolog.New(os.Stderr).Level(parsedLevel).With().Timestamp().Logger()
		}
		if err != nil {
			log.Warn().Str("requested", level).Msg("unknown log level, defaulting to info")
		}
	})
}
