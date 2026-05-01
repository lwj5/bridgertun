package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/lwj5/bridgertun/internal/agent"
	"github.com/lwj5/bridgertun/internal/logutil"
)

var randomFloat64 = rand.Float64

const startupBanner = `
 ____       _     _                 _
| __ ) _ __(_) __| | __ _  ___ _ __| |_ _   _ _ __
|  _ \\| '__| |/ _  |/ _  |/ _ \\ '__| __| | | | '_ \\
| |_) | |  | | (_| | (_| |  __/ |  | |_| |_| | | | |
|____/|_|  |_|\\__,_|\\__, |\\___|_|   \\__|\\__,_|_| |_|
					 |___/

	_                    _
   / \\   __ _  ___ _ __ | |_
  / _ \\ / _  |/ _ \\ '_ \\| __|
 / ___ \\ (_| |  __/ | | | |_
/_/   \\_\\__, |\\___|_| |_|\\__|
		  |___/
`

func newOIDCTokenSource(ctx context.Context, cfg *agentConfig) (agent.TokenSource, error) { //nolint:ireturn
	return agent.NewOIDCTokenSource(ctx, agent.OIDCConfig{ //nolint:wrapcheck
		IssuerURL:        cfg.OIDCIssuerURL,
		ClientID:         cfg.OIDCClientID,
		ClientSecret:     cfg.OIDCClientSecret,
		Audience:         cfg.OIDCAudience,
		DeviceScope:      cfg.OIDCDeviceScope,
		DevicePoll:       cfg.OIDCDevicePoll,
		TokenRefreshSkew: cfg.OIDCTokenRefreshSkew,
	})
}

func runSession(
	ctx context.Context, cfg *agentConfig, state *agent.ResumeState, auth agent.TokenSource,
) (time.Duration, error) {
	return agent.RunSession(ctx, agent.SessionConfig{ //nolint:wrapcheck
		RelayWSURL:      cfg.RelayWSURL,
		LocalServiceURL: cfg.LocalServiceURL,
		BcryptCost:      cfg.BcryptCost,
		SendBuffer:      cfg.SendBuffer,
		ChunkSizeBytes:  cfg.ChunkSizeBytes,
	}, state, auth)
}

func main() {
	cfg, err := loadConfig(context.Background(), http.DefaultClient, os.Args[1:])
	if err != nil {
		_, _ = os.Stderr.WriteString("agent config: " + err.Error() + "\n")
		os.Exit(2)
	}
	if cfg.JSONLogs {
		logutil.Init(cfg.LogLevel)
	} else {
		logutil.InitConsole(cfg.LogLevel)
	}
	_, _ = fmt.Fprint(os.Stdout, startupBanner)
	log.Info().
		Str("relay", cfg.RelayWSURL).
		Str("local", cfg.LocalServiceURL).
		Msg("starting agent")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	authSource, err := newOIDCTokenSource(ctx, cfg)
	if err != nil {
		stop()
		log.Fatal().Err(err).Msg("initialize oidc auth")
	}
	defer stop()

	// Resume state is kept across reconnect attempts so the agent can ask the
	// relay to resume the same session ID (preserving the tunnel URL and
	// operator tokens) after a network blip. An empty state.sessionID on the
	// first iteration means "fresh session".
	state := &agent.ResumeState{}

	attempt := 0
	for ctx.Err() == nil {
		sessionDuration, err := runSession(ctx, cfg, state, authSource)
		if err != nil {
			if errors.Is(err, agent.ErrRelayAuthRejected) {
				log.Warn().Err(err).Dur("session_dur", sessionDuration).Msg("session auth rejected; token invalidated")
			} else {
				log.Warn().Err(err).Dur("session_dur", sessionDuration).Msg("session ended")
			}
		} else {
			log.Info().Dur("session_dur", sessionDuration).Msg("session ended")
		}

		if ctx.Err() != nil {
			break
		}

		if sessionDuration >= cfg.ReconnectStableReset {
			attempt = 0
		}
		wait := backoff(attempt, cfg.ReconnectMaxBackoff)
		attempt++
		log.Info().Dur("wait", wait).Int("attempt", attempt).Msg("reconnecting")

		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	log.Info().Msg("agent stopped")
}

// backoff returns min(2^attempt, maxWait) with ±25% jitter.
func backoff(attempt int, maxWait time.Duration) time.Duration {
	base := time.Second << uint(attempt) //nolint:gosec // attempt is bounded by the cap below.
	if base <= 0 || base > maxWait {
		base = maxWait
	}
	jitter := float64(base) * 0.25
	//nolint:gosec // jitter is not security-sensitive and is overridable for tests.
	delta := (randomFloat64()*2 - 1) * jitter
	wait := base + time.Duration(delta)
	if wait < 0 {
		return 0
	}
	if wait > maxWait {
		return maxWait
	}
	return wait
}
