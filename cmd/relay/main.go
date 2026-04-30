// Package main is the entry point for the relay server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/valkey-io/valkey-go"

	"github.com/lwj5/bridgertun/internal/api"
	"github.com/lwj5/bridgertun/internal/auth"
	"github.com/lwj5/bridgertun/internal/log"
	"github.com/lwj5/bridgertun/internal/registry"
	wspkg "github.com/lwj5/bridgertun/internal/ws"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		panic(err)
	}
	log.Init(cfg.LogLevel)
	log.L().Info().Str("node", cfg.NodeID).Msg("starting relay")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	verifier, err := auth.NewVerifier(ctx, cfg.OIDCIssuerURL, cfg.OIDCAudience)
	if err != nil {
		log.L().Fatal().Err(err).Msg("oidc verifier")
	}

	valkeyOption := valkey.ClientOption{
		InitAddress: []string{cfg.ValkeyAddr},
		Password:    cfg.ValkeyPassword,
		SelectDB:    cfg.ValkeyDB,
	}
	if cfg.ValkeyTLS {
		valkeyOption.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	valkeyClient, err := valkey.NewClient(valkeyOption)
	if err != nil {
		log.L().Fatal().Err(err).Msg("valkey client")
	}
	defer valkeyClient.Close()

	sessionRegistry, err := registry.NewValkeyRegistry(
		ctx, valkeyClient, cfg.NodeID, cfg.ResumeGraceTTL,
	)
	if err != nil {
		log.L().Fatal().Err(err).Msg("registry init")
	}
	defer func() {
		if err := sessionRegistry.Close(); err != nil {
			log.L().Warn().Err(err).Msg("registry close")
		}
	}()

	// WS listener
	webSocketMux := chi.NewRouter()
	webSocketHandler := wspkg.NewHandler(wspkg.HandlerConfig{
		AllowedOrigins:    cfg.AllowedOrigins,
		PingInterval:      cfg.WSPingInterval,
		PongTimeout:       cfg.WSPongTimeout,
		StreamIdleTimeout: cfg.StreamIdleTimeout,
	}, verifier, sessionRegistry, cfg.PublicBaseURL)
	webSocketMux.Handle("/v1/agent/connect", webSocketHandler)
	webSocketMux.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	webSocketServer := &http.Server{
		Addr:              cfg.WSAddr,
		Handler:           webSocketMux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       0,
	}

	// Public API listener
	apiServer := &http.Server{
		Addr: cfg.APIAddr,
		Handler: api.NewRouter(api.Config{
			OIDCIssuerURL:       cfg.OIDCIssuerURL,
			OIDCAgentClientID:   cfg.OIDCAgentClientID,
			MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
			TrustedProxies:      cfg.TrustedProxies,
			StreamIdleTimeout:   cfg.StreamIdleTimeout,
		}, sessionRegistry, verifier, valkeyClient),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go serve(&wg, webSocketServer, "ws", cfg.TLSCertFile, cfg.TLSKeyFile)
	go serve(&wg, apiServer, "api", cfg.TLSCertFile, cfg.TLSKeyFile)

	<-ctx.Done()
	log.L().Info().Msg("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownDrain)
	defer cancel()
	if err := webSocketServer.Shutdown(shutdownCtx); err != nil {
		log.L().Warn().Err(err).Msg("ws server shutdown")
	}
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.L().Warn().Err(err).Msg("api server shutdown")
	}
	wg.Wait()
	log.L().Info().Msg("relay stopped")
}

func serve(wg *sync.WaitGroup, server *http.Server, name, cert, key string) {
	defer wg.Done()
	log.L().Info().Str("server", name).Str("addr", server.Addr).Msg("listening")
	var err error
	if cert != "" && key != "" {
		err = server.ListenAndServeTLS(cert, key)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.L().Error().Err(err).Str("server", name).Msg("server exited")
	}
}
