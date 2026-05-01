// Package main is the entry point for the agent binary.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alexflint/go-arg"
)

const (
	relayConfigPath  = "/v1/agent/config"
	relayConnectPath = "/v1/agent/connect"
)

// agentArgs holds the CLI arguments parsed by go-arg. Field tags supply long
// and short flags, env-var fallbacks, and --help text in one place.
type agentArgs struct {
	RelayURL string `arg:"-r,--relay-url,required,env:RELAY_URL" help:"Relay base URL, e.g. https://relay.example.com"`
	LocalURL string `arg:"-l,--local-url,required,env:LOCAL_URL" help:"Base URL of the local HTTP service to expose"`
	LogLevel string `arg:"-v,--log-level,env:LOG_LEVEL" default:"info" help:"Log level: debug, info, warn, error"`
	JSONLogs bool   `arg:"--json-logs,env:JSON_LOGS" help:"Emit structured JSON logs instead of the default console logs"`
}

type agentConfig struct {
	RelayWSURL      string
	LocalServiceURL string

	OIDCIssuerURL        string
	OIDCClientID         string
	OIDCClientSecret     string
	OIDCAudience         string
	OIDCDeviceScope      string
	OIDCDevicePoll       time.Duration
	OIDCTokenRefreshSkew time.Duration

	BcryptCost int

	LogLevel string
	JSONLogs bool

	ReconnectMaxBackoff  time.Duration
	ReconnectStableReset time.Duration

	ChunkSizeBytes int
	SendBuffer     int
}

type relayDiscovery struct {
	IssuerURL string `json:"issuer_url"`
	ClientID  string `json:"client_id"`
}

func loadConfig(ctx context.Context, httpClient *http.Client, rawArgs []string) (*agentConfig, error) {
	var parsed agentArgs
	parser, err := arg.NewParser(arg.Config{Program: "agent"}, &parsed)
	if err != nil {
		return nil, fmt.Errorf("init arg parser: %w", err)
	}
	if err := parser.Parse(rawArgs); err != nil {
		return nil, fmt.Errorf("parse args: %w", err)
	}

	relayWSURL, err := deriveRelayWSURL(parsed.RelayURL)
	if err != nil {
		return nil, err
	}

	discovery, err := fetchRelayDiscovery(ctx, httpClient, parsed.RelayURL)
	if err != nil {
		return nil, fmt.Errorf("relay discovery: %w", err)
	}

	return &agentConfig{
		RelayWSURL:           relayWSURL,
		LocalServiceURL:      parsed.LocalURL,
		OIDCIssuerURL:        discovery.IssuerURL,
		OIDCClientID:         discovery.ClientID,
		OIDCClientSecret:     "",
		OIDCAudience:         "",
		OIDCDeviceScope:      "openid profile offline_access",
		OIDCDevicePoll:       5 * time.Second,
		OIDCTokenRefreshSkew: 30 * time.Second,
		BcryptCost:           10,
		LogLevel:             parsed.LogLevel,
		JSONLogs:             parsed.JSONLogs,
		ReconnectMaxBackoff:  60 * time.Second,
		ReconnectStableReset: 60 * time.Second,
		ChunkSizeBytes:       32 * 1024,
		SendBuffer:           64,
	}, nil
}

func deriveRelayWSURL(base string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse --relay-url: %w", err)
	}
	switch parsed.Scheme {
	case "https":
		parsed.Scheme = "wss"
	case "http":
		parsed.Scheme = "ws"
	default:
		return "", fmt.Errorf("--relay-url scheme must be http or https, got %q", parsed.Scheme)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + relayConnectPath
	return parsed.String(), nil
}

func fetchRelayDiscovery(ctx context.Context, client *http.Client, base string) (*relayDiscovery, error) {
	discoveryURL := strings.TrimRight(base, "/") + relayConfigPath

	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build discovery request: %w", err)
	}

	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("discovery request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from relay", response.StatusCode)
	}

	var discovery relayDiscovery
	if err := json.NewDecoder(response.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("decode discovery response: %w", err)
	}
	if discovery.IssuerURL == "" || discovery.ClientID == "" {
		return nil, fmt.Errorf("relay returned incomplete discovery (missing issuer_url or client_id)")
	}

	return &discovery, nil
}
