package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testIssuerURL = "http://localhost:8080/realms/tunnel"
	testClientID  = "tunnel-agent"
	testLocalURL  = "http://127.0.0.1:3000"
	flagRelayURL  = "--relay-url"
	flagLocalURL  = "--local-url"
)

func newDiscoveryServer(t *testing.T, d relayDiscovery) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != relayConfigPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d)
	}))
}

func TestLoadConfigValid(t *testing.T) {
	server := newDiscoveryServer(t, relayDiscovery{
		IssuerURL: testIssuerURL,
		ClientID:  testClientID,
	})
	defer server.Close()

	cfg, err := loadConfig(context.Background(), server.Client(), []string{
		flagRelayURL, server.URL,
		flagLocalURL, testLocalURL,
	})
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.OIDCDeviceScope == "" {
		t.Fatalf("OIDCDeviceScope must have a default")
	}
	if cfg.OIDCIssuerURL != testIssuerURL {
		t.Fatalf("unexpected issuer URL: %q", cfg.OIDCIssuerURL)
	}
	if !strings.HasSuffix(cfg.RelayWSURL, relayConnectPath) {
		t.Fatalf("RelayWSURL should end with %q, got %q", relayConnectPath, cfg.RelayWSURL)
	}
}

func TestLoadConfigMissingRequired(t *testing.T) {
	_, err := loadConfig(context.Background(), http.DefaultClient, []string{})
	if err == nil {
		t.Fatal("loadConfig() expected error when required flags are missing")
	}
	// go-arg reports missing required arguments; check the presence of the
	// flag name rather than the exact phrasing so the test is not brittle.
	if !strings.Contains(err.Error(), "relay-url") && !strings.Contains(err.Error(), "RELAY_URL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfigLogLevelDefault(t *testing.T) {
	server := newDiscoveryServer(t, relayDiscovery{
		IssuerURL: testIssuerURL,
		ClientID:  testClientID,
	})
	defer server.Close()

	cfg, err := loadConfig(context.Background(), server.Client(), []string{
		flagRelayURL, server.URL,
		flagLocalURL, testLocalURL,
	})
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("expected default log level 'info', got %q", cfg.LogLevel)
	}
	if cfg.JSONLogs {
		t.Fatal("expected JSON logs to default to false")
	}
}

func TestLoadConfigLogLevelOverride(t *testing.T) {
	server := newDiscoveryServer(t, relayDiscovery{
		IssuerURL: testIssuerURL,
		ClientID:  testClientID,
	})
	defer server.Close()

	cfg, err := loadConfig(context.Background(), server.Client(), []string{
		flagRelayURL, server.URL,
		flagLocalURL, testLocalURL,
		"--log-level", "debug",
	})
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("expected log level 'debug', got %q", cfg.LogLevel)
	}
}

func TestLoadConfigJSONLogsOverride(t *testing.T) {
	server := newDiscoveryServer(t, relayDiscovery{
		IssuerURL: testIssuerURL,
		ClientID:  testClientID,
	})
	defer server.Close()

	cfg, err := loadConfig(context.Background(), server.Client(), []string{
		flagRelayURL, server.URL,
		flagLocalURL, testLocalURL,
		"--json-logs",
	})
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !cfg.JSONLogs {
		t.Fatal("expected JSON logs to be enabled")
	}
}

func TestDeriveRelayWSURL(t *testing.T) {
	cases := []struct {
		base    string
		want    string
		wantErr bool
	}{
		{"https://relay.example.com", "wss://relay.example.com/v1/agent/connect", false},
		{"http://relay.example.com", "ws://relay.example.com/v1/agent/connect", false},
		{"https://relay.example.com/prefix", "wss://relay.example.com/prefix/v1/agent/connect", false},
		{"ftp://relay.example.com", "", true},
	}
	for _, tc := range cases {
		got, err := deriveRelayWSURL(tc.base)
		if tc.wantErr {
			if err == nil {
				t.Errorf("deriveRelayWSURL(%q): expected error", tc.base)
			}
			continue
		}
		if err != nil {
			t.Errorf("deriveRelayWSURL(%q): unexpected error: %v", tc.base, err)
			continue
		}
		if got != tc.want {
			t.Errorf("deriveRelayWSURL(%q) = %q, want %q", tc.base, got, tc.want)
		}
	}
}
