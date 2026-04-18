package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRouterServesAgentDiscovery(t *testing.T) {
	t.Parallel()

	router := NewRouter(Config{
		OIDCIssuerURL:     "https://issuer.example.com/realms/tunnel",
		OIDCAgentClientID: "agent-client",
	}, stubRegistry{}, nil, nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/agent/config", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response agentDiscoveryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if response.IssuerURL != "https://issuer.example.com/realms/tunnel" {
		t.Fatalf("IssuerURL = %q", response.IssuerURL)
	}
	if response.ClientID != "agent-client" {
		t.Fatalf("ClientID = %q", response.ClientID)
	}
}

func TestNewRouterHealthz(t *testing.T) {
	t.Parallel()

	router := NewRouter(Config{}, stubRegistry{}, nil, nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}
