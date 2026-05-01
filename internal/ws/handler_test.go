package ws

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/lwj5/bridgertun/internal/auth"
	"github.com/lwj5/bridgertun/internal/proxy"
	"github.com/lwj5/bridgertun/internal/registry"
	"github.com/lwj5/bridgertun/internal/wire"
)

type handlerRegistryStub struct {
	lookupFunc     func(ctx context.Context, sessionID string) (*registry.SessionInfo, error)
	forceCloseFunc func(ctx context.Context, sessionID string) error
}

func (s handlerRegistryStub) Register(context.Context, *registry.SessionInfo, registry.LocalSender) error {
	panic("unexpected Register call")
}

func (s handlerRegistryStub) Unregister(context.Context, string) error {
	panic("unexpected Unregister call")
}

func (s handlerRegistryStub) Detach(context.Context, string, registry.LocalSender) error {
	panic("unexpected Detach call")
}

//nolint:ireturn // Registry interface requires returning LocalSender.
func (s handlerRegistryStub) LocalSenderFor(string) (registry.LocalSender, bool) {
	return nil, false
}

func (s handlerRegistryStub) Lookup(ctx context.Context, sessionID string) (*registry.SessionInfo, error) {
	if s.lookupFunc == nil {
		panic("unexpected Lookup call")
	}
	return s.lookupFunc(ctx, sessionID)
}

func (s handlerRegistryStub) Dispatch(context.Context, string, *wire.Envelope) (registry.ProxyStream, error) { //nolint:ireturn,lll
	panic("unexpected Dispatch call")
}

func (s handlerRegistryStub) List(context.Context, registry.Filter) ([]*registry.SessionInfo, error) {
	panic("unexpected List call")
}

func (s handlerRegistryStub) ForceClose(ctx context.Context, sessionID string) error {
	if s.forceCloseFunc == nil {
		return nil
	}
	return s.forceCloseFunc(ctx, sessionID)
}

func (s handlerRegistryStub) Close() error { return nil }

var _ registry.Registry = handlerRegistryStub{}
var _ = proxy.ErrConnGone

func TestServeAgentConfig(t *testing.T) {
	t.Parallel()

	handler := NewHandler(HandlerConfig{
		OIDCIssuerURL:     "https://issuer.example.com/realms/tunnel",
		OIDCAgentClientID: "agent-client",
	}, nil, handlerRegistryStub{}, "")

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/agent/config", nil)
	handler.ServeAgentConfig(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
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

func TestResolveSessionIDRejectsInvalidResumeHint(t *testing.T) {
	t.Parallel()

	handler := &Handler{}
	_, _, err := handler.resolveSessionID(context.Background(), "not-a-uuid", &auth.Principal{Subject: "subject-1"})

	var resumeErr *resumeError
	if !errors.As(err, &resumeErr) {
		t.Fatalf("err = %v, want resumeError", err)
	}
	if resumeErr.status != 400 {
		t.Fatalf("resumeErr.status = %d, want 400", resumeErr.status)
	}
}

func TestResolveSessionIDRejectsDifferentPrincipal(t *testing.T) {
	t.Parallel()

	hint := uuid.NewString()
	handler := &Handler{registry: handlerRegistryStub{
		lookupFunc: func(context.Context, string) (*registry.SessionInfo, error) {
			return &registry.SessionInfo{SessionID: hint, Subject: "other-subject"}, nil
		},
	}}

	_, _, err := handler.resolveSessionID(context.Background(), hint, &auth.Principal{Subject: "subject-1"})

	var resumeErr *resumeError
	if !errors.As(err, &resumeErr) {
		t.Fatalf("err = %v, want resumeError", err)
	}
	if resumeErr.status != 403 {
		t.Fatalf("resumeErr.status = %d, want 403", resumeErr.status)
	}
}

func TestResolveSessionIDReturnsExistingDetachedSessionForSamePrincipal(t *testing.T) {
	t.Parallel()

	hint := uuid.NewString()
	handler := &Handler{registry: handlerRegistryStub{
		lookupFunc: func(context.Context, string) (*registry.SessionInfo, error) {
			return &registry.SessionInfo{SessionID: hint, Subject: "subject-1", State: registry.SessionStateDetached}, nil
		},
	}}

	sessionID, resumed, err := handler.resolveSessionID(context.Background(), hint, &auth.Principal{Subject: "subject-1"})
	if err != nil {
		t.Fatalf("resolveSessionID() error = %v", err)
	}
	if !resumed {
		t.Fatal("resumed = false, want true")
	}
	if sessionID != hint {
		t.Fatalf("sessionID = %q, want %q", sessionID, hint)
	}
}
