package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lwj5/bridgertun/internal/registry"
	"github.com/lwj5/bridgertun/internal/wire"
)

type stubRegistry struct {
	listFunc func(ctx context.Context, filter registry.Filter) ([]*registry.SessionInfo, error)
}

func (s stubRegistry) Register(context.Context, *registry.SessionInfo, registry.LocalSender) error {
	panic("unexpected Register call")
}

func (s stubRegistry) Unregister(context.Context, string) error {
	panic("unexpected Unregister call")
}

func (s stubRegistry) Detach(context.Context, string, registry.LocalSender) error {
	panic("unexpected Detach call")
}

//nolint:ireturn // Registry interface requires returning LocalSender.
func (s stubRegistry) LocalSenderFor(string) (registry.LocalSender, bool) {
	return nil, false
}

func (s stubRegistry) Lookup(context.Context, string) (*registry.SessionInfo, error) {
	panic("unexpected Lookup call")
}

func (s stubRegistry) Dispatch(context.Context, string, *wire.Envelope) (registry.ProxyStream, error) { //nolint:ireturn
	panic("unexpected Dispatch call")
}

func (s stubRegistry) List(ctx context.Context, filter registry.Filter) ([]*registry.SessionInfo, error) {
	if s.listFunc == nil {
		panic("unexpected List call")
	}
	return s.listFunc(ctx, filter)
}

func (s stubRegistry) ForceClose(context.Context, string) error {
	panic("unexpected ForceClose call")
}

func (s stubRegistry) Close() error {
	return nil
}

var _ registry.Registry = stubRegistry{}

func TestOperatorListSessionsSkipsNilEntries(t *testing.T) {
	t.Parallel()

	handler := newOperatorHandler(stubRegistry{
		listFunc: func(context.Context, registry.Filter) ([]*registry.SessionInfo, error) {
			return []*registry.SessionInfo{
				nil,
				{
					SessionID:      testSessionID,
					Subject:        "subject-1",
					TunnelAuthHash: "secret-hash",
				},
			}, nil
		},
	}, nil)

	request := httptest.NewRequest(http.MethodGet, "/v1/operator/sessions", nil)
	recorder := httptest.NewRecorder()

	handler.listSessions(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var sessions []registry.SessionInfo
	if err := json.Unmarshal(recorder.Body.Bytes(), &sessions); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("len(sessions) = %d, want 1", len(sessions))
	}
	if sessions[0].SessionID != testSessionID {
		t.Fatalf("sessionID = %q, want %q", sessions[0].SessionID, testSessionID)
	}
	if sessions[0].TunnelAuthHash != "" {
		t.Fatalf("TunnelAuthHash = %q, want redacted empty string", sessions[0].TunnelAuthHash)
	}
}
