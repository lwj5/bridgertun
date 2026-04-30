package ws

import (
	"context"
	"errors"
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

func (s handlerRegistryStub) Detach(context.Context, string) error {
	panic("unexpected Detach call")
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
