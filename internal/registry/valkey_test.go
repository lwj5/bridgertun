package registry

import (
	"context"
	"testing"

	"github.com/lwj5/bridgertun/internal/proxy"
	"github.com/lwj5/bridgertun/internal/wire"
)

type stubLocalSender struct {
	closeReason string
	done        chan struct{}
}

func (s *stubLocalSender) OpenStream(context.Context, *wire.Envelope) (*proxy.Stream, error) {
	return nil, nil
}

func (s *stubLocalSender) Close(reason string) {
	s.closeReason = reason
}

func (s *stubLocalSender) Done() <-chan struct{} {
	if s.done == nil {
		s.done = make(chan struct{})
		close(s.done)
	}
	return s.done
}

func TestValkeyRegistryHandleCtrlCancelInvokesPendingCancel(t *testing.T) {
	t.Parallel()

	registry := &ValkeyRegistry{}
	called := false
	registry.pendingCtx.Store("request-1", context.CancelFunc(func() { called = true }))

	registry.handleCtrl(context.Background(), &ctrlMessage{Type: ctrlTypeCancel, RequestID: "request-1"})

	if !called {
		t.Fatal("cancel func was not invoked")
	}
	if _, ok := registry.pendingCtx.Load("request-1"); ok {
		t.Fatal("pendingCtx entry should be removed after cancel")
	}
}

func TestValkeyRegistryHandleCtrlCloseClosesLocalSender(t *testing.T) {
	t.Parallel()

	sender := &stubLocalSender{}
	registry := &ValkeyRegistry{locals: map[string]*localEntry{
		"session-1": {sender: sender},
	}}

	registry.handleCtrl(context.Background(), &ctrlMessage{Type: ctrlTypeClose, SessionID: "session-1"})

	if sender.closeReason != "forced by remote" {
		t.Fatalf("closeReason = %q, want %q", sender.closeReason, "forced by remote")
	}
}

func TestValkeyKeyHelpers(t *testing.T) {
	t.Parallel()

	if got := sessionKey("abc"); got != "session:abc" {
		t.Fatalf("sessionKey() = %q, want %q", got, "session:abc")
	}
	if got := bySubjectKey("sub-1"); got != "sessions:by-sub:sub-1" {
		t.Fatalf("bySubjectKey() = %q, want %q", got, "sessions:by-sub:sub-1")
	}
}
