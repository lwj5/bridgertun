package registry

import (
	"context"
	"testing"

	"github.com/lwj5/bridgertun/internal/proxy"
	"github.com/lwj5/bridgertun/internal/wire"
)

const testSessionID = "session-1"

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
		testSessionID: {sender: sender},
	}}

	registry.handleCtrl(context.Background(), &ctrlMessage{Type: ctrlTypeClose, SessionID: testSessionID})

	if sender.closeReason != "forced by remote" {
		t.Fatalf("closeReason = %q, want %q", sender.closeReason, "forced by remote")
	}
}

// TestValkeyDetachWithStaleSender exercises the same-node resume race: if a
// new connection has already claimed the local entry, Detach called with the
// old sender must leave the new entry untouched.
func TestValkeyDetachWithStaleSender(t *testing.T) {
	t.Parallel()

	oldSender := &stubLocalSender{}
	newSender := &stubLocalSender{}

	registry := &ValkeyRegistry{
		locals: map[string]*localEntry{
			testSessionID: {sender: newSender},
		},
	}

	// Detach called with the OLD sender must not delete the NEW entry.
	if err := registry.Detach(context.Background(), testSessionID, oldSender); err != nil {
		t.Fatalf("Detach() error = %v", err)
	}
	if _, ok := registry.locals[testSessionID]; !ok {
		t.Fatal("Detach with stale sender deleted the new local entry")
	}
}

// TestValkeyDetachWithMatchingSender verifies that Detach removes the local
// entry and invokes the cancel func when the sender matches.
// info is nil so Detach returns before touching the Valkey client.
func TestValkeyDetachWithMatchingSender(t *testing.T) {
	t.Parallel()

	sender := &stubLocalSender{}
	cancelCalled := false
	registry := &ValkeyRegistry{
		locals: map[string]*localEntry{
			testSessionID: {
				sender: sender,
				cancel: func() { cancelCalled = true },
				info:   nil, // causes early return before any Valkey I/O
			},
		},
	}

	if err := registry.Detach(context.Background(), testSessionID, sender); err != nil {
		t.Fatalf("Detach() error = %v", err)
	}
	if _, ok := registry.locals[testSessionID]; ok {
		t.Fatal("Detach with matching sender did not remove local entry")
	}
	if !cancelCalled {
		t.Fatal("Detach did not invoke the entry cancel func")
	}
}

// TestValkeyLocalSenderFor verifies the helper returns the stored sender.
func TestValkeyLocalSenderFor(t *testing.T) {
	t.Parallel()

	sender := &stubLocalSender{}
	registry := &ValkeyRegistry{
		locals: map[string]*localEntry{
			testSessionID: {sender: sender},
		},
	}

	got, ok := registry.LocalSenderFor(testSessionID)
	if !ok {
		t.Fatal("LocalSenderFor returned false for a known local session")
	}
	if got != sender {
		t.Fatal("LocalSenderFor returned the wrong sender")
	}

	_, ok = registry.LocalSenderFor("unknown")
	if ok {
		t.Fatal("LocalSenderFor returned true for unknown session")
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
