// Package registry manages agent session state across relay nodes.
package registry

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/lwj5/bridgertun/internal/proxy"
	"github.com/lwj5/bridgertun/internal/wire"
)

var (
	// ErrNotFound is returned when the requested session does not exist in the registry.
	ErrNotFound = errors.New("session not found")
	// ErrUnavailable is returned when the registry backend is unreachable.
	ErrUnavailable = errors.New("registry unavailable")
)

// Session states persisted in SessionInfo.State.
const (
	// SessionStateActive means the owning node currently holds a live WebSocket.
	SessionStateActive = "active"
	// SessionStateDetached means the WebSocket has closed but the record is kept
	// around for the resume grace window so the agent can reconnect with the
	// same session ID.
	SessionStateDetached = "detached"
)

// SessionInfo is the persisted metadata about an agent session.
type SessionInfo struct {
	SessionID      string    `json:"session_id"`
	NodeID         string    `json:"node_id"`
	Subject        string    `json:"sub"`
	Username       string    `json:"username,omitempty"`
	Tenant         string    `json:"tenant,omitempty"`
	ConnectedAt    time.Time `json:"connected_at"`
	TunnelAuthHash string    `json:"tunnel_auth_hash,omitempty"`
	State          string    `json:"state,omitempty"`
}

// LocalSender is implemented by things that own a live WebSocket to an agent
// (e.g. *ws.Connection). Registered at session start, looked up on local
// dispatch.
type LocalSender interface {
	OpenStream(ctx context.Context, envelope *wire.Envelope) (*proxy.Stream, error)
	Close(reason string)
	// Done is closed once the underlying connection has fully torn down.
	// Used by the resume path to wait for an evicted local owner before
	// the new connection re-registers.
	Done() <-chan struct{}
}

// ProxyStream is what the API handler consumes regardless of whether the
// target session lives locally or on another node.
type ProxyStream interface {
	io.Closer
	// Receive returns the next envelope in the stream (head, chunk, or terminal).
	// Returns io.EOF after a terminal envelope has been consumed.
	Receive(ctx context.Context) (*wire.Envelope, error)
	// Cancel propagates a cancellation upstream so the agent can abort the
	// local HTTP request.
	Cancel()
}

// Registry is the facade exposed to the WS handler and API.
type Registry interface {
	// Register records a local session and persists its metadata so remote
	// nodes can route to it.
	Register(ctx context.Context, info *SessionInfo, sender LocalSender) error
	// Unregister removes local + persisted records for a session.
	Unregister(ctx context.Context, sessionID string) error
	// Detach marks a session as disconnected without deleting its persisted
	// record. The session row remains in the registry for the TTL grace
	// window so the agent can reconnect and resume with the same ID.
	// sender must be the LocalSender that was passed to Register; the
	// registry will skip the cleanup if a newer sender has already taken
	// over the session (same-node resume race guard).
	Detach(ctx context.Context, sessionID string, sender LocalSender) error
	// LocalSenderFor returns the LocalSender currently held for a session on
	// this node, if any. Used by the resume path to wait on the prior
	// owner's Done() channel before re-registering.
	LocalSenderFor(sessionID string) (LocalSender, bool)
	// Lookup returns the persisted metadata for a session.
	Lookup(ctx context.Context, sessionID string) (*SessionInfo, error)
	// Dispatch opens a proxy stream to the target session. It resolves to a
	// local sender if the session is owned by this node, else it routes via
	// Valkey to the owning node.
	Dispatch(ctx context.Context, sessionID string, envelope *wire.Envelope) (ProxyStream, error)
	// List returns metadata for sessions matching the filter (prefix match on sub/tenant).
	List(ctx context.Context, filter Filter) ([]*SessionInfo, error)
	// ForceClose closes the session (locally or via pubsub to the owning node).
	ForceClose(ctx context.Context, sessionID string) error
	// Close tears down registry resources.
	Close() error
}

// Filter restricts session listing to sessions owned by a given subject or tenant.
type Filter struct {
	Subject string
	Tenant  string
}
