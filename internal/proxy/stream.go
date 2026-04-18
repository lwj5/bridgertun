// Package proxy manages in-flight HTTP streams multiplexed over a WebSocket.
package proxy

import (
	"errors"
	"sync"

	"github.com/lwj5/bridgertun/internal/log"
	"github.com/lwj5/bridgertun/internal/wire"
)

// Sentinel errors returned by stream operations.
var (
	ErrConnGone       = errors.New("tunnel connection gone")
	ErrStreamCanceled = errors.New("stream canceled")
)

// chunkBufferSize bounds buffered response chunks. Sized to absorb short
// bursts (e.g. SSE event flurries) without blocking the WS read loop, while
// keeping per-stream memory bounded.
const chunkBufferSize = 32

// Stream represents a single in-flight HTTP exchange proxied over the tunnel.
type Stream struct {
	ID     string
	Head   chan *wire.Envelope
	Chunks chan *wire.Envelope

	cancel func()

	closeOnce sync.Once
	closed    chan struct{}

	// sendMu serializes Close (write lock) with concurrent Deliver/Fail
	// (read lock) so the channel-close in Close cannot race a send.
	sendMu sync.RWMutex
}

// NewStream creates a Stream with the given correlation ID and cancellation function.
func NewStream(id string, cancel func()) *Stream {
	return &Stream{
		ID:     id,
		Head:   make(chan *wire.Envelope, 1),
		Chunks: make(chan *wire.Envelope, chunkBufferSize),
		cancel: cancel,
		closed: make(chan struct{}),
	}
}

// Cancel invokes the stream's context cancellation function.
func (s *Stream) Cancel() {
	if s.cancel != nil {
		s.cancel()
	}
}

// HeadCh returns the channel that receives the single response_head envelope.
func (s *Stream) HeadCh() <-chan *wire.Envelope { return s.Head }

// ChunksCh returns the channel that receives response_chunk / response_end / error envelopes.
func (s *Stream) ChunksCh() <-chan *wire.Envelope { return s.Chunks }

// Deliver pushes an envelope to the appropriate channel. Sends block to
// provide natural backpressure into the WS read loop; the closed channel
// always wins so Close cannot deadlock with a stuck consumer.
func (s *Stream) Deliver(envelope *wire.Envelope) {
	s.sendMu.RLock()
	select {
	case <-s.closed:
		s.sendMu.RUnlock()
		return
	default:
	}
	var target chan *wire.Envelope
	switch envelope.Type {
	case wire.TypeResponseHead:
		target = s.Head
	case wire.TypeResponseChunk, wire.TypeResponseEnd, wire.TypeError:
		target = s.Chunks
	default:
		s.sendMu.RUnlock()
		return
	}
	select {
	case target <- envelope:
	case <-s.closed:
	}
	s.sendMu.RUnlock()
	if envelope.IsTerminal() {
		s.Close()
	}
}

// Close shuts down the stream, closing all delivery channels exactly once.
// Close blocks until any concurrent Deliver/Fail have returned, so the
// channel-close cannot race an in-flight send.
func (s *Stream) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.sendMu.Lock()
		close(s.Chunks)
		close(s.Head)
		s.sendMu.Unlock()
	})
}

// Fail delivers a synthetic error envelope, then closes. If the chunk buffer
// is full (consumer wedged), the error is logged rather than dropped silently.
func (s *Stream) Fail(err error) {
	s.sendMu.RLock()
	select {
	case <-s.closed:
		s.sendMu.RUnlock()
		return
	default:
	}
	envelope := &wire.Envelope{ID: s.ID, Type: wire.TypeError, Error: err.Error()}
	select {
	case s.Chunks <- envelope:
	case <-s.closed:
	default:
		log.L().Warn().Str("stream", s.ID).Err(err).Msg("fail: chunks buffer full, error envelope dropped")
	}
	s.sendMu.RUnlock()
	s.Close()
}

// Registry tracks in-flight streams on a single WS connection.
type Registry struct {
	mu      sync.RWMutex
	streams map[string]*Stream
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{streams: make(map[string]*Stream)}
}

// Add registers a stream in the registry, keyed by its ID.
func (r *Registry) Add(s *Stream) {
	r.mu.Lock()
	r.streams[s.ID] = s
	r.mu.Unlock()
}

// Get retrieves the stream with the given ID, returning false if not found.
func (r *Registry) Get(id string) (*Stream, bool) {
	r.mu.RLock()
	s, ok := r.streams[id]
	r.mu.RUnlock()
	return s, ok
}

// Remove deletes the stream with the given ID from the registry.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	delete(r.streams, id)
	r.mu.Unlock()
}

// CloseAll terminates every tracked stream with the provided error.
func (r *Registry) CloseAll(err error) {
	r.mu.Lock()
	streams := r.streams
	r.streams = make(map[string]*Stream)
	r.mu.Unlock()
	for _, s := range streams {
		s.Fail(err)
	}
}
