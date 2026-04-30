// Package ws manages WebSocket connections for authenticated agent sessions.
package ws

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/lwj5/bridgertun/internal/auth"
	"github.com/lwj5/bridgertun/internal/log"
	"github.com/lwj5/bridgertun/internal/proxy"
	"github.com/lwj5/bridgertun/internal/wire"
)

// Connection wraps a WebSocket connection for a single authenticated agent session.
type Connection struct {
	SessionID string
	Principal *auth.Principal

	webSocketConn *websocket.Conn
	streams       *proxy.Registry

	sendCh chan *wire.Envelope
	done   chan struct{}
	once   sync.Once

	pingInterval time.Duration
	pongTimeout  time.Duration
	idleTimeout  time.Duration
}

// ConnectionOptions configures per-connection timing behaviour.
type ConnectionOptions struct {
	PingInterval time.Duration
	PongTimeout  time.Duration
	IdleTimeout  time.Duration
}

// NewConnection creates a Connection ready for use; call Run to start pumping frames.
func NewConnection(
	sessionID string,
	principal *auth.Principal,
	webSocketConn *websocket.Conn,
	opts ConnectionOptions,
) *Connection {
	return &Connection{
		SessionID:     sessionID,
		Principal:     principal,
		webSocketConn: webSocketConn,
		streams:       proxy.NewRegistry(),
		sendCh:        make(chan *wire.Envelope, 64),
		done:          make(chan struct{}),
		pingInterval:  opts.PingInterval,
		pongTimeout:   opts.PongTimeout,
		idleTimeout:   opts.IdleTimeout,
	}
}

// Done returns a channel that is closed when the connection has terminated.
func (c *Connection) Done() <-chan struct{} { return c.done }

// Run spawns read/write/heartbeat goroutines and blocks until the connection closes.
func (c *Connection) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go c.writePump(ctx, &wg)
	go c.readPump(ctx, cancel, &wg)
	wg.Wait()

	c.close(errors.New("connection closed"))
}

// Send enqueues an envelope for delivery to the agent. It blocks only if the
// send channel is full, which provides backpressure.
func (c *Connection) Send(ctx context.Context, envelope *wire.Envelope) error {
	select {
	case c.sendCh <- envelope:
		return nil
	case <-c.done:
		return proxy.ErrConnGone
	case <-ctx.Done():
		return fmt.Errorf("send canceled: %w", ctx.Err())
	}
}

// OpenStream sends a request envelope and returns a Stream the caller can use
// to read the response_head then chunks.
func (c *Connection) OpenStream(ctx context.Context, envelope *wire.Envelope) (*proxy.Stream, error) {
	if envelope.ID == "" {
		envelope.ID = uuid.NewString()
	}
	envelope.Type = wire.TypeRequest

	stream := proxy.NewStream(envelope.ID, func() {
		c.sendCancel(envelope.ID)
		c.streams.Remove(envelope.ID)
	})
	c.streams.Add(stream)

	if err := c.Send(ctx, envelope); err != nil {
		c.streams.Remove(envelope.ID)
		stream.Fail(err)
		return nil, err
	}
	return stream, nil
}

func (c *Connection) sendCancel(requestID string) {
	envelope := &wire.Envelope{ID: requestID, Type: wire.TypeRequestCancel}
	select {
	case c.sendCh <- envelope:
		return
	case <-c.done:
		return
	default:
	}
	// Buffer is briefly full. Wait a short while so the cancel isn't dropped —
	// a missed cancel leaves the agent running work the relay abandoned.
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case c.sendCh <- envelope:
	case <-c.done:
	case <-timer.C:
		log.L().Warn().Str("session", c.SessionID).Str("requestID", requestID).Msg("cancel dropped: send buffer full")
	}
}

func (c *Connection) writePump(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case envelope := <-c.sendCh:
			payload, err := wire.Encode(envelope)
			if err != nil {
				log.L().Error().Err(err).Str("session", c.SessionID).Msg("encode envelope")
				continue
			}
			writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = c.webSocketConn.Write(writeCtx, websocket.MessageBinary, payload)
			cancel()
			if err != nil {
				log.L().Warn().Err(err).Str("session", c.SessionID).Msg("ws write")
				return
			}
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, c.pongTimeout)
			err := c.webSocketConn.Ping(pingCtx)
			cancel()
			if err != nil {
				log.L().Warn().Err(err).Str("session", c.SessionID).Msg("ws ping failed")
				return
			}
		}
	}
}

func (c *Connection) readPump(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup) {
	defer wg.Done()
	defer cancel()

	// Allow 16 MiB per frame for large SSE events.
	c.webSocketConn.SetReadLimit(16 * 1024 * 1024)

	for {
		messageType, data, err := c.webSocketConn.Read(ctx)
		if err != nil {
			log.L().Info().Err(err).Str("session", c.SessionID).Msg("ws read closed")
			return
		}
		if messageType != websocket.MessageBinary {
			continue
		}
		envelope, err := wire.Decode(data)
		if err != nil {
			log.L().Warn().Err(err).Str("session", c.SessionID).Msg("decode envelope")
			continue
		}
		c.dispatch(envelope)
	}
}

func (c *Connection) dispatch(envelope *wire.Envelope) {
	switch envelope.Type {
	case wire.TypePong:
		// handled by read deadline / ping keepalive
	case wire.TypeResponseHead, wire.TypeResponseChunk, wire.TypeResponseEnd, wire.TypeError:
		stream, ok := c.streams.Get(envelope.ID)
		if !ok {
			return
		}
		// Deliver runs synchronously to preserve chunk ordering for this
		// stream. The 32-slot Chunks buffer absorbs short bursts; a fully
		// wedged consumer will back-pressure the read loop until ping
		// timeout terminates the connection.
		stream.Deliver(envelope)
		if envelope.IsTerminal() {
			c.streams.Remove(envelope.ID)
		}
	default:
		log.L().Debug().Str("type", envelope.Type).Str("session", c.SessionID).Msg("unhandled envelope")
	}
}

func (c *Connection) close(err error) {
	c.once.Do(func() {
		close(c.done)
		c.streams.CloseAll(err)
		_ = c.webSocketConn.Close(websocket.StatusNormalClosure, "closing")
	})
}

// Close forces the connection and all streams down.
func (c *Connection) Close(reason string) {
	c.close(fmt.Errorf("%s", reason))
}
