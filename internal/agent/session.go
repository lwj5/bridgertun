package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/lwj5/bridgertun/internal/log"
	"github.com/lwj5/bridgertun/internal/wire"
)

// ErrRelayAuthRejected is returned when the relay rejects the agent's access token.
var ErrRelayAuthRejected = errors.New("relay rejected agent access token")

// SessionConfig holds the parameters required to run an agent session.
type SessionConfig struct {
	RelayWSURL      string
	LocalServiceURL string
	BcryptCost      int
	SendBuffer      int
	ChunkSizeBytes  int
}

// ResumeState carries session identity across reconnects so the agent can ask
// the relay to resume the same session ID (and therefore the same tunnel URL
// and operator tokens) after a network blip.
type ResumeState struct {
	sessionID string
	tokens    *sessionTokens
}

// RunSession opens one WebSocket session, reads hello, multiplexes requests,
// and returns when the connection closes. Returns the wall-clock duration of
// the session so the outer loop can decide whether to reset backoff.
//
// On entry, state may carry identity from a prior session. On successful
// resume, state is left unchanged. If the relay mints a new session (e.g.
// because the grace window expired), state is rewritten with the new ID and
// freshly generated tokens; the caller keeps the updated state for the next
// iteration.
func RunSession(ctx context.Context, cfg SessionConfig, state *ResumeState, auth TokenSource) (time.Duration, error) {
	start := time.Now()

	if state.tokens == nil {
		generated, err := newSessionTokens(cfg.BcryptCost)
		if err != nil {
			return 0, err
		}
		state.tokens = generated
	}
	tokens := state.tokens

	accessToken, err := auth.AccessToken(ctx)
	if err != nil {
		return 0, fmt.Errorf("get access token: %w", err)
	}

	dialURL, err := buildDialURL(cfg.RelayWSURL)
	if err != nil {
		return 0, err
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+accessToken)
	headers.Set("X-Tunnel-Secret-Hash", tokens.RelayTokenHash)
	if state.sessionID != "" {
		headers.Set("X-Tunnel-Resume-Session", state.sessionID)
	}

	webSocketConn, response, err := websocket.Dial(ctx, dialURL, &websocket.DialOptions{
		HTTPHeader:      headers,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if response != nil {
			if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
				auth.Invalidate()
				return time.Since(start), fmt.Errorf("%w (http %d)", ErrRelayAuthRejected, response.StatusCode)
			}
			return time.Since(start), fmt.Errorf("ws dial: %w (http %d)", err, response.StatusCode)
		}
		return time.Since(start), fmt.Errorf("ws dial: %w", err)
	}
	// Match the relay's 16 MiB per-frame cap.
	webSocketConn.SetReadLimit(16 * 1024 * 1024)

	defer func() {
		_ = webSocketConn.Close(websocket.StatusNormalClosure, "closing")
	}()

	// First frame must be hello.
	helloCtx, helloCancel := context.WithTimeout(ctx, 10*time.Second)
	hello, err := readEnvelope(helloCtx, webSocketConn)
	helloCancel()
	if err != nil {
		return time.Since(start), fmt.Errorf("read hello: %w", err)
	}
	if hello.Type != wire.TypeHello {
		return time.Since(start), fmt.Errorf("expected hello, got %q", hello.Type)
	}

	resumed := state.sessionID != "" && hello.ID == state.sessionID
	if !resumed {
		// Either a fresh connect, or a resume hint the relay declined (expired
		// or never existed). Rotate tokens so the operator block we print
		// corresponds to the new session. The relay already associated the
		// current RelayTokenHash with hello.ID server-side.
		if state.sessionID != "" {
			log.L().Info().
				Str("prev_session", state.sessionID).
				Str("new_session", hello.ID).
				Msg("resume declined; new session issued")
		}
		state.sessionID = hello.ID
		printOperatorBlock(hello.ID, hello.TunnelURL, tokens)
	}
	log.L().Info().
		Str("session", hello.ID).
		Str("tunnel_url", hello.TunnelURL).
		Bool("resumed", resumed).
		Msg("agent session established")

	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	sendCh := make(chan *wire.Envelope, cfg.SendBuffer)
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		writerLoop(sessionCtx, webSocketConn, sendCh)
	}()

	// serveWG tracks in-flight serve goroutines; we drain them before
	// closing sendCh so a late trySend cannot panic on a closed channel.
	var serveWG sync.WaitGroup

	var inflightMu sync.Mutex
	inflight := make(map[string]context.CancelFunc)

	registerInflight := func(id string, cancel context.CancelFunc) {
		inflightMu.Lock()
		inflight[id] = cancel
		inflightMu.Unlock()
	}
	cancelInflight := func(id string) {
		inflightMu.Lock()
		cancel, ok := inflight[id]
		delete(inflight, id)
		inflightMu.Unlock()
		if ok {
			cancel()
		}
	}
	cancelAllInflight := func() {
		inflightMu.Lock()
		for id, cancel := range inflight {
			cancel()
			delete(inflight, id)
		}
		inflightMu.Unlock()
	}

	// Read loop.
	var readErr error
	for {
		envelope, err := readEnvelope(sessionCtx, webSocketConn)
		if err != nil {
			readErr = err
			break
		}
		switch envelope.Type {
		case wire.TypeRequest:
			requestCtx, requestCancel := context.WithCancel(sessionCtx)
			registerInflight(envelope.ID, requestCancel)
			serveWG.Add(1)
			go func(envelope *wire.Envelope) {
				defer serveWG.Done()
				defer cancelInflight(envelope.ID)
				serve(requestCtx, envelope, sendCh, tokens.AgentToken, cfg.LocalServiceURL, cfg.ChunkSizeBytes)
			}(envelope)
		case wire.TypeRequestCancel:
			cancelInflight(envelope.ID)
		case wire.TypeHello:
			log.L().Warn().Str("id", envelope.ID).Msg("unexpected hello mid-session")
		default:
			log.L().Debug().Str("type", envelope.Type).Msg("unhandled envelope")
		}
	}

	cancelSession()
	cancelAllInflight()
	// Wait for serve goroutines to finish so they cannot send into a closed channel.
	serveWG.Wait()
	close(sendCh)
	writerWG.Wait()

	if errors.Is(readErr, context.Canceled) {
		return time.Since(start), nil
	}
	return time.Since(start), readErr
}

func readEnvelope(ctx context.Context, webSocketConn *websocket.Conn) (*wire.Envelope, error) {
	messageType, data, err := webSocketConn.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("ws read: %w", err)
	}
	if messageType != websocket.MessageBinary {
		return nil, fmt.Errorf("unexpected message type %v", messageType)
	}
	envelope, err := wire.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	// Decode aliases its input buffer for Body. The websocket library may
	// reuse that buffer on the next Read, and our envelope is handed off
	// to a goroutine that may outlive this call. Copy defensively.
	if len(envelope.Body) > 0 {
		bodyCopy := make([]byte, len(envelope.Body))
		copy(bodyCopy, envelope.Body)
		envelope.Body = bodyCopy
	}
	return envelope, nil
}

func writerLoop(ctx context.Context, webSocketConn *websocket.Conn, ch <-chan *wire.Envelope) {
	for {
		select {
		case <-ctx.Done():
			return
		case envelope, ok := <-ch:
			if !ok {
				return
			}
			frame, err := wire.Encode(envelope)
			if err != nil {
				log.L().Error().Err(err).Str("id", envelope.ID).Msg("encode envelope")
				continue
			}
			writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = webSocketConn.Write(writeCtx, websocket.MessageBinary, frame)
			cancel()
			if err != nil {
				log.L().Warn().Err(err).Str("id", envelope.ID).Msg("ws write")
				return
			}
		}
	}
}

func buildDialURL(relayWSURL string) (string, error) {
	parsed, err := url.Parse(relayWSURL)
	if err != nil {
		return "", fmt.Errorf("parse relay WS URL: %w", err)
	}
	return parsed.String(), nil
}
