package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/valkey-io/valkey-go"

	"github.com/lwj5/bridgertun/internal/wire"
)

const (
	sessionKeyPrefix    = "session:"
	bySubjectKeyPrefix  = "sessions:by-sub:"
	nodeCtrlChanFmt     = "relay:node:%s:ctrl"
	requestStreamKeyFmt = "relay:req:%s"
	sessionTTL          = 90 * time.Second
	sessionRefreshDur   = 30 * time.Second
	requestStreamTTL    = 5 * time.Minute
	requestStreamMaxLen = 10_000

	ctrlTypeStart  = "start"
	ctrlTypeCancel = "cancel"
	ctrlTypeClose  = "close"
)

// ErrBlockTimeout is returned by remoteStream.Receive when the blocking XREAD
// times out with no new data. Callers should retry.
var ErrBlockTimeout = errors.New("stream block timeout")

type ctrlMessage struct {
	Type        string `json:"type"`
	RequestID   string `json:"request_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	ReplyStream string `json:"reply_stream,omitempty"`
	// EnvelopeFrame is the wire-encoded envelope (JSON header + raw body).
	// The ctrlMessage itself is JSON, so this field is base64-encoded by
	// encoding/json. Control traffic volume is low (one message per remote
	// dispatch / cancel), so the overhead is accepted to keep one codec.
	EnvelopeFrame []byte `json:"envelope_frame,omitempty"`
}

type localEntry struct {
	info   *SessionInfo
	sender LocalSender
	cancel context.CancelFunc
}

// ValkeyRegistry is a distributed session registry backed by Valkey (Redis-compatible).
type ValkeyRegistry struct {
	valkeyClient valkey.Client
	nodeID       string

	// resumeGraceTTL is how long a Detach'd session lingers before the record
	// is reaped. Configurable via RESUME_GRACE_TTL; see config.Config.
	resumeGraceTTL time.Duration

	mu     sync.RWMutex
	locals map[string]*localEntry

	// in-flight remote dispatches on THIS node, keyed by requestID, so we can
	// propagate cancel from caller -> owner via another pubsub message.
	inflight   sync.Map // requestID -> *remoteStream
	pendingCtx sync.Map // requestID → context.CancelFunc (for remote replies being forwarded)

	subscriberCancel context.CancelFunc
	wg               sync.WaitGroup
}

// NewValkeyRegistry creates a ValkeyRegistry, verifies connectivity, and starts the subscription loop.
// resumeGraceTTL must be positive; callers (e.g. config) are expected to validate.
func NewValkeyRegistry(
	ctx context.Context,
	valkeyClient valkey.Client,
	nodeID string,
	resumeGraceTTL time.Duration,
) (*ValkeyRegistry, error) {
	if resumeGraceTTL <= 0 {
		return nil, fmt.Errorf("resumeGraceTTL must be positive, got %s", resumeGraceTTL)
	}
	if err := valkeyClient.Do(ctx, valkeyClient.B().Ping().Build()).Error(); err != nil {
		return nil, fmt.Errorf("valkey ping: %w", err)
	}
	subscriberCtx, subscriberCancel := context.WithCancel(ctx)
	registry := &ValkeyRegistry{
		valkeyClient:     valkeyClient,
		nodeID:           nodeID,
		resumeGraceTTL:   resumeGraceTTL,
		locals:           make(map[string]*localEntry),
		subscriberCancel: subscriberCancel,
	}
	registry.wg.Add(1)
	go registry.controlSubscriber(subscriberCtx)
	return registry, nil
}

// Register persists session metadata in Valkey and records the local sender for this node.
func (r *ValkeyRegistry) Register(ctx context.Context, info *SessionInfo, sender LocalSender) error {
	info.NodeID = r.nodeID
	if info.ConnectedAt.IsZero() {
		info.ConnectedAt = time.Now()
	}
	info.State = SessionStateActive
	payload, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshal session info: %w", err)
	}
	setCmd := r.valkeyClient.B().Set().Key(sessionKey(info.SessionID)).Value(string(payload)).Ex(sessionTTL).Build()
	if err := r.valkeyClient.Do(ctx, setCmd).Error(); err != nil {
		return fmt.Errorf("set session info: %w", err)
	}
	if info.Subject != "" {
		saddCmd := r.valkeyClient.B().Sadd().Key(bySubjectKey(info.Subject)).Member(info.SessionID).Build()
		if err := r.valkeyClient.Do(ctx, saddCmd).Error(); err != nil {
			log.Warn().Err(err).Str("session", info.SessionID).Msg("sadd session by subject")
		}
	}

	// TTL refresh must outlive the caller's request context; tie its lifetime
	// only to Unregister (via the cancel stored in localEntry, invoked below).
	//nolint:gosec // cancel is invoked by Unregister via localEntry.cancel
	refreshCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r.mu.Lock()
	r.locals[info.SessionID] = &localEntry{info: info, sender: sender, cancel: cancel}
	r.mu.Unlock()

	r.wg.Add(1)
	go r.refreshTTL(refreshCtx, info.SessionID)
	return nil
}

func (r *ValkeyRegistry) refreshTTL(ctx context.Context, sessionID string) {
	defer r.wg.Done()
	ticker := time.NewTicker(sessionRefreshDur)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			expireCmd := r.valkeyClient.B().Expire().Key(sessionKey(sessionID)).Seconds(int64(sessionTTL.Seconds())).Build()
			if err := r.valkeyClient.Do(ctx, expireCmd).Error(); err != nil {
				log.Warn().Err(err).Str("session", sessionID).Msg("refresh TTL")
			}
		}
	}
}

// Unregister removes the session from Valkey and cancels its TTL refresh goroutine.
func (r *ValkeyRegistry) Unregister(ctx context.Context, sessionID string) error {
	r.mu.Lock()
	entry, ok := r.locals[sessionID]
	delete(r.locals, sessionID)
	r.mu.Unlock()
	if ok && entry.cancel != nil {
		entry.cancel()
	}
	if err := r.valkeyClient.Do(ctx, r.valkeyClient.B().Del().Key(sessionKey(sessionID)).Build()).Error(); err != nil {
		log.Warn().Err(err).Str("session", sessionID).Msg("unregister del session")
	}
	if ok && entry.info != nil && entry.info.Subject != "" {
		sremCmd := r.valkeyClient.B().Srem().Key(bySubjectKey(entry.info.Subject)).Member(sessionID).Build()
		if err := r.valkeyClient.Do(ctx, sremCmd).Error(); err != nil {
			log.Warn().Err(err).Str("session", sessionID).Msg("unregister srem")
		}
	}
	return nil
}

// Detach marks the session as disconnected and drops the local entry, but
// leaves the Valkey record in place until the TTL expires. Lets the agent
// reconnect (possibly on a different node) and resume with the same ID.
//
// The Valkey rewrite only happens if the current record still names this
// node as the owner. If a resume on another node has already taken over,
// we leave their record alone.
func (r *ValkeyRegistry) Detach(ctx context.Context, sessionID string) error {
	r.mu.Lock()
	entry, ok := r.locals[sessionID]
	if !ok {
		r.mu.Unlock()
		return nil
	}
	delete(r.locals, sessionID)
	r.mu.Unlock()
	if entry.cancel != nil {
		entry.cancel()
	}
	if entry.info == nil {
		return nil
	}

	// Compare-then-write to avoid clobbering a concurrent takeover.
	rawBytes, err := r.valkeyClient.Do(ctx, r.valkeyClient.B().Get().Key(sessionKey(sessionID)).Build()).AsBytes()
	if err != nil {
		// Record already gone (expired or force-deleted). Nothing to do.
		return nil
	}
	var currentInfo SessionInfo
	if err := json.Unmarshal(rawBytes, &currentInfo); err != nil {
		return nil
	}
	if currentInfo.NodeID != r.nodeID {
		// Someone else owns the record now — they already took over.
		return nil
	}

	detachedInfo := *entry.info
	detachedInfo.State = SessionStateDetached
	payload, err := json.Marshal(&detachedInfo)
	if err != nil {
		return nil
	}
	setCmd := r.valkeyClient.B().Set().Key(sessionKey(sessionID)).Value(string(payload)).Ex(r.resumeGraceTTL).Build()
	if err := r.valkeyClient.Do(ctx, setCmd).Error(); err != nil {
		log.Warn().Err(err).Str("session", sessionID).Msg("detach set")
	}
	return nil
}

// Lookup fetches session metadata from Valkey by session ID.
func (r *ValkeyRegistry) Lookup(ctx context.Context, sessionID string) (*SessionInfo, error) {
	r.mu.RLock()
	entry, ok := r.locals[sessionID]
	r.mu.RUnlock()
	if ok {
		return entry.info, nil
	}
	rawBytes, err := r.valkeyClient.Do(ctx, r.valkeyClient.B().Get().Key(sessionKey(sessionID)).Build()).AsBytes()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("lookup session bytes: %w", err)
	}
	var info SessionInfo
	if err := json.Unmarshal(rawBytes, &info); err != nil {
		return nil, fmt.Errorf("unmarshal session info: %w", err)
	}
	return &info, nil
}

// Dispatch routes an HTTP request envelope to the owning agent, either locally or via Valkey.
//
//nolint:ireturn // Registry contract intentionally returns interface for local/remote stream abstraction.
func (r *ValkeyRegistry) Dispatch(ctx context.Context, sessionID string, envelope *wire.Envelope) (ProxyStream, error) {
	r.mu.RLock()
	entry, ok := r.locals[sessionID]
	r.mu.RUnlock()
	if ok {
		stream, err := entry.sender.OpenStream(ctx, envelope)
		if err != nil {
			return nil, fmt.Errorf("open local stream: %w", err)
		}
		return newLocalProxyStream(stream), nil
	}

	info, err := r.Lookup(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if info.NodeID == "" || info.NodeID == r.nodeID {
		// Owner says it's us but we don't hold a local entry — stale.
		return nil, ErrNotFound
	}
	return r.dispatchRemote(ctx, info.NodeID, envelope)
}

//nolint:ireturn // Registry contract intentionally returns interface for local/remote stream abstraction.
func (r *ValkeyRegistry) dispatchRemote(
	ctx context.Context,
	ownerNodeID string,
	envelope *wire.Envelope,
) (ProxyStream, error) {
	if envelope.ID == "" {
		envelope.ID = uuid.NewString()
	}
	envelope.Type = wire.TypeRequest

	requestID := envelope.ID
	replyStream := fmt.Sprintf(requestStreamKeyFmt, requestID)

	// sessionID is read from a well-known header set by Dispatch's caller;
	// we re-surface it as a dedicated field below.
	sessionID := ""
	if headerValues := envelope.Headers["X-Tunnel-Session-Internal"]; len(headerValues) > 0 {
		sessionID = headerValues[0]
		delete(envelope.Headers, "X-Tunnel-Session-Internal")
	}

	frame, err := wire.Encode(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode start envelope: %w", err)
	}
	startMessage := ctrlMessage{
		Type:          ctrlTypeStart,
		RequestID:     requestID,
		SessionID:     sessionID,
		ReplyStream:   replyStream,
		EnvelopeFrame: frame,
	}
	payload, err := json.Marshal(startMessage)
	if err != nil {
		return nil, fmt.Errorf("marshal start message: %w", err)
	}
	pubCmd := r.valkeyClient.B().Publish().
		Channel(fmt.Sprintf(nodeCtrlChanFmt, ownerNodeID)).
		Message(string(payload)).
		Build()
	if err := r.valkeyClient.Do(ctx, pubCmd).Error(); err != nil {
		return nil, fmt.Errorf("publish start: %w", err)
	}
	remoteStream := &remoteStream{
		valkeyClient: r.valkeyClient,
		requestID:    requestID,
		replyStream:  replyStream,
		ownerNodeID:  ownerNodeID,
		nextID:       "0-0",
		inflight:     &r.inflight,
	}
	r.inflight.Store(requestID, remoteStream)
	return remoteStream, nil
}

// List returns session metadata for all sessions matching the given filter.
func (r *ValkeyRegistry) List(ctx context.Context, filter Filter) ([]*SessionInfo, error) {
	var ids []string
	if filter.Subject != "" {
		smembersCmd := r.valkeyClient.B().Smembers().Key(bySubjectKey(filter.Subject)).Build()
		res, err := r.valkeyClient.Do(ctx, smembersCmd).AsStrSlice()
		if err != nil && !valkey.IsValkeyNil(err) {
			return nil, fmt.Errorf("list sessions by subject: %w", err)
		}
		ids = res
	} else {
		var cursor uint64
		for {
			scanCmd := r.valkeyClient.B().Scan().Cursor(cursor).Match(sessionKeyPrefix + "*").Count(200).Build()
			scanEntry, err := r.valkeyClient.Do(ctx, scanCmd).AsScanEntry()
			if err != nil {
				return nil, fmt.Errorf("scan sessions: %w", err)
			}
			for _, key := range scanEntry.Elements {
				ids = append(ids, strings.TrimPrefix(key, sessionKeyPrefix))
			}
			cursor = scanEntry.Cursor
			if cursor == 0 {
				break
			}
		}
	}
	out := make([]*SessionInfo, 0, len(ids))
	for _, id := range ids {
		info, err := r.Lookup(ctx, id)
		if err != nil {
			continue
		}
		if filter.Tenant != "" && info.Tenant != filter.Tenant {
			continue
		}
		out = append(out, info)
	}
	return out, nil
}

// ForceClose terminates a session, locally or by publishing a close control message to the owning node.
func (r *ValkeyRegistry) ForceClose(ctx context.Context, sessionID string) error {
	r.mu.RLock()
	entry, ok := r.locals[sessionID]
	r.mu.RUnlock()
	if ok {
		entry.sender.Close("forced")
		return nil
	}
	info, err := r.Lookup(ctx, sessionID)
	if err != nil {
		return err
	}
	closeMessage := ctrlMessage{Type: ctrlTypeClose, SessionID: sessionID}
	payload, err := json.Marshal(closeMessage)
	if err != nil {
		return fmt.Errorf("marshal force close: %w", err)
	}
	pubCmd := r.valkeyClient.B().Publish().
		Channel(fmt.Sprintf(nodeCtrlChanFmt, info.NodeID)).
		Message(string(payload)).
		Build()
	if err := r.valkeyClient.Do(ctx, pubCmd).Error(); err != nil {
		return fmt.Errorf("publish force close: %w", err)
	}
	return nil
}

// Close shuts down the registry, cancels the subscription goroutine, and waits for it to exit.
func (r *ValkeyRegistry) Close() error {
	r.subscriberCancel()
	r.wg.Wait()
	return nil
}

// controlSubscriber reads messages destined for this node and forwards them to
// the appropriate local action: start a new stream, cancel one, or force-close
// a session.
func (r *ValkeyRegistry) controlSubscriber(ctx context.Context) {
	defer r.wg.Done()
	channelName := fmt.Sprintf(nodeCtrlChanFmt, r.nodeID)

	const baseBackoff = 500 * time.Millisecond
	const maxBackoff = 30 * time.Second
	backoff := baseBackoff
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		subscribeCmd := r.valkeyClient.B().Subscribe().Channel(channelName).Build()
		err := r.valkeyClient.Receive(ctx, subscribeCmd, func(msg valkey.PubSubMessage) {
			var controlMessage ctrlMessage
			if err := json.Unmarshal([]byte(msg.Message), &controlMessage); err != nil {
				log.Warn().Err(err).Msg("ctrl decode")
				return
			}
			r.handleCtrl(ctx, &controlMessage)
		})
		if err == nil {
			backoff = baseBackoff
			continue
		}
		if errors.Is(err, context.Canceled) {
			return
		}
		log.Warn().Err(err).Dur("backoff", backoff).Msg("ctrl subscribe")
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (r *ValkeyRegistry) handleCtrl(ctx context.Context, message *ctrlMessage) {
	switch message.Type {
	case ctrlTypeStart:
		if len(message.EnvelopeFrame) == 0 || message.RequestID == "" {
			return
		}
		envelope, err := wire.Decode(message.EnvelopeFrame)
		if err != nil {
			log.Warn().Err(err).Str("requestID", message.RequestID).Msg("ctrl start envelope decode")
			return
		}
		r.runRemote(ctx, message, envelope)
	case ctrlTypeCancel:
		if loaded, ok := r.pendingCtx.LoadAndDelete(message.RequestID); ok {
			if cancel, isCancel := loaded.(context.CancelFunc); isCancel {
				cancel()
			}
		}
	case ctrlTypeClose:
		r.mu.RLock()
		entry, ok := r.locals[message.SessionID]
		r.mu.RUnlock()
		if ok {
			entry.sender.Close("forced by remote")
		}
	}
}

// runRemote opens a local stream on behalf of a remote caller and forwards
// envelopes to the Valkey stream the caller is reading.
func (r *ValkeyRegistry) runRemote(ctx context.Context, message *ctrlMessage, envelope *wire.Envelope) {
	sessionID := message.SessionID
	if sessionID == "" {
		log.Warn().Str("requestID", message.RequestID).Msg("remote start without session id")
		return
	}
	r.mu.RLock()
	entry, ok := r.locals[sessionID]
	r.mu.RUnlock()
	if !ok {
		// We don't own it after all. Publish a synthetic error so the caller unblocks.
		r.writeTerminal(ctx, message.ReplyStream, &wire.Envelope{
			ID: message.RequestID, Type: wire.TypeError, Error: "session not on this node",
		})
		return
	}

	streamCtx, cancel := context.WithCancel(ctx)
	r.pendingCtx.Store(message.RequestID, cancel)
	defer func() {
		r.pendingCtx.Delete(message.RequestID)
		cancel()
	}()

	stream, err := entry.sender.OpenStream(streamCtx, envelope)
	if err != nil {
		r.writeTerminal(ctx, message.ReplyStream, &wire.Envelope{
			ID: message.RequestID, Type: wire.TypeError, Error: err.Error(),
		})
		return
	}

	// forward head
	select {
	case head, ok := <-stream.Head:
		if ok && head != nil {
			r.xaddEnvelope(ctx, message.ReplyStream, head)
		}
	case <-streamCtx.Done():
		stream.Cancel()
		return
	}
	for {
		select {
		case chunkEnvelope, ok := <-stream.Chunks:
			if !ok {
				return
			}
			r.xaddEnvelope(ctx, message.ReplyStream, chunkEnvelope)
			if chunkEnvelope.IsTerminal() {
				return
			}
		case <-streamCtx.Done():
			stream.Cancel()
			return
		}
	}
}

func (r *ValkeyRegistry) xaddEnvelope(ctx context.Context, stream string, envelope *wire.Envelope) {
	frame, err := wire.Encode(envelope)
	if err != nil {
		log.Warn().Err(err).Str("stream", stream).Msg("xadd encode")
		return
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	xaddCmd := r.valkeyClient.B().Xadd().
		Key(stream).
		Maxlen().Almost().Threshold(strconv.FormatInt(requestStreamMaxLen, 10)).
		Id("*").
		FieldValue().FieldValue("e", valkey.BinaryString(frame)).
		Build()
	if err := r.valkeyClient.Do(timeoutCtx, xaddCmd).Error(); err != nil {
		log.Warn().Err(err).Str("stream", stream).Msg("xadd")
	}
	expireCmd := r.valkeyClient.B().Expire().Key(stream).Seconds(int64(requestStreamTTL.Seconds())).Build()
	if err := r.valkeyClient.Do(timeoutCtx, expireCmd).Error(); err != nil {
		log.Warn().Err(err).Str("stream", stream).Msg("xadd expire")
	}
}

func (r *ValkeyRegistry) writeTerminal(ctx context.Context, stream string, envelope *wire.Envelope) {
	r.xaddEnvelope(ctx, stream, envelope)
}

// remoteStream consumes a Valkey Stream populated by the owner node.
type remoteStream struct {
	valkeyClient valkey.Client
	requestID    string
	replyStream  string
	ownerNodeID  string
	inflight     *sync.Map // caller-side requestID → *remoteStream; cleaned up by Close

	mu       sync.Mutex
	nextID   string // XREAD id cursor
	finished bool
}

func (r *remoteStream) Receive(ctx context.Context) (*wire.Envelope, error) {
	r.mu.Lock()
	if r.finished {
		r.mu.Unlock()
		return nil, io.EOF
	}
	nextID := r.nextID
	r.mu.Unlock()

	xreadCmd := r.valkeyClient.B().Xread().Count(1).Block(5000).Streams().Key(r.replyStream).Id(nextID).Build()
	streams, err := r.valkeyClient.Do(ctx, xreadCmd).AsXRead()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			// block timeout — caller will loop unless ctx is done
			if ctx.Err() != nil {
				return nil, fmt.Errorf("xread canceled: %w", ctx.Err())
			}
			return nil, ErrBlockTimeout
		}
		return nil, fmt.Errorf("xread replies: %w", err)
	}
	messages := streams[r.replyStream]
	if len(messages) == 0 {
		return nil, ErrBlockTimeout
	}
	message := messages[0]
	raw := message.FieldValues["e"]
	envelope, err := wire.Decode([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("decode reply envelope: %w", err)
	}

	r.mu.Lock()
	r.nextID = message.ID
	if envelope.IsTerminal() {
		r.finished = true
	}
	r.mu.Unlock()
	return envelope, nil
}

func (r *remoteStream) Cancel() {
	cancelMessage := ctrlMessage{Type: ctrlTypeCancel, RequestID: r.requestID}
	payload, err := json.Marshal(cancelMessage)
	if err != nil {
		log.Warn().Err(err).Str("requestID", r.requestID).Msg("remote cancel marshal")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pubCmd := r.valkeyClient.B().Publish().
		Channel(fmt.Sprintf(nodeCtrlChanFmt, r.ownerNodeID)).
		Message(string(payload)).
		Build()
	if err := r.valkeyClient.Do(ctx, pubCmd).Error(); err != nil {
		log.Warn().Err(err).Str("requestID", r.requestID).Msg("remote cancel publish")
	}
}

func (r *remoteStream) Close() error {
	r.mu.Lock()
	r.finished = true
	r.mu.Unlock()
	if r.inflight != nil {
		r.inflight.Delete(r.requestID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := r.valkeyClient.Do(ctx, r.valkeyClient.B().Del().Key(r.replyStream).Build()).Error(); err != nil {
		log.Warn().Err(err).Str("requestID", r.requestID).Msg("remote close del")
	}
	return nil
}

func sessionKey(id string) string        { return sessionKeyPrefix + id }
func bySubjectKey(subject string) string { return bySubjectKeyPrefix + subject }
