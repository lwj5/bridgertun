// Package wire defines the framed protocol exchanged between relay and agent.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Envelope type constants used in the Type field of every wire frame.
const (
	TypeHello         = "hello"
	TypeRequest       = "request"
	TypeResponseHead  = "response_head"
	TypeResponseChunk = "response_chunk"
	TypeResponseEnd   = "response_end"
	TypeRequestCancel = "request_cancel"
	TypePing          = "ping"
	TypePong          = "pong"
	TypeError         = "error"
)

// MaxFrameSize bounds the total encoded frame (header length prefix + JSON
// header + raw body). Matches the WebSocket per-frame read limit enforced by
// connection readers.
const MaxFrameSize = 16 * 1024 * 1024

// Envelope is the in-memory representation of a protocol frame. On the wire,
// everything except Body is serialized as a JSON header; Body is appended as
// raw trailing bytes. Use Encode/Decode rather than json.Marshal directly.
type Envelope struct {
	ID        string
	Type      string
	Method    string
	Path      string
	Headers   map[string][]string
	Status    int
	Body      []byte
	EOF       bool
	Error     string
	TunnelURL string
}

// envelopeHeader is the JSON-serialized portion of a frame. It intentionally
// excludes Body so that any ad-hoc json.Marshal(env) path cannot accidentally
// include it (base64) or silently drop it.
type envelopeHeader struct {
	ID        string              `json:"id"`
	Type      string              `json:"type"`
	Method    string              `json:"method,omitempty"`
	Path      string              `json:"path,omitempty"`
	Headers   map[string][]string `json:"headers,omitempty"`
	Status    int                 `json:"status,omitempty"`
	EOF       bool                `json:"eof,omitempty"`
	Error     string              `json:"error,omitempty"`
	TunnelURL string              `json:"tunnel_url,omitempty"`
}

// IsTerminal reports whether this envelope type ends a request/response exchange.
func (e *Envelope) IsTerminal() bool {
	return e.Type == TypeResponseEnd || e.Type == TypeError
}

// Sentinel errors so callers can distinguish frame-format failures from
// transport/IO errors with errors.Is.
var (
	ErrNilEnvelope    = errors.New("nil envelope")
	ErrFrameTooLarge  = errors.New("frame exceeds MaxFrameSize")
	ErrShortFrame     = errors.New("frame shorter than 4-byte header length prefix")
	ErrHeaderOverflow = errors.New("header length exceeds frame payload")
)

// Encode returns the framed bytes: [4B BE header-len][JSON header][raw body].
func Encode(envelope *Envelope) ([]byte, error) {
	if envelope == nil {
		return nil, ErrNilEnvelope
	}
	header := envelopeHeader{
		ID:        envelope.ID,
		Type:      envelope.Type,
		Method:    envelope.Method,
		Path:      envelope.Path,
		Headers:   envelope.Headers,
		Status:    envelope.Status,
		EOF:       envelope.EOF,
		Error:     envelope.Error,
		TunnelURL: envelope.TunnelURL,
	}
	headerBytes, err := json.Marshal(&header)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope header: %w", err)
	}
	if len(headerBytes) > MaxFrameSize-4 {
		return nil, fmt.Errorf("envelope header (%d bytes): %w", len(headerBytes), ErrFrameTooLarge)
	}
	total := 4 + len(headerBytes) + len(envelope.Body)
	if total > MaxFrameSize {
		return nil, fmt.Errorf("envelope frame (%d bytes > %d): %w", total, MaxFrameSize, ErrFrameTooLarge)
	}
	buf := make([]byte, total)
	//nolint:gosec // len(headerBytes) bounded by MaxFrameSize-4 check above
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(headerBytes)))
	copy(buf[4:4+len(headerBytes)], headerBytes)
	if len(envelope.Body) > 0 {
		copy(buf[4+len(headerBytes):], envelope.Body)
	}
	return buf, nil
}

// Decode parses a received frame. The returned Envelope.Body aliases the
// input buffer when non-empty; callers must not retain Body past the next
// reuse of data or must copy it defensively.
func Decode(data []byte) (*Envelope, error) {
	if len(data) > MaxFrameSize {
		return nil, fmt.Errorf("decode input (%d bytes > %d): %w", len(data), MaxFrameSize, ErrFrameTooLarge)
	}
	if len(data) < 4 {
		return nil, ErrShortFrame
	}
	headerLength := binary.BigEndian.Uint32(data[0:4])
	if int64(headerLength) > int64(len(data)-4) {
		return nil, fmt.Errorf("header length %d, payload %d: %w", headerLength, len(data)-4, ErrHeaderOverflow)
	}
	var header envelopeHeader
	if err := json.Unmarshal(data[4:4+headerLength], &header); err != nil {
		return nil, fmt.Errorf("unmarshal envelope header: %w", err)
	}
	envelope := &Envelope{
		ID:        header.ID,
		Type:      header.Type,
		Method:    header.Method,
		Path:      header.Path,
		Headers:   header.Headers,
		Status:    header.Status,
		EOF:       header.EOF,
		Error:     header.Error,
		TunnelURL: header.TunnelURL,
	}
	if tail := data[4+headerLength:]; len(tail) > 0 {
		envelope.Body = tail
	}
	return envelope, nil
}
