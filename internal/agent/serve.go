// Package agent implements the agent-side tunnel connection logic.
package agent

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lwj5/bridgertun/internal/log"
	"github.com/lwj5/bridgertun/internal/wire"
)

// httpClient is a streaming-friendly client shared across all serve invocations.
// Client.Timeout is intentionally zero so long SSE streams are not killed; per-
// dial timeouts live on the Transport.
var httpClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 0,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	},
}

// serve handles one `request` envelope: verifies the per-session agent token,
// strips Tier 2 + relay-internal credentials, dispatches to the local service,
// and streams the response back as response_head + response_chunk + response_end.
func serve(
	ctx context.Context,
	envelope *wire.Envelope,
	sendCh chan<- *wire.Envelope,
	agentToken string,
	localBase string,
	chunkSize int,
) {
	if !verifyAgentToken(envelope, agentToken) {
		trySend(ctx, sendCh, &wire.Envelope{
			ID:     envelope.ID,
			Type:   wire.TypeResponseHead,
			Status: http.StatusUnauthorized,
		})
		trySend(ctx, sendCh, &wire.Envelope{ID: envelope.ID, Type: wire.TypeResponseEnd, EOF: true})
		return
	}

	localURL, err := buildLocalURL(localBase, envelope.Path)
	if err != nil {
		trySend(ctx, sendCh, &wire.Envelope{ID: envelope.ID, Type: wire.TypeError, Error: "bad path: " + err.Error()})
		return
	}

	method := envelope.Method
	if method == "" {
		method = http.MethodGet
	}

	//nolint:gosec // G704: localURL is derived from the operator-supplied --local-url flag, not untrusted input.
	httpRequest, err := http.NewRequestWithContext(ctx, method, localURL, bytes.NewReader(envelope.Body))
	if err != nil {
		trySend(ctx, sendCh, &wire.Envelope{ID: envelope.ID, Type: wire.TypeError, Error: "build request: " + err.Error()})
		return
	}
	httpRequest.Header = cleanedHeaders(envelope.Headers)

	//nolint:gosec // G704: same rationale as above.
	response, err := httpClient.Do(httpRequest)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}
		trySend(ctx, sendCh, &wire.Envelope{ID: envelope.ID, Type: wire.TypeError, Error: err.Error()})
		return
	}
	defer func() { _ = response.Body.Close() }()

	if !trySend(ctx, sendCh, &wire.Envelope{
		ID:      envelope.ID,
		Type:    wire.TypeResponseHead,
		Status:  response.StatusCode,
		Headers: response.Header,
	}) {
		return
	}

	buf := make([]byte, chunkSize)
	for {
		n, readErr := response.Body.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if !trySend(ctx, sendCh, &wire.Envelope{
				ID:   envelope.ID,
				Type: wire.TypeResponseChunk,
				Body: chunk,
			}) {
				return
			}
		}
		if readErr == io.EOF {
			trySend(ctx, sendCh, &wire.Envelope{ID: envelope.ID, Type: wire.TypeResponseEnd, EOF: true})
			return
		}
		if readErr != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return
			}
			trySend(ctx, sendCh, &wire.Envelope{ID: envelope.ID, Type: wire.TypeError, Error: readErr.Error()})
			return
		}
	}
}

// verifyAgentToken checks X-Tunnel-Agent-Auth using a constant-time
// comparison. Headers map keys may or may not be canonicalized; check both
// forms.
func verifyAgentToken(envelope *wire.Envelope, expected string) bool {
	got := firstHeader(envelope.Headers, "X-Tunnel-Agent-Auth")
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

// firstHeader returns the first value for name, searching both the canonical
// form and any case-variant key in the map.
func firstHeader(headers map[string][]string, name string) string {
	if headers == nil {
		return ""
	}
	if values, ok := headers[http.CanonicalHeaderKey(name)]; ok && len(values) > 0 {
		return values[0]
	}
	for k, values := range headers {
		if strings.EqualFold(k, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// cleanedHeaders returns a new http.Header with Tier 2 and relay-internal keys
// removed. Uses http.Header.Add so values are canonicalized for downstream
// consumers.
func cleanedHeaders(in map[string][]string) http.Header {
	out := make(http.Header, len(in))
	for k, values := range in {
		if strings.EqualFold(k, "X-Tunnel-Agent-Auth") ||
			strings.EqualFold(k, "X-Tunnel-Session-Internal") ||
			strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range values {
			out.Add(k, v)
		}
	}
	return out
}

// buildLocalURL joins localBase with envelopePath and strips the agent_secret
// query param. It avoids the double-slash that naive concat produces when
// localBase ends with '/' and envelopePath starts with '/'.
func buildLocalURL(localBase, envelopePath string) (string, error) {
	base := strings.TrimSuffix(localBase, "/")
	if envelopePath == "" {
		envelopePath = "/"
	}
	parsed, err := url.Parse(base + envelopePath)
	if err != nil {
		return "", fmt.Errorf("parse local url: %w", err)
	}
	if parsed.RawQuery != "" {
		query := parsed.Query()
		if query.Has("agent_secret") {
			query.Del("agent_secret")
			parsed.RawQuery = query.Encode()
		}
	}
	return parsed.String(), nil
}

// trySend enqueues an envelope. Non-terminal frames (chunks) drop after a
// short timeout so a wedged consumer cannot stall the entire agent. Terminal
// frames (response_end, error) wait longer because dropping them leaves the
// relay's stream silently hanging until its idle timeout fires; ctx
// cancellation always unblocks so we cannot deadlock during shutdown.
func trySend(ctx context.Context, ch chan<- *wire.Envelope, envelope *wire.Envelope) bool {
	select {
	case ch <- envelope:
		return true
	default:
	}
	deadline := 250 * time.Millisecond
	if envelope.IsTerminal() {
		deadline = 5 * time.Second
	}
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case ch <- envelope:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		log.L().Warn().Str("id", envelope.ID).Str("type", envelope.Type).Msg("send buffer full; dropping frame")
		return false
	}
}
