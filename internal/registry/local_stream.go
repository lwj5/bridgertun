// Package registry manages agent session state across relay nodes.
package registry

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/lwj5/bridgertun/internal/proxy"
	"github.com/lwj5/bridgertun/internal/wire"
)

// localProxyStream wraps a *proxy.Stream (backed by an in-process WS connection)
// so it satisfies the ProxyStream interface that the HTTP API consumes.
type localProxyStream struct {
	s *proxy.Stream

	mu       sync.Mutex
	sawHead  bool
	finished bool
}

func newLocalProxyStream(s *proxy.Stream) *localProxyStream {
	return &localProxyStream{s: s}
}

func (l *localProxyStream) Receive(ctx context.Context) (*wire.Envelope, error) {
	l.mu.Lock()
	finished := l.finished
	sawHead := l.sawHead
	l.mu.Unlock()
	if finished {
		return nil, io.EOF
	}
	if !sawHead {
		select {
		case env, ok := <-l.s.Head:
			if !ok {
				// stream closed before head
				select {
				case e, ok := <-l.s.Chunks:
					if ok && e != nil {
						l.markFinished()
						return e, nil
					}
				default:
				}
				return nil, io.EOF
			}
			l.mu.Lock()
			l.sawHead = true
			l.mu.Unlock()
			return env, nil
		case <-ctx.Done():
			return nil, fmt.Errorf("receive head: %w", ctx.Err())
		}
	}
	select {
	case env, ok := <-l.s.Chunks:
		if !ok {
			l.markFinished()
			return nil, io.EOF
		}
		if env.IsTerminal() {
			l.markFinished()
		}
		return env, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("receive chunk: %w", ctx.Err())
	}
}

func (l *localProxyStream) Cancel() { l.s.Cancel() }

func (l *localProxyStream) Close() error {
	l.s.Close()
	l.markFinished()
	return nil
}

func (l *localProxyStream) markFinished() {
	l.mu.Lock()
	l.finished = true
	l.mu.Unlock()
}
