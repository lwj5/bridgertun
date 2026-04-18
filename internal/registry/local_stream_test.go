package registry

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/lwj5/bridgertun/internal/proxy"
	"github.com/lwj5/bridgertun/internal/wire"
)

func TestLocalProxyStream_TerminalBeforeHead(t *testing.T) {
	s := proxy.NewStream("req-1", func() {})
	ps := newLocalProxyStream(s)

	// Agent errors before sending a response_head.
	s.Deliver(&wire.Envelope{ID: "req-1", Type: wire.TypeError, Error: "boom"})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	env, err := ps.Receive(ctx)
	if err != nil {
		t.Fatalf("first receive: %v", err)
	}
	if env == nil || env.Type != wire.TypeError {
		t.Fatalf("got envelope %+v, want TypeError", env)
	}

	if _, err := ps.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("second receive err=%v, want io.EOF", err)
	}
}

func TestLocalProxyStream_HeadThenChunksThenEnd(t *testing.T) {
	s := proxy.NewStream("req-2", func() {})
	ps := newLocalProxyStream(s)

	s.Deliver(&wire.Envelope{ID: "req-2", Type: wire.TypeResponseHead, Status: 200})
	s.Deliver(&wire.Envelope{ID: "req-2", Type: wire.TypeResponseChunk, Body: []byte("hello")})
	s.Deliver(&wire.Envelope{ID: "req-2", Type: wire.TypeResponseEnd, EOF: true})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	head, err := ps.Receive(ctx)
	if err != nil || head.Type != wire.TypeResponseHead {
		t.Fatalf("head receive: env=%+v err=%v", head, err)
	}
	chunk, err := ps.Receive(ctx)
	if err != nil || chunk.Type != wire.TypeResponseChunk || string(chunk.Body) != "hello" {
		t.Fatalf("chunk receive: env=%+v err=%v", chunk, err)
	}
	end, err := ps.Receive(ctx)
	if err != nil || end.Type != wire.TypeResponseEnd {
		t.Fatalf("end receive: env=%+v err=%v", end, err)
	}
	if _, err := ps.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("post-terminal receive err=%v, want io.EOF", err)
	}
}
