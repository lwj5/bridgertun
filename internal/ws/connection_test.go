package ws

import (
	"context"
	"testing"

	"github.com/lwj5/bridgertun/internal/auth"
	"github.com/lwj5/bridgertun/internal/wire"
)

const testSubject = "subject-1"

func TestConnectionDispatchRoutesTerminalEnvelopeAndRemovesStream(t *testing.T) {
	t.Parallel()

	connection := NewConnection("session-1", &auth.Principal{Subject: testSubject}, nil, ConnectionOptions{})
	stream, err := connection.OpenStream(context.Background(), &wire.Envelope{Method: "GET", Path: "/healthz"})
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}

	connection.dispatch(context.Background(), &wire.Envelope{ID: stream.ID, Type: wire.TypeResponseHead, Status: 204})
	head := <-stream.HeadCh()
	if head == nil || head.Status != 204 {
		t.Fatalf("head = %+v, want status 204", head)
	}

	connection.dispatch(context.Background(), &wire.Envelope{ID: stream.ID, Type: wire.TypeResponseEnd, EOF: true})
	end := <-stream.ChunksCh()
	if end == nil || end.Type != wire.TypeResponseEnd {
		t.Fatalf("end = %+v, want response_end", end)
	}
	if _, ok := connection.streams.Get(stream.ID); ok {
		t.Fatal("stream should be removed after terminal envelope")
	}
}
