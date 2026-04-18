package proxy

import (
	"errors"
	"testing"

	"github.com/lwj5/bridgertun/internal/wire"
)

func TestStreamFailDeliversErrorAndCloses(t *testing.T) {
	t.Parallel()

	stream := NewStream("request-1", func() {})
	stream.Fail(errors.New("boom"))

	envelope, ok := <-stream.ChunksCh()
	if !ok {
		t.Fatal("ChunksCh closed before error envelope was delivered")
	}
	if envelope.Type != wire.TypeError || envelope.Error != "boom" {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
	if _, ok := <-stream.ChunksCh(); ok {
		t.Fatal("ChunksCh should be closed after terminal error")
	}
	if _, ok := <-stream.HeadCh(); ok {
		t.Fatal("HeadCh should be closed after Fail")
	}
}

func TestRegistryCloseAllRemovesStreams(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	stream := NewStream("request-2", func() {})
	registry.Add(stream)

	registry.CloseAll(errors.New("gone"))

	if _, ok := registry.Get(stream.ID); ok {
		t.Fatal("registry still returns stream after CloseAll")
	}
	envelope, ok := <-stream.ChunksCh()
	if !ok {
		t.Fatal("expected error envelope before chunks channel closed")
	}
	if envelope.Type != wire.TypeError || envelope.Error != "gone" {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
}
