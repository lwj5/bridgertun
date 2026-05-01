package logutil

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestInitDefaultsUnknownLevelToInfo(t *testing.T) {
	Init("definitely-not-a-level")

	if got := zerolog.GlobalLevel(); got != zerolog.InfoLevel {
		t.Fatalf("zerolog.GlobalLevel() = %s, want %s", got, zerolog.InfoLevel)
	}
}
