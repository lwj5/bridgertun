package registry

import (
	"errors"
	"testing"
)

func TestSessionStateConstantsAreDistinct(t *testing.T) {
	t.Parallel()

	if SessionStateActive == "" || SessionStateDetached == "" {
		t.Fatal("session state constants must be non-empty")
	}
	if SessionStateActive == SessionStateDetached {
		t.Fatal("session state constants must differ")
	}
}

func TestRegistryErrorsAreDistinct(t *testing.T) {
	t.Parallel()

	if ErrNotFound == nil || ErrUnavailable == nil {
		t.Fatal("registry sentinel errors must be initialized")
	}
	if errors.Is(ErrNotFound, ErrUnavailable) {
		t.Fatal("registry sentinel errors must be distinct")
	}
}
