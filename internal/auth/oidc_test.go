package auth

import (
	"context"
	"strings"
	"testing"
)

func TestVerifierVerifyRejectsEmptyBearer(t *testing.T) {
	t.Parallel()

	verifier := &Verifier{}
	_, err := verifier.Verify(context.Background(), "Bearer   ")
	if err == nil {
		t.Fatal("Verify() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("Verify() error = %q, want empty token error", err)
	}
}
