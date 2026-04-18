package main

import (
	"testing"
	"time"
)

func TestBackoffClampsToMaxWaitAfterPositiveJitter(t *testing.T) {
	original := randomFloat64
	randomFloat64 = func() float64 { return 1 }
	defer func() { randomFloat64 = original }()

	const maxWait = 5 * time.Second
	if got := backoff(10, maxWait); got != maxWait {
		t.Fatalf("backoff(10, %s) = %s, want %s", maxWait, got, maxWait)
	}
}

func TestBackoffAppliesNegativeJitter(t *testing.T) {
	original := randomFloat64
	randomFloat64 = func() float64 { return 0 }
	defer func() { randomFloat64 = original }()

	const maxWait = 10 * time.Second
	want := 750 * time.Millisecond
	if got := backoff(0, maxWait); got != want {
		t.Fatalf("backoff(0, %s) = %s, want %s", maxWait, got, want)
	}
}
