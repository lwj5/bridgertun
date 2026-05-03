package httpmiddleware

import (
	"net/url"
	"strings"
	"testing"
)

func TestSanitizeURL_RedactsTunnelAuth(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("/v1/tunnel/sess-1?x-tunnel-auth=relay-secret%3Aagent-secret&foo=bar")
	got := sanitizeURL(u)
	if strings.Contains(got, "relay-secret") || strings.Contains(got, "agent-secret") {
		t.Fatalf("x-tunnel-auth value leaked into log URL: %q", got)
	}
	if !strings.Contains(got, "x-tunnel-auth=***") {
		t.Fatalf("x-tunnel-auth placeholder missing: %q", got)
	}
	if !strings.Contains(got, "foo=bar") {
		t.Fatalf("unrelated param removed: %q", got)
	}
}

func TestSanitizeURL_RedactsCaseInsensitiveKey(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("/v1/tunnel/sess-1?X-Tunnel-Auth=mysecret&baz=qux")
	got := sanitizeURL(u)
	if strings.Contains(got, "mysecret") {
		t.Fatalf("X-Tunnel-Auth value leaked: %q", got)
	}
	if !strings.Contains(got, "=***") {
		t.Fatalf("placeholder missing: %q", got)
	}
}

func TestSanitizeURL_NoQueryPassthrough(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("/v1/tunnel/sess-1")
	got := sanitizeURL(u)
	if got != "/v1/tunnel/sess-1" {
		t.Fatalf("unexpected mutation: %q", got)
	}
}

func TestSanitizeURL_InnocentQueryUntouched(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("/path?foo=bar&baz=qux")
	got := sanitizeURL(u)
	if strings.Contains(got, "***") {
		t.Fatalf("unexpected redaction of clean params: %q", got)
	}
	if !strings.Contains(got, "foo=bar") || !strings.Contains(got, "baz=qux") {
		t.Fatalf("clean params unexpectedly stripped: %q", got)
	}
}
