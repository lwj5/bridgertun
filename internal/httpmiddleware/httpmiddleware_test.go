package httpmiddleware

import (
	"net/url"
	"strings"
	"testing"
)

func TestSanitizeURL_RedactsTunnelSecret(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("/v1/tunnel/sess-1?tunnel_secret=supersecret&foo=bar")
	got := sanitizeURL(u)
	if strings.Contains(got, "supersecret") {
		t.Fatalf("tunnel_secret value leaked into log URL: %q", got)
	}
	if !strings.Contains(got, "tunnel_secret=***") {
		t.Fatalf("tunnel_secret placeholder missing: %q", got)
	}
	if !strings.Contains(got, "foo=bar") {
		t.Fatalf("unrelated param removed: %q", got)
	}
}

func TestSanitizeURL_RedactsAgentSecret(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("/v1/tunnel/sess-1?agent_secret=mytoken&baz=qux")
	got := sanitizeURL(u)
	if strings.Contains(got, "mytoken") {
		t.Fatalf("agent_secret value leaked into log URL: %q", got)
	}
	if !strings.Contains(got, "agent_secret=***") {
		t.Fatalf("agent_secret placeholder missing: %q", got)
	}
	if !strings.Contains(got, "baz=qux") {
		t.Fatalf("unrelated param removed: %q", got)
	}
}

func TestSanitizeURL_RedactsBothSecrets(t *testing.T) {
	t.Parallel()
	u, _ := url.Parse("/v1/tunnel/sess-1?tunnel_secret=rs&agent_secret=as&x=1")
	got := sanitizeURL(u)
	if strings.Contains(got, "=rs") || strings.Contains(got, "=as") {
		t.Fatalf("secret values leaked: %q", got)
	}
	if !strings.Contains(got, "tunnel_secret=***") || !strings.Contains(got, "agent_secret=***") {
		t.Fatalf("placeholders missing: %q", got)
	}
	if !strings.Contains(got, "x=1") {
		t.Fatalf("unrelated param removed: %q", got)
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
	if strings.Contains(got, "tunnel_secret") || strings.Contains(got, "agent_secret") {
		t.Fatalf("unexpected redaction of clean params: %q", got)
	}
	if !strings.Contains(got, "foo=bar") || !strings.Contains(got, "baz=qux") {
		t.Fatalf("clean params unexpectedly stripped: %q", got)
	}
}
