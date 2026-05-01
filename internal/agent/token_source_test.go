package agent

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestDecodeTokenRequiresAccessToken(t *testing.T) {
	t.Parallel()

	_, err := decodeToken([]byte(`{"refresh_token":"refresh-only"}`))
	if err == nil {
		t.Fatal("decodeToken() error = nil, want non-nil")
	}
}

func TestParseOAuthErrorFallsBackToTrimmedBody(t *testing.T) {
	t.Parallel()

	got := parseOAuthError([]byte("  upstream temporarily unavailable  "))
	if got != "upstream temporarily unavailable" {
		t.Fatalf("parseOAuthError() = %q, want trimmed fallback", got)
	}
}

func TestShouldRefreshHonorsConfiguredSkew(t *testing.T) {
	t.Parallel()

	source := &oidcTokenSource{cfg: OIDCConfig{TokenRefreshSkew: 30 * time.Second}}

	if !source.shouldRefresh(&oauth2.Token{}) {
		t.Fatal("empty token should require refresh")
	}
	if source.shouldRefresh(&oauth2.Token{AccessToken: testAccessToken}) {
		t.Fatal("token without expiry should not require refresh")
	}
	if !source.shouldRefresh(&oauth2.Token{AccessToken: testAccessToken, Expiry: time.Now().Add(10 * time.Second)}) {
		t.Fatal("token within skew should require refresh")
	}
	if source.shouldRefresh(&oauth2.Token{AccessToken: testAccessToken, Expiry: time.Now().Add(2 * time.Minute)}) {
		t.Fatal("token outside skew should not require refresh")
	}
}

func TestParseOAuthErrorStructIgnoresMalformedJSON(t *testing.T) {
	t.Parallel()

	got := parseOAuthErrorStruct([]byte("not-json"))
	if got.Error != "" || got.ErrorDescription != "" {
		t.Fatalf("parseOAuthErrorStruct() = %+v, want zero value", got)
	}
	if strings.TrimSpace(parseOAuthError([]byte(""))) != "unknown error" {
		t.Fatal("empty oauth error body should return unknown error")
	}
}
