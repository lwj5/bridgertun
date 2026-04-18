// Package auth provides OIDC token verification.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// providerDiscoveryTimeout bounds the OIDC discovery + JWKS fetch on startup.
// Without it the default http.Client has no timeout and a slow provider
// blocks process start indefinitely.
const providerDiscoveryTimeout = 15 * time.Second

// Principal holds the verified claims extracted from an OIDC JWT.
type Principal struct {
	Subject  string
	Username string
	Tenant   string
	Scopes   []string
}

// Verifier validates JWTs against a configured OIDC provider.
type Verifier struct {
	issuer   string
	audience string
	verifier *oidc.IDTokenVerifier
}

// NewVerifier creates a Verifier for the given OIDC issuer URL and expected audience.
// Audience must be non-empty; the caller is responsible for failing fast otherwise.
func NewVerifier(ctx context.Context, issuer, audience string) (*Verifier, error) {
	discoveryCtx, cancel := context.WithTimeout(ctx, providerDiscoveryTimeout)
	defer cancel()
	httpClient := &http.Client{Timeout: providerDiscoveryTimeout}
	provider, err := oidc.NewProvider(oidc.ClientContext(discoveryCtx, httpClient), issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}
	return &Verifier{
		issuer:   issuer,
		audience: audience,
		verifier: provider.Verifier(&oidc.Config{ClientID: audience}),
	}, nil
}

// Verify validates the raw JWT and returns the extracted Principal on success.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Principal, error) {
	raw = strings.TrimPrefix(raw, "Bearer ")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty token")
	}
	tok, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	var claims struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
		Tenant            string `json:"tenant"`
		Scope             string `json:"scope"`
	}
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}
	return &Principal{
		Subject:  claims.Sub,
		Username: claims.PreferredUsername,
		Tenant:   claims.Tenant,
		Scopes:   strings.Fields(claims.Scope),
	}, nil
}
