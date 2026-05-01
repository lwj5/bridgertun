package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

const (
	grantTypeDeviceCode      = "urn:ietf:params:oauth:grant-type:device_code"
	providerDiscoveryTimeout = 15 * time.Second
	maxDevicePollInterval    = 30 * time.Second
)

// OIDCConfig holds the parameters required to create an OIDCTokenSource.
type OIDCConfig struct {
	IssuerURL        string
	ClientID         string
	ClientSecret     string
	Audience         string
	DeviceScope      string
	DevicePoll       time.Duration
	TokenRefreshSkew time.Duration
}

// TokenSource retrieves and caches OAuth2 access tokens.
type TokenSource interface {
	AccessToken(ctx context.Context) (string, error)
	Invalidate()
}

type oidcTokenSource struct {
	cfg OIDCConfig

	httpClient *http.Client
	tokenURL   string
	deviceURL  string

	mu           sync.Mutex
	token        *oauth2.Token
	forceRefresh bool
}

type providerMetadata struct {
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// NewOIDCTokenSource discovers the OIDC provider at issuerURL and returns a
// TokenSource that uses the device-code flow and refresh tokens.
func NewOIDCTokenSource(ctx context.Context, cfg OIDCConfig) (TokenSource, error) { //nolint:ireturn
	discoveryCtx, cancel := context.WithTimeout(ctx, providerDiscoveryTimeout)
	defer cancel()
	discoveryClient := &http.Client{Timeout: providerDiscoveryTimeout}
	provider, err := oidc.NewProvider(oidc.ClientContext(discoveryCtx, discoveryClient), cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}

	var metadata providerMetadata
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("decode oidc metadata: %w", err)
	}
	if metadata.DeviceAuthorizationEndpoint == "" {
		return nil, fmt.Errorf("issuer does not expose device_authorization_endpoint")
	}

	endpoint := provider.Endpoint()
	if endpoint.TokenURL == "" {
		return nil, fmt.Errorf("issuer does not expose token endpoint")
	}

	return &oidcTokenSource{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		tokenURL:   endpoint.TokenURL,
		deviceURL:  metadata.DeviceAuthorizationEndpoint,
	}, nil
}

func (s *oidcTokenSource) AccessToken(ctx context.Context) (string, error) {
	token, err := s.ensureToken(ctx)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func (s *oidcTokenSource) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forceRefresh = true
	if s.token != nil {
		s.token.Expiry = time.Unix(0, 0)
	}
}

func (s *oidcTokenSource) ensureToken(ctx context.Context) (*oauth2.Token, error) {
	s.mu.Lock()
	current := s.token
	forceRefresh := s.forceRefresh
	s.mu.Unlock()

	if current != nil && !forceRefresh && !s.shouldRefresh(current) {
		return current, nil
	}

	if current != nil && current.RefreshToken != "" {
		fresh, err := s.refreshWithToken(ctx, current.RefreshToken)
		if err == nil {
			s.setToken(fresh)
			return fresh, nil
		}
		log.Warn().Err(err).Msg("refresh token failed, re-authenticating with device flow")
	}

	fresh, err := s.authorizeWithDeviceCode(ctx)
	if err != nil {
		return nil, err
	}
	s.setToken(fresh)
	return fresh, nil
}

func (s *oidcTokenSource) setToken(token *oauth2.Token) {
	s.mu.Lock()
	s.token = token
	s.forceRefresh = false
	s.mu.Unlock()
}

func (s *oidcTokenSource) shouldRefresh(token *oauth2.Token) bool {
	if token.AccessToken == "" {
		return true
	}
	if token.Expiry.IsZero() {
		return false
	}
	return time.Now().Add(s.cfg.TokenRefreshSkew).After(token.Expiry)
}

func (s *oidcTokenSource) authorizeWithDeviceCode(ctx context.Context) (*oauth2.Token, error) {
	form := url.Values{}
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}
	if s.cfg.DeviceScope != "" {
		form.Set("scope", s.cfg.DeviceScope)
	}
	if s.cfg.Audience != "" {
		form.Set("audience", s.cfg.Audience)
	}

	status, body, err := s.postForm(ctx, s.deviceURL, form)
	if err != nil {
		return nil, err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		oauthErr := parseOAuthError(body)
		return nil, fmt.Errorf("device authorization failed: %s", oauthErr)
	}

	var deviceResponse deviceAuthResponse
	if err := json.Unmarshal(body, &deviceResponse); err != nil {
		return nil, fmt.Errorf("decode device authorization response: %w", err)
	}
	if deviceResponse.DeviceCode == "" {
		return nil, fmt.Errorf("device authorization response missing device_code")
	}

	verificationURL := deviceResponse.VerificationURI
	if deviceResponse.VerificationURIComplete != "" {
		verificationURL = deviceResponse.VerificationURIComplete
	}
	log.Info().
		Str("verification_url", verificationURL).
		Str("user_code", deviceResponse.UserCode).
		Msg("complete login in your browser")

	pollInterval := s.cfg.DevicePoll
	if deviceResponse.Interval > 0 {
		serverInterval := time.Duration(deviceResponse.Interval) * time.Second
		if serverInterval > pollInterval {
			pollInterval = serverInterval
		}
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}

	expiresAt := time.Now().Add(10 * time.Minute)
	if deviceResponse.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(deviceResponse.ExpiresIn) * time.Second)
	}

	for {
		if time.Now().After(expiresAt) {
			return nil, fmt.Errorf("device authorization timed out")
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("device auth: %w", ctx.Err())
		case <-time.After(pollInterval):
		}

		token, oauthErr, err := s.exchangeDeviceCode(ctx, deviceResponse.DeviceCode)
		if err != nil {
			return nil, err
		}
		if oauthErr == nil {
			return token, nil
		}

		switch oauthErr.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			pollInterval += 5 * time.Second
			if pollInterval > maxDevicePollInterval {
				pollInterval = maxDevicePollInterval
			}
			continue
		case "access_denied":
			return nil, fmt.Errorf("device authorization denied by user")
		case "expired_token":
			return nil, fmt.Errorf("device authorization code expired")
		default:
			return nil, fmt.Errorf("device authorization failed: %s", oauthErr)
		}
	}
}

func (s *oidcTokenSource) exchangeDeviceCode(
	ctx context.Context,
	deviceCode string,
) (*oauth2.Token, *oauthErrorResponse, error) {
	form := url.Values{}
	form.Set("grant_type", grantTypeDeviceCode)
	form.Set("device_code", deviceCode)
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}

	status, body, err := s.postForm(ctx, s.tokenURL, form)
	if err != nil {
		return nil, nil, err
	}
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		token, err := decodeToken(body)
		if err != nil {
			return nil, nil, err
		}
		return token, nil, nil
	}

	oauthErr := parseOAuthErrorStruct(body)
	if oauthErr.Error == "" {
		return nil, nil, fmt.Errorf("device token exchange failed with http %d", status)
	}
	return nil, &oauthErr, nil
}

func (s *oidcTokenSource) refreshWithToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", s.cfg.ClientID)
	if s.cfg.ClientSecret != "" {
		form.Set("client_secret", s.cfg.ClientSecret)
	}

	status, body, err := s.postForm(ctx, s.tokenURL, form)
	if err != nil {
		return nil, err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		oauthErr := parseOAuthError(body)
		return nil, fmt.Errorf("refresh token grant failed: %s", oauthErr)
	}

	token, err := decodeToken(body)
	if err != nil {
		return nil, err
	}
	if token.RefreshToken == "" {
		token.RefreshToken = refreshToken
	}
	return token, nil
}

func (s *oidcTokenSource) postForm(ctx context.Context, endpoint string, form url.Values) (int, []byte, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := s.httpClient.Do(httpRequest)
	if err != nil {
		return 0, nil, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("read response: %w", err)
	}
	return response.StatusCode, body, nil
}

func decodeToken(raw []byte) (*oauth2.Token, error) {
	var response tokenResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if response.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}

	token := &oauth2.Token{
		AccessToken:  response.AccessToken,
		TokenType:    response.TokenType,
		RefreshToken: response.RefreshToken,
	}
	if response.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(response.ExpiresIn) * time.Second)
	}
	return token, nil
}

func parseOAuthError(raw []byte) string {
	errorResponse := parseOAuthErrorStruct(raw)
	if errorResponse.Error == "" {
		trimmed := strings.TrimSpace(string(raw))
		if trimmed == "" {
			return "unknown error"
		}
		return trimmed
	}
	if errorResponse.ErrorDescription != "" {
		return errorResponse.Error + ": " + errorResponse.ErrorDescription
	}
	return errorResponse.Error
}

func parseOAuthErrorStruct(raw []byte) oauthErrorResponse {
	var errorResponse oauthErrorResponse
	_ = json.Unmarshal(raw, &errorResponse)
	return errorResponse
}
