package agent

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type sessionTokens struct {
	RelayToken     string
	RelayTokenHash string
	AgentToken     string
}

func newSessionTokens(bcryptCost int) (*sessionTokens, error) {
	relayToken, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("relay token: %w", err)
	}
	agentToken, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("agent token: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(relayToken), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt relay token: %w", err)
	}
	return &sessionTokens{
		RelayToken:     relayToken,
		RelayTokenHash: string(hash),
		AgentToken:     agentToken,
	}, nil
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// printOperatorBlock writes the session details to stdout for the operator to
// hand off to whoever is calling. Per the README compatibility contract,
// agent_token is a bearer credential and should never reach INFO-level logs
// once the session is live.
func printOperatorBlock(sessionID, tunnelURL string, tokens *sessionTokens) {
	_, _ = fmt.Fprint(os.Stdout, formatOperatorBlock(sessionID, tunnelURL, tokens))
}

func formatOperatorBlock(sessionID, tunnelURL string, tokens *sessionTokens) string {
	var builder strings.Builder

	_, _ = fmt.Fprintf(&builder, "session      : %s\n", sessionID)
	_, _ = fmt.Fprintf(&builder, "tunnel       : %s\n", tunnelURL)
	_, _ = fmt.Fprintf(&builder, "relay token  : %s\n", tokens.RelayToken)
	_, _ = fmt.Fprintf(&builder, "agent token  : %s\n", tokens.AgentToken)
	_, _ = fmt.Fprintf(&builder, "example url  : %s\n", tunnelURLWithCredentials(tunnelURL, tokens))
	_, _ = fmt.Fprint(&builder, "example headers:\n")
	_, _ = fmt.Fprintf(&builder, "  %s: %s\n", "X-Tunnel-Auth", tokens.RelayToken)
	_, _ = fmt.Fprintf(&builder, "  %s: %s\n", "X-Tunnel-Agent-Auth", tokens.AgentToken)

	return builder.String()
}

func tunnelURLWithCredentials(tunnelURL string, tokens *sessionTokens) string {
	parsed, err := url.Parse(tunnelURL)
	if err != nil {
		return tunnelURL
	}

	query := parsed.Query()
	query.Set("tunnel_secret", tokens.RelayToken)
	query.Set("agent_secret", tokens.AgentToken)
	parsed.RawQuery = query.Encode()

	return parsed.String()
}

func exampleHeaders(tokens *sessionTokens) http.Header {
	headers := make(http.Header, 2)
	headers.Set("X-Tunnel-Auth", tokens.RelayToken)
	headers.Set("X-Tunnel-Agent-Auth", tokens.AgentToken)
	return headers
}
