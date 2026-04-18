package agent

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

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
	_, _ = fmt.Fprintf(os.Stdout, "session: %s\n", sessionID)
	_, _ = fmt.Fprintf(os.Stdout, "tunnel : %s\n", tunnelURL)
	_, _ = fmt.Fprintf(os.Stdout, "relay  : %s\n", tokens.RelayToken)
	_, _ = fmt.Fprintf(os.Stdout, "agent  : %s\n", tokens.AgentToken)
}
