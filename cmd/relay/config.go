package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

type config struct {
	WSAddr  string `env:"RELAY_WS_ADDR"  envDefault:":8443"`
	APIAddr string `env:"RELAY_API_ADDR" envDefault:":9000"`

	OIDCIssuerURL     string `env:"OIDC_ISSUER_URL,required"`
	OIDCAudience      string `env:"OIDC_AUDIENCE,required"`
	OIDCAgentClientID string `env:"OIDC_AGENT_CLIENT_ID,required"`

	ValkeyAddr     string `env:"VALKEY_ADDR,required"`
	ValkeyPassword string `env:"VALKEY_PASSWORD"`
	ValkeyDB       int    `env:"VALKEY_DB"  envDefault:"0"`
	ValkeyTLS      bool   `env:"VALKEY_TLS" envDefault:"false"`

	NodeID string `env:"RELAY_NODE_ID"`

	RelayBaseURL string `env:"RELAY_URL,required"`

	AllowedOrigins []string `env:"RELAY_ALLOWED_ORIGINS" envSeparator:","`

	WSPingInterval      time.Duration `env:"WS_PING_INTERVAL"      envDefault:"30s"`
	WSPongTimeout       time.Duration `env:"WS_PONG_TIMEOUT"       envDefault:"10s"`
	ProxyRequestTimeout time.Duration `env:"PROXY_REQUEST_TIMEOUT" envDefault:"30s"`
	StreamIdleTimeout   time.Duration `env:"STREAM_IDLE_TIMEOUT"   envDefault:"60s"`
	ShutdownDrain       time.Duration `env:"SHUTDOWN_DRAIN"        envDefault:"15s"`
	ResumeGraceTTL      time.Duration `env:"RESUME_GRACE_TTL"      envDefault:"5m"`

	TLSCertFile string `env:"TLS_CERT_FILE"`
	TLSKeyFile  string `env:"TLS_KEY_FILE"`

	MaxRequestBodyBytes int64 `env:"MAX_REQUEST_BODY_BYTES" envDefault:"8388608"` // 8 MiB

	TrustedProxiesRaw string `env:"TRUSTED_PROXIES"`

	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`

	// Parsed from TrustedProxiesRaw after env parsing.
	TrustedProxies []*net.IPNet `env:"-"`
}

func loadConfig() (*config, error) {
	cfg := &config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	if cfg.NodeID == "" {
		cfg.NodeID, _ = os.Hostname()
	}
	if cfg.NodeID == "" {
		return nil, fmt.Errorf("RELAY_NODE_ID could not be determined")
	}

	cfg.RelayBaseURL = strings.TrimRight(cfg.RelayBaseURL, "/")
	parsedURL, err := url.Parse(cfg.RelayBaseURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return nil, fmt.Errorf("RELAY_URL must be an absolute http(s) URL: %q", cfg.RelayBaseURL)
	}

	if cfg.ResumeGraceTTL <= 0 {
		return nil, fmt.Errorf("RESUME_GRACE_TTL must be > 0")
	}
	if cfg.ProxyRequestTimeout <= 0 {
		return nil, fmt.Errorf("PROXY_REQUEST_TIMEOUT must be > 0")
	}
	if cfg.MaxRequestBodyBytes <= 0 {
		return nil, fmt.Errorf("MAX_REQUEST_BODY_BYTES must be > 0")
	}

	if cfg.TrustedProxies, err = parseCIDRList(cfg.TrustedProxiesRaw); err != nil {
		return nil, err
	}

	return cfg, nil
}

// parseCIDRList parses a comma-separated list of CIDRs or bare IPs into
// *net.IPNet. Bare IPs become /32 or /128.
func parseCIDRList(raw string) ([]*net.IPNet, error) {
	if raw == "" {
		return nil, nil
	}
	var out []*net.IPNet
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(p); err == nil {
			out = append(out, n)
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: invalid CIDR or IP %q", p)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}
