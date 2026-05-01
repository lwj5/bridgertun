# Bridgertun

Bridgertun - BRIJ-ur-tun (/ˈbrɪdʒərtən/) - comprises of two components. The relay component and agent binaries running on
users' machines connect over a persistent WebSocket, authenticated via
an OIDC provider, and expose their local HTTP services to callers through a
per-session tunnel URL.

This repo also ships a reference Go agent under [`cmd/agent`](cmd/agent/) that
implements the compatibility contract documented in this README end-to-end.
Agent binaries in other languages remain fully supported.

## Architecture

```
             ┌───────────────────────────────────────────────┐
             │                relay (this repo)              │
             │                                               │
 agent ──────►  :8443  /v1/agent/config   (OIDC discovery)  │
 agent ─WS──►  :8443  /v1/agent/connect                     │
             │           │                                   │
             │           ▼                                   │
             │      session registry (in-mem + Valkey)       │
             │           │                                   │
 caller ─────►  :9000  /v1/tunnel/{sessionID}/*  ───────────►│──► agent's local service
             │                                               │
             └───────────────────────────────────────────────┘
```

Two listeners in one process:

| Port    | Purpose                                                            |
| ------- | ------------------------------------------------------------------ |
| `:8443` | Agent endpoints: config discovery (`/v1/agent/config`) + WebSocket |
| `:9000` | Proxy + operator API                                               |

Multiple relay nodes share state via Valkey. Cross-node requests are routed
through Valkey Streams so SSE and large responses stream correctly without
buffering.

## Quick start (local dev)

```bash
# Start Keycloak (port 8080) and Valkey (port 6379)
make compose-up

# Configure a Keycloak realm and service account, then export env vars:
export OIDC_ISSUER_URL=http://localhost:8080/realms/tunnel
export OIDC_AUDIENCE=relay
export OIDC_AGENT_CLIENT_ID=agent
export VALKEY_ADDR=localhost:6379
export RELAY_URL=http://localhost:9000

make run
```

The relay starts on `:8443` (agent WebSocket) and `:9000` (relay API).

## Agent connection

Agents authenticate with an OIDC access token obtained through the Device
Authorization Grant and declare a per-session credential that
callers must present to reach the tunnel.

Per-session credentials use a **two-tier** model. The relay enforces Tier 1
(relay ↔ caller); the agent itself enforces Tier 2 (caller ↔ agent,
end-to-end). The relay **never** sees the Tier 2 secret, so a compromised
relay cannot forge requests to the agent.

The agent must **bcrypt the Tier 1 secret locally** and submit only the
hash in a header. Plaintext credentials are rejected with `400`.

```
GET ws://localhost:8443/v1/agent/connect
Authorization: Bearer <oidc-jwt>
X-Tunnel-Secret-Hash: <bcrypt-hash>
```

On connect the relay sends a `hello` envelope containing the session ID and
the tunnel URL the caller should use:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "hello",
  "tunnel_url": "https://relay.example.com/v1/tunnel/550e8400-.../"
}
```

## Calling through a tunnel

Once an agent is connected, any HTTP client can proxy requests through it.
The caller presents **both** tiers on every request — Tier 1 to the relay,
Tier 2 to the agent. Either tier can be sent as a header or as a URL query
param, so SSE / EventSource clients that can't set headers are supported.

| Tier | Header                   | URL fallback       | Checked by |
| ---- | ------------------------ | ------------------ | ---------- |
| 1    | `X-Tunnel-Auth: …`       | `?tunnel_secret=…` | Relay      |
| 2    | `X-Tunnel-Agent-Auth: …` | `?agent_secret=…`  | Agent      |

**Header mode (normal HTTP clients):**

```bash
curl -H "X-Tunnel-Auth: <relay_token>" \
     -H "X-Tunnel-Agent-Auth: <agent_token>" \
     https://relay.example.com/v1/tunnel/<sessionID>/api/health
```

**URL mode (EventSource / webhook producers that can't set headers):**

```bash
curl -N "https://relay.example.com/v1/tunnel/<sessionID>/events?tunnel_secret=<relay_token>&agent_secret=<agent_token>"
```

The relay strips `tunnel_*` query params before forwarding to the agent, so
Tier 1 credentials do not leak onto the agent-side wire. If callers
provide `agent_secret` in the URL, the relay moves it into
`X-Tunnel-Agent-Auth` before forwarding and removes `agent_secret` from the
forwarded query.

SSE and chunked responses stream end-to-end without buffering; the relay
flushes each chunk immediately after it arrives from the agent.

## Reference agent

A ready-to-run Go agent lives in [`cmd/agent`](cmd/agent/). It generates fresh
per-session Tier 1/Tier 2 tokens on every connect, bcrypts the Tier 1 token
locally, prints both tokens to stdout for the operator, verifies
`X-Tunnel-Agent-Auth` on every incoming request, strips Tier 2 + relay-internal
credentials before hitting the local service, and reconnects with exponential
backoff when the WebSocket drops.

```bash
make run-agent ARGS="--relay-url=http://localhost:8443 --local-url=http://127.0.0.1:3000"
```

On first connect (and again only if refresh/offline tokens become invalid),
the agent prints a browser verification URL and user code. After sign-in,
tokens are kept in memory and refreshed automatically.

On connect the agent prints the session block to stdout:

```
session      : 550e8400-e29b-41d4-a716-446655440000
tunnel       : http://localhost:9000/v1/tunnel/550e8400-.../
relay token  : <relay_token>
agent token  : <agent_token>
example url  : http://localhost:9000/v1/tunnel/550e8400-.../?agent_secret=<agent_token>&tunnel_secret=<relay_token>
example headers:
  X-Tunnel-Auth: <relay_token>
  X-Tunnel-Agent-Auth: <agent_token>
```

Hand `relay` and `agent` to whoever is calling (see [Calling through a
tunnel](#calling-through-a-tunnel)).

### Agent configuration

The agent is configured via CLI flags, and the same values may also be
provided via environment variables. OIDC issuer URL and client ID are
fetched automatically from the relay at startup (`GET /v1/agent/config`).

| Flag                | Env var     | Default      | Description                                          |
| ------------------- | ----------- | ------------ | ---------------------------------------------------- |
| `-r`, `--relay-url` | `RELAY_URL` | **required** | Relay base URL, e.g. `https://relay.example.com`     |
| `-l`, `--local-url` | `LOCAL_URL` | **required** | Base URL of the local HTTP service to expose         |
| `--json-logs`       | `JSON_LOGS` | `false`      | Emit JSON logs instead of the default console output |
| `-v`, `--log-level` | `LOG_LEVEL` | `info`       | zerolog level (`debug`, `info`, `warn`, `error`)     |

## Agent compatibility contract

This section is the authoritative relay/agent contract for agent
implementations in any language.

### Two-tier per-session authentication

Per-session auth is split into two independent tokens:

| Token         | Known to relay                   | Checked by | Caller sends as                                   |
| ------------- | -------------------------------- | ---------- | ------------------------------------------------- |
| `relay_token` | bcrypt hash only (at WS connect) | Relay      | `X-Tunnel-Auth` or `tunnel_secret` query param    |
| `agent_token` | never transmitted to the relay   | Agent      | `X-Tunnel-Agent-Auth` (relay maps `agent_secret`) |

Requirements:

- Generate both tokens independently from a CSPRNG on every new WS session.
- Use 32 random bytes per token, encoded as URL-safe base64 or hex.
- Bcrypt only the Tier 1 token (`relay_token`) locally with cost at least 10.
- Send only the bcrypt hash to `/v1/agent/connect` using `X-Tunnel-Secret-Hash`.
- Keep `agent_token` in memory; do not send it to the relay at connect time.

### Operator handoff and secret handling

After connection, the agent should print a handoff block containing session
ID, tunnel URL, `relay_token`, and `agent_token`, so operators can share both
credentials out of band.

`agent_token` is a bearer credential and should not be written to normal
runtime logs after session establishment.

### Per-request agent authentication

For every incoming `request` envelope, the agent must:

1. Read Tier 2 credential from `X-Tunnel-Agent-Auth` header.
2. Compare against in-memory `agent_token` using constant-time comparison.
3. Return `response_head` with status `401` followed by `response_end` on
   mismatch.
4. Do not dispatch unauthorized requests to the local service.

### Credential stripping before local forwarding

Before issuing the local HTTP request, remove:

- `X-Tunnel-Agent-Auth` header
- `X-Tunnel-Session-Internal` header
- `Host` header (allow client transport to set it)

The relay strips `tunnel_*` and `agent_secret` query parameters on its side,
while promoting `agent_secret` to `X-Tunnel-Agent-Auth`. Together this keeps
Tier 1 and Tier 2 secrets out of downstream service logs.

### Translating request envelopes to local HTTP

Agent behavior:

- Build local URL as `LOCAL_SERVICE_URL` base plus envelope path (including raw query).
- Copy remaining headers after stripping rules.
- Forward envelope body as raw bytes.
- Attach a cancelable context per in-flight request.
- Forward `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto`
  unless local ingress policy requires changes.

### Streaming requirements

Agents must stream response bodies and never buffer complete responses before
writing envelopes.

Streaming rules:

- Send `response_head` as soon as local response status and headers are known.
- Stream body incrementally via `response_chunk` envelopes.
- End with `response_end` when complete.
- Keep chunks reasonably small (less than about 64 KiB recommended).
- Relay frame limit is 16 MiB per frame.

SSE and long-lived responses:

- Preserve low latency by flushing chunks promptly.
- Relay enforces `STREAM_IDLE_TIMEOUT` (default 60 s) between chunks.
- If local upstream may be silent longer than that, emit periodic keepalive
  comment chunks.

### Cancellation and multiplexing

The relay multiplexes many request IDs over one agent WebSocket.

Agent requirements:

- Handle each `request` envelope concurrently so one slow request does not
  block others.
- Serialize WebSocket writes through one sender loop to avoid concurrent frame
  write corruption.
- Track `requestID -> cancel function` for in-flight local calls.
- On `request_cancel`, cancel matching local request context.
- After cancellation, do not send `response_end` for that request ID.

### Heartbeat and reconnection

Relay heartbeat defaults:

- Ping interval: 30 s
- Pong timeout: 10 s

Agent requirements:

- Keep read loop responsive so WS library can process ping/pong.
- Treat prolonged silence (ping interval + pong timeout) as a dead link.
- Reconnect persistently with exponential backoff capped at 60 s plus jitter
  (about ±25%).
- Reset backoff attempt counter after 60 s of stable connection.
- On reconnect, reuse existing Tier 1 and Tier 2 tokens and send
  `X-Tunnel-Resume-Session` to resume the prior session. Generate tokens only
  once on first connect; if the relay declines the resume (grace window
  expired), accept the new session ID but keep the same tokens.
- Drop all in-flight local request contexts on disconnect.

### Error handling contract

- If the local HTTP call fails before headers, send `error` envelope.
- If it fails after partial body streaming, send `error` after streamed chunks.
- If an inbound envelope cannot be decoded, log and ignore it (do not close WS).
- If outbound send buffer is saturated, fail only the affected request when
  possible rather than stalling the whole connection.

## Wire protocol

WebSocket binary frames only. Each frame is a length-prefixed JSON header
followed by the raw body bytes — no base64 on the hot path.

```
offset  size  name       notes
0       4     hdr_len    big-endian uint32
4       H     hdr_json   UTF-8 JSON, fields per Envelope (Body excluded)
4+H     B     body       raw bytes, 0..N; presence implied by total length

invariants:
  4 + H + B <= 16 MiB (per-frame cap)
```

The JSON header mirrors the in-memory envelope minus `Body`:

```go
type Envelope struct {
    ID      string              // correlation UUID per HTTP exchange
    Type    string              // see constants below
    Method  string
    Path    string
    Headers map[string][]string
    Status  int
    Body    []byte              // trailing raw bytes (not JSON)
    EOF     bool
    Error   string
    TunnelURL string
}
```

| Type             | Direction     | Meaning                                                 |
| ---------------- | ------------- | ------------------------------------------------------- |
| `hello`          | relay → agent | Session established; contains session ID and tunnel URL |
| `request`        | relay → agent | Forwarded HTTP request                                  |
| `response_head`  | agent → relay | HTTP status + headers                                   |
| `response_chunk` | agent → relay | Body bytes (stream)                                     |
| `response_end`   | agent → relay | Stream complete                                         |
| `request_cancel` | relay → agent | Caller disconnected; abort local request                |
| `error`          | agent → relay | Agent-side failure                                      |
| `ping` / `pong`  | both          | Keepalive (30 s interval, 10 s timeout)                 |

## Operator API

Requires an OIDC token with the `relay:operator` scope.

| Method   | Path                | Description                                |
| -------- | ------------------- | ------------------------------------------ |
| `GET`    | `/v1/sessions`      | List active sessions (`?sub=`, `?tenant=`) |
| `GET`    | `/v1/sessions/{id}` | Get session metadata                       |
| `DELETE` | `/v1/sessions/{id}` | Force-disconnect an agent                  |
| `GET`    | `/healthz`          | Liveness probe                             |
| `GET`    | `/readyz`           | Readiness probe (checks Valkey)            |

## Configuration

All settings are environment variables:

| Variable                 | Default           | Description                                                           |
| ------------------------ | ----------------- | --------------------------------------------------------------------- |
| `RELAY_WS_ADDR`          | `:8443`           | Agent WebSocket listener                                              |
| `RELAY_API_ADDR`         | `:9000`           | Proxy + operator API listener                                         |
| `RELAY_URL`              | **required**      | Override the `tunnel_url` base (e.g. `https://relay.example.com`)     |
| `RELAY_ALLOWED_ORIGINS`  | —                 | Comma-separated Origin patterns accepted for agent WebSocket upgrades |
| `RELAY_NODE_ID`          | hostname          | Unique ID for this instance in the Valkey registry                    |
| `OIDC_ISSUER_URL`        | **required**      | OIDC provider issuer URL (discovery endpoint)                         |
| `OIDC_AUDIENCE`          | **required**      | Expected `aud` claim in agent JWTs                                    |
| `OIDC_AGENT_CLIENT_ID`   | **required**      | Client ID served to agents via `GET /v1/agent/config`                 |
| `VALKEY_ADDR`            | **required**      | `host:port` of Valkey instance                                        |
| `VALKEY_PASSWORD`        | —                 | Valkey password                                                       |
| `VALKEY_DB`              | `0`               | Valkey logical database index                                         |
| `VALKEY_TLS`             | `false`           | Connect to Valkey over TLS                                            |
| `TRUSTED_PROXIES`        | —                 | Comma-separated CIDRs/IPs whose `X-Forwarded-For` is honored          |
| `RELAY_ALLOWED_ORIGINS`  | —                 | Comma-separated Origin patterns accepted for agent WebSocket upgrades |
| `WS_PING_INTERVAL`       | `30s`             | How often the relay pings each agent                                  |
| `WS_PONG_TIMEOUT`        | `10s`             | Max wait for a pong before closing                                    |
| `PROXY_REQUEST_TIMEOUT`  | `30s`             | Per-request idle timeout (non-streaming)                              |
| `RESUME_GRACE_TTL`       | `5m`              | How long a detached session is allowed to resume with the same ID     |
| `STREAM_IDLE_TIMEOUT`    | `60s`             | Max silence between chunks on a streaming response                    |
| `SHUTDOWN_DRAIN`         | `15s`             | Time to drain in-flight requests on SIGTERM                           |
| `MAX_REQUEST_BODY_BYTES` | `8388608` (8 MiB) | Maximum request body the relay buffers                                |
| `TLS_CERT_FILE`          | —                 | TLS certificate (both listeners); omit for plain HTTP                 |
| `TLS_KEY_FILE`           | —                 | TLS private key                                                       |
| `LOG_LEVEL`              | `info`            | zerolog level (`debug`, `info`, `warn`, `error`)                      |

## Multi-node

Run multiple relay instances pointing at the same Valkey. Each instance
registers its sessions in Valkey and subscribes to its own control channel.
When the API receives a proxy request for a session owned by another node, it
publishes the request over Valkey and streams the response back through a
dedicated Valkey Stream key. No sticky sessions or load-balancer affinity
required.

## Limitations

- Request body is buffered in full (max `MAX_REQUEST_BODY_BYTES`); request-side streaming is not yet supported.
- WebSocket tunneling (WS-through-WS) is not supported; only plain HTTP and SSE.
- TLS termination is expected to happen at the ingress layer (nginx, ALB, etc.) in production.
