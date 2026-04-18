# AGENTS.md

## Purpose
This repo implements the relay component of the Bridgertun system and includes a reference Go agent in `cmd/agent`.
Use this file to understand how to work on the relay, agent compatibility contract, auth rules, and repository conventions.

## What to know first
- Read `README.md` for architecture, tunnel authentication, and agent compatibility contract.

## Build and test
- `make run` — build and run the relay locally
- `make run-agent ARGS="..."` — build and run the reference agent
- `make test` — run unit tests
- `make lint` — run `golangci-lint run ./...`
- `make update` — run `go mod tidy` and refresh `vendor/`

## Repository layout
- `cmd/relay` — relay server entrypoint
- `cmd/agent` — reference Go agent implementation that connects to the relay
- `internal/api` — public operator API, proxy handling, and HTTP server logic
- `internal/ws` — agent WebSocket connect logic and tunnel auth
- `internal/registry` — session registry and Valkey stream integration
- `internal/proxy` — request/response streaming and tunnel forwarding
- `internal/auth` — OIDC auth helpers
- `internal/wire` — envelope types and tunnel message protocol

## Key conventions for AI agents
- Use full descriptive names whenever possible.
- Keep Go idioms like `ctx`, `err`, `ok`, `wg`, `w`, `r`.
- Prefer `registry` over `reg`, `webSocketServer` over `wsSrv`, `tunnelURL` over `tunnel_url` in variable names.
- There is exactly one auth kind: bearer (`X-Tunnel-Secret-Hash` / bcrypt hash).
- `ParseTunnelAuth` returns a bcrypt hash string or error; `verifyBearer` is called directly.

## Important behavior to preserve
- Relay and agent auth is two-tiered; the relay never sees the agent secret.
- The relay strips `tunnel_*` query params and forwards Tier 2 auth as `X-Tunnel-Agent-Auth`.
- Agent implementations should keep Tier 2 secrets only in memory and never log them.
- The reference agent must generate fresh per-session tokens and bcrypt the Tier 1 token locally.

## Relevant files
- `README.md` — architecture, auth contract, and protocol details
- `Makefile` — canonical build/test commands
