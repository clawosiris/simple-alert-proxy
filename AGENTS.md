# AGENTS.md

Guidance for coding agents working in this repository.

## Project Shape

`simple-alert-proxy` is a Rust Axum/Tokio alert webhook gateway. It accepts
SigNoz and generic JSON webhooks, normalizes them into canonical alert events,
routes them to chat or webhook targets, persists alert and delivery state in
SQLite, and serves a small operator UI.

Treat alert delivery correctness, auth behavior, persistence, container
runtime behavior, and release/CI plumbing as first-class project behavior.

## Repository Basics

- Primary branch: `main`
- Preserved original-design branch: `simple-proxy`
- Current package version is in `Cargo.toml` and `Cargo.lock`.
- Public container image: `ghcr.io/clawosiris/simple-alert-proxy`
- Main example config: `examples/config.yaml`
- User-facing docs: `README.md`, `docs/SPEC.md`, `docs/COMPATIBILITY.md`
- Gateway planning docs: `docs/ALERT_WEBHOOK_GATEWAY_PRD.md`,
  `docs/ALERT_WEBHOOK_GATEWAY_OPENSPEC.md`

## Local Commands

Run the normal verification set before PRs that touch code, config behavior,
container behavior, or workflows:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
git diff --check
```

For workflow-only changes, also run `actionlint` when available. If it is not
installed locally, say so in the PR verification notes.

For docs-only changes, `git diff --check` is usually enough unless the change
touches examples that should be parsed by tests.

## GitHub And Branching

- `main` is protected. Do not bypass required review or required checks.
- Use short-lived branches and open PRs for changes.
- Include `Agent: Simple Alert` in GitHub-visible PR bodies, issue comments,
  reviews, and review replies when acting as this workspace agent.
- Use authenticated `gh` for private/authenticated repo state, checks, releases,
  issues, and PRs.
- Do not push directly to `main`.
- If a branch has been merged and is stale, delete it only after confirming it
  has no remaining useful unmerged content.

## Release Notes

Release prep currently means:

1. Bump `Cargo.toml`.
2. Bump the `simple-alert-proxy` package entry in `Cargo.lock`.
3. Update README GHCR pull examples.
4. Run the full local verification set.
5. Open and merge a version-bump PR.
6. Tag `vX.Y.Z` from current `main` after the PR merges.
7. Watch the Release workflow until the binary, checksum, container image, and
   SBOM assets are published.

The release workflow publishes source and container SBOMs in SPDX JSON and
CycloneDX JSON formats, plus SHA-256 checksums.

## Container Runtime Gotchas

The published container runs as the non-root `simple-alert-proxy` user. The
mounted data directory must be writable by that in-container UID/GID.

For persistent container runs, keep SQLite inside the mounted data directory:

```yaml
storage:
  type: "sqlite"
  path: "/var/lib/simple-alert-proxy/data/simple-alert-proxy.db"
```

`examples/config.yaml` is container-friendly and already uses that path. If a
user reports `unable to open database file: simple-alert-proxy.db`, suspect an
older copied config with a relative SQLite path or a bind-mounted directory that
is not writable by the container user.

The image sets `WORKDIR` to `/var/lib/simple-alert-proxy/data` so older relative
SQLite paths land in the data directory in newer releases, but absolute mounted
paths are still clearer.

## Auth Behavior

Inbound webhooks use `server.auth.bearer_token` when configured.

Management endpoints include `/debug/webhook`, `/api/*`, `/`, and `/ui`.
Management auth behavior is:

- `management.allow_unauthenticated: true` deliberately disables auth for
  management endpoints only.
- Otherwise `management.auth.bearer_token` is used when configured.
- If management auth is not configured, management endpoints fall back to
  `server.auth.bearer_token`.

Do not confuse management auth with inbound webhook auth. Leaving
`management.allow_unauthenticated: true` must not disable normal inbound webhook
bearer-token checks.

## Testing Priorities

Add or update tests when changing:

- webhook auth or management auth
- SigNoz parsing or generic integration mapping
- routing, receiver selection, grouping, retry, or dead-letter behavior
- SQLite persistence schema or migrations
- container defaults, config validation, or documented examples
- workflow/release behavior that affects published artifacts

Prefer focused regression tests for bugs reported from real container or alert
delivery usage.

## Safety

- Do not log secrets or raw bearer tokens.
- Debug payload logging should stay redacted by default.
- Be careful with user-provided webhook payloads and stored summaries.
- Do not remove compatibility behavior for `POST /webhooks/signoz` unless the
  deprecation path is explicit.
