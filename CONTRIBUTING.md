# Contributing

Thanks for taking a look at `simple-alert-proxy`.

## Before You Start

- Open an issue for bugs, feature requests, or design changes before investing in a large pull request.
- For security problems, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development

Run the same checks used by CI before opening a pull request:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

Container changes should also keep this passing:

```bash
podman build --format docker -t simple-alert-proxy:ci .
```

### Black-box system tests

The normal Rust suite covers unit, parser/adapter contracts, storage behavior,
and in-process Axum integration behavior. The binary system suite covers the
production process boundary: real configuration files, HTTP/HTTPS listeners,
authentication, routing and persistence, receiver traffic, retry/replay,
restart recovery, startup failures, and signal handling.

Run it against the release-profile binary:

```bash
cargo build --release --locked
SYSTEM_E2E_BIN=target/release/simple-alert-proxy \
  python3 -m unittest -v tests.system.test_binary_e2e
```

The container suite covers image metadata, the non-root runtime user, the image
health check, mounted config/data/certificates, receiver delivery, persistent
restart state, TLS, signal handling, and invalid startup config. It requires a
Linux Podman environment with `host.containers.internal` support:

```bash
sudo podman build --format docker -t simple-alert-proxy:e2e .
CONTAINER_ENGINE="sudo podman" \
CONTAINER_E2E_IMAGE=simple-alert-proxy:e2e \
  python3 -m unittest -v tests.container.test_container_e2e
```

Both suites are hermetic: they use temporary configuration, SQLite databases,
ports, certificates, local mock receivers, containers, and networks. They do
not contact public receiver services. CI publishes redacted process logs and
receiver captures only when a system job fails.

Use the smallest layer that catches the regression:

- unit/contract tests for parsing, mapping, storage, and receiver formatting;
- in-process integration or BDD scenarios for application behavior without OS
  process concerns;
- binary system tests for listener, startup, signal, TLS, and restart behavior;
- container system tests for packaging, mounts, image health, and runtime user
  behavior.

## Pull Requests

- Keep changes focused.
- Include tests when behavior changes.
- Update docs or examples when config, API, or deployment behavior changes.
- Prefer small reviewable commits over a giant mystery blob.
