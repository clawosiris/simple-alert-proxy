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
podman build -t simple-alert-proxy:ci .
```

## Pull Requests

- Keep changes focused.
- Include tests when behavior changes.
- Update docs or examples when config, API, or deployment behavior changes.
- Prefer small reviewable commits over a giant mystery blob.
