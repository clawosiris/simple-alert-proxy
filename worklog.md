2026-07-07

- Started Phase 1 of issue #10 on `alert-proxy_v2`.
- Goal: integration abstraction, SigNoz compatibility integration, generic JSON webhook normalization, validation, examples, tests, push after phase completion.
- ACP Codex session queued as `simple-alert phase1 acp codex`; local implementation proceeding in repo as source of truth.
- ACP Codex failed without usable output; continued local implementation.
- Added `src/integration.rs`, generic integration config, canonical-event routing, generic webhook handler, example fixture/config, docs, and tests.
- Completed Phase 1 locally, committed `46dc513`, pushed, and checked Phase 1 boxes in issue #10.
- Started Phase 2: SQLite event/delivery records, background retry worker, redacted delivery errors, persistence-before-delivery tests, retry/dead-letter tests.
- Completed Phase 2 locally, committed `1b82cc1`, pushed, and checked Phase 2 boxes in issue #10.
- Started Phase 3: alert group records keyed by fingerprint, lifecycle/audit state, read APIs, action APIs, and tests.
- Completed Phase 3 locally, committed `0375174`, pushed, and checked Phase 3 boxes in issue #10.
- Started Phase 4: static operator UI at `/` and `/ui`, API-backed group table/detail panel, lifecycle/replay controls, route smoke test.
- Completed Phase 4 locally, committed `bef78fd`, pushed, and checked Phase 4 boxes in issue #10.
- Started Phase 5: generic webhook, Slack, Mattermost, and Discord receiver configs/adapters plus source preset validation.
- Completed Phase 5 locally, committed `e5769ed`, pushed, and checked Phase 5 boxes in issue #10.
- Started Phase 6: escalation policy config, route policy selection, persisted escalation tasks, and cancellation on ack/resolve.
- Completed Phase 6 locally, committed `a6589bf`, pushed, and checked Phase 6 boxes in issue #10.
- Started Phase 7: optional intelligence config disabled by default, advisory enrichment records/API, and UI advisory section.
- Started E2E core alert proxy test work on `alert-proxy_v2`: synthetic webhook generator, mock receivers, severity routing, canonical output checks, and alert-group dedupe assertions.
- Completed E2E test locally; `cargo fmt --check`, `cargo test`, and `git diff --check` pass with 44 tests.
- Fixed PR #12 Rust CI Clippy failures on `alert-proxy_v2`: removed a single-binding match in the generic webhook handler and cloned mock receiver payloads before later awaits in the E2E test. Verified `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, and `cargo test` locally.

2026-07-10

- Started security workflow hardening on `security/sbom-scorecard`.
- Added SBOM support with Syft: standalone source SBOM workflow and release-time source/container SPDX JSON + CycloneDX JSON assets with checksums.
- Added OpenSSF Scorecard workflow with SARIF upload and public score publishing.
- Verified workflow syntax with `actionlint`, checked whitespace with `git diff --check`, and smoke-tested Syft source SBOM generation locally.
- Started release `v0.0.7`: bumped Cargo/README version references so the next release includes the SBOM and OpenSSF Scorecard workflow work from PR #23.
- Fixed repeated container SQLite startup failure for configs using relative `storage.path`: set the image working directory to `/var/lib/simple-alert-proxy/data`, pre-create it in the image, and add storage-open context for clearer container guidance.
- Updated `examples/config.yaml` to use the container-safe SQLite path directly so copied configs no longer need a manual storage path edit.
- Fixed `management.allow_unauthenticated: true` so it overrides the `server.auth` management fallback for `/debug/webhook` and other management endpoints.
- Started issue #30 implementation on `feat/user-management-rbac`: local users with Argon2id password hashes, SQLite-backed sessions, CSRF-protected cookie auth, bootstrap admin from `SIMPLE_ALERT_PROXY_BOOTSTRAP_ADMIN_PASSWORD`, admin user/team APIs, basic global RBAC, actor-aware lifecycle audit, WebUI login/admin panels, and docs/Quadlet env updates.
