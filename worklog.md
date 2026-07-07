2026-07-07

- Started Phase 1 of issue #10 on `alert-proxy_v2`.
- Goal: integration abstraction, SigNoz compatibility integration, generic JSON webhook normalization, validation, examples, tests, push after phase completion.
- ACP Codex session queued as `simple-alert phase1 acp codex`; local implementation proceeding in repo as source of truth.
- ACP Codex failed without usable output; continued local implementation.
- Added `src/integration.rs`, generic integration config, canonical-event routing, generic webhook handler, example fixture/config, docs, and tests.
