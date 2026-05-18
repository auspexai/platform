# AuspexAI Platform

The coordinator daemon and platform infrastructure for [AuspexAI](https://github.com/auspexai) — a volunteer-driven, open-source distributed compute network for AI safety research.

## Status

**Phase 1 — Coordinator daemon in active development.** M1 (project skeleton + FastAPI app + health endpoints + CLI scaffold) is in place. Subsequent milestones land auth middleware (three credential classes per §5.18 of the [Principles & Scope](https://github.com/auspexai/.github)), field-exposure filtering, the SQLite control DB + per-job DB pattern, resource routes (tenants, experiments, workers, receipts, accounts, alerts), the Device Flow handler, scheduler, reducer dispatch, the `retired_keys` registry, and the SSE event bus.

## Scope

This repository holds:

- The coordinator daemon — durable state, restart recovery, worker pool management, scheduling
- Control DB / per-job DB persistence layer
- Job-and-result protocol — signed Ed25519 submissions, generic schema
- HTTP API (JSON) consumed by four Phase 1 UI surfaces (operator console, researcher dashboard, tenant onboarding form, public receipt verifier) plus the tenant SDK and worker daemon — see §5.18
- Operator CLI — submit, status, abort, workers, drain, token rotation, db migration, logs
- Test harness, including the synthetic tenant integration test that runs on every CI build

The platform is tenant-neutral by design: its data model speaks in `job`, `worker`, `work_unit`, `result`, `project` — never in domain-specific research terms. See the [`tenant-sdk`](https://github.com/auspexai/tenant-sdk) repository for the contract between platform and tenant code.

## Development

Python 3.11+. Quick start:

```bash
uv venv
uv pip install -e ".[dev]"
auspexai-coordinator serve              # listens on http://127.0.0.1:8080
pytest                                  # run tests
ruff check src tests                    # lint
ruff format --check src tests           # format check
```

`GET /api/v0/health` returns liveness; `GET /api/v0/health/public` is the anonymous-public variant (will gain field-exposure filtering in M3).

## License

[AGPL-3.0](LICENSE) — strong copyleft so derivative work and network-served forks remain open. Patent grant via AGPL §11. Trademark on "AuspexAI" is controlled separately.

## Governance & policies

- [Governance](https://github.com/auspexai/.github/blob/main/GOVERNANCE.md) — roles, decision rules, recruitment, conflict of interest
- [Code of Conduct](https://github.com/auspexai/.github/blob/main/CODE_OF_CONDUCT.md) — community standards, reporting, escalation pathway
- [Contributing](https://github.com/auspexai/.github/blob/main/CONTRIBUTING.md) — DCO sign-off, PR workflow, RFC requirement for substantial architectural changes
- [Research Ethics Policy](https://github.com/auspexai/.github/blob/main/RESEARCH_ETHICS_POLICY.md) — what AI safety research can run on the network and how it's reviewed

## Watch this repo

Activity will begin as Phase 1 ramps up. Until then, issues and discussion are welcome.
