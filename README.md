# AuspexAI Platform

The coordinator daemon and platform infrastructure for [AuspexAI](https://github.com/auspexai) — a volunteer-driven, open-source distributed compute network for AI safety research.

## Status

**LIVE — open beta.** The coordinator daemon runs at [coord.auspexai.network](https://coord.auspexai.network) (v0.1.170). M1–M8 shipped and well beyond — signed receipts + per-account trust-tier promotion, DOI minting, HF model catalog, benchmark board, Rekor anchoring, and settle/reap timers. CI green on Python 3.11 + 3.12. What's live:

- **System + auth:** `GET /api/v0/health` + `GET /api/v0/health/public`, `GET /api/v0/auth/whoami`
- **Tenants:** `POST/GET /api/v0/tenants`, `GET /api/v0/tenants/{id}`
- **Experiments:** `POST/GET /api/v0/experiments`, `GET /api/v0/experiments/{id}`, `POST /api/v0/experiments/{id}/actions/{approve,abort,archive}`
- **Accounts (M6a):** `POST /api/v0/accounts/oauth/exchange` — verifies an IdP access token (Phase 1: GitHub only), creates or fetches the (idp, idp_sub)-keyed account, mints a 5-min one-shot binding token for downstream binders
- **Workers (M6b):** `POST /workers/enroll` (anonymous; T0), `POST /workers/{id}/upgrade` (consumes M6a binding token; T0→T1), `POST /workers/{id}/heartbeat`, `GET /workers` (maintainer), `GET /workers/{id}` (self or maintainer), `POST /workers/{id}/actions/retire`
- **Work units (M6c):** `POST /experiments/{id}/work-units` (researcher, batch submit), `GET /experiments/{id}/work-units`, `GET .../work-units/{unit_id}`. **Per-job DB pattern** (per §5.7): each experiment with submitted work gets its own `<jobs_dir>/<experiment_id>.db` lazily on first submission. Manifest-swap protection enforces `work_unit.manifest_sha256 == experiment.manifest_hash` per §5.14.
- **Scheduler + assignments (M6d):** `GET /workers/{id}/assignments` (worker pulls next unit; first-fit, replication-target-aware), `POST /workers/{id}/assignments/{unit_id}/result` (verifies worker_pubkey match, inserts Result, attaches to Assignment, increments completions_so_far → marks unit `completed` at target). Per-job tables `assignments` + `results` join the work_units table in the same per-job DB.
- **Experiment lifecycle (M6e):** `POST /experiments/{id}/actions/pause` + `.../resume` (researcher own-tenant OR maintainer; pause = soft, stops new scheduler assignments, accepts in-flight). `POST .../actions/finalize-submissions` (researcher or maintainer; closes work-unit submission gate). **Auto-complete**: when submissions_finalized=true AND all units completed AND status=approved, the coordinator auto-transitions the experiment to `completed` with audit `actor_class=system`. New columns: `submissions_finalized`, `last_action_at`, `last_action_by_class` (visible on every experiment response for cross-role state-change attribution without waiting for M8's audit-log endpoint).
- **Five credential classes (per §5.18):** maintainer bearer token, researcher RFC 9421 HTTP Message Signature, anonymous-public, **worker** (M6b — RFC 9421 signed), and **system** (M6e — coordinator-driven actions; appears in audit_log only, never bound to an HTTP request)
- **Four field-exposure tags** filter responses field-by-field per credential class
- **SQLite control DB** with sequential migration framework; **per-job DBs** holding work_units + assignments + results
- **CLI:** `auspexai-coordinator {serve, token init/rotate/show}` + maintenance/timer subcommands (`settle`, `settle-outcomes`, `age-off`, `reap-orphan-jobs`, `refresh-hf-catalog`, `attestation`, `receipts`)

Subsequent milestones:
- **M7** — Receipts + per-account trust-tier promotion (§6.8.2) + retired_keys registry + reducer dispatch + public receipt-verify endpoint
- **M8** — Audit log list endpoint + alerts + SSE event bus

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

`GET /api/v0/health` returns liveness; `GET /api/v0/health/public` is the anonymous-public variant. Both pass through the M3 field-exposure filter (all health fields are `public`-tagged so the responses are equivalent today; later milestones add operator-only fields).

`auspexai-coordinator token init` writes a maintainer bearer token at `<state-dir>/maintainer.token`; pass it as `Authorization: Bearer <token>` on operator console requests.

## License

[AGPL-3.0](LICENSE) — strong copyleft so derivative work and network-served forks remain open. Patent grant via AGPL §11. Trademark on "AuspexAI" is controlled separately.

## Governance & policies

- [Governance](https://github.com/auspexai/.github/blob/main/GOVERNANCE.md) — roles, decision rules, recruitment, conflict of interest
- [Code of Conduct](https://github.com/auspexai/.github/blob/main/CODE_OF_CONDUCT.md) — community standards, reporting, escalation pathway
- [Contributing](https://github.com/auspexai/.github/blob/main/CONTRIBUTING.md) — DCO sign-off, PR workflow, RFC requirement for substantial architectural changes
- [Research Ethics Policy](https://github.com/auspexai/.github/blob/main/RESEARCH_ETHICS_POLICY.md) — what AI safety research can run on the network and how it's reviewed

## Watch this repo

The coordinator is live in open beta. Issues and discussion are welcome.
