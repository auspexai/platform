# AuspexAI Platform

The coordinator daemon and platform infrastructure for [AuspexAI](https://github.com/auspexai) — a volunteer-driven, open-source distributed compute network for AI safety research.

## Status

**Phase 0 — Foundation.** Code begins in Phase 1, starting with a coordinator daemon that runs Sentinel's D6 experiment on the existing lab cluster. The architectural primitives (tenant-neutral core, signed protocol, tenant SDK boundary) are in place from the first lines of code.

## Scope

This repository will hold:

- The coordinator daemon — durable state, restart recovery, worker pool management, scheduling
- Control DB / per-job DB persistence layer
- Job-and-result protocol — signed Ed25519 submissions, generic schema
- Operator CLI — submit, status, abort, workers, drain, logs
- Test harness, including the synthetic tenant integration test that runs on every CI build

The platform is tenant-neutral by design: its data model speaks in `job`, `worker`, `work_unit`, `result`, `project` — never in domain-specific research terms. See the [`tenant-sdk`](https://github.com/auspexai/tenant-sdk) repository for the contract between platform and tenant code.

## License

[AGPL-3.0](LICENSE) — strong copyleft so derivative work and network-served forks remain open. Patent grant via AGPL §11. Trademark on "AuspexAI" is controlled separately.

## Governance & policies

- [Governance](https://github.com/auspexai/.github/blob/main/GOVERNANCE.md) — roles, decision rules, recruitment, conflict of interest
- [Code of Conduct](https://github.com/auspexai/.github/blob/main/CODE_OF_CONDUCT.md) — community standards, reporting, escalation pathway
- [Contributing](https://github.com/auspexai/.github/blob/main/CONTRIBUTING.md) — DCO sign-off, PR workflow, RFC requirement for substantial architectural changes
- [Research Ethics Policy](https://github.com/auspexai/.github/blob/main/RESEARCH_ETHICS_POLICY.md) — what AI safety research can run on the network and how it's reviewed

## Watch this repo

Activity will begin as Phase 1 ramps up. Until then, issues and discussion are welcome.
