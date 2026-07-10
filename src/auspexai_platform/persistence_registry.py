"""Persistence registry — the bounded-growth decision for every persistent table.

The A11 lesson (from the D22-B receipt leak, `persistent_artifact_reaper_audit.md`):
a persistent artifact that accumulates with no bounded reaper is a leak the
behavior-oriented property suite never catches. The durable fix is to make the
decision EXPLICIT and TEST-ENFORCED: every persistent table must be classified
here as either

  - REAPED           — a bounded reaper (timer / DELETE-on-event) prunes it, or
  - GROWS_BY_DESIGN  — it is a permanent record bounded by a finite real-world
                       domain (one row per result / experiment / account / …),
                       with the bound stated.

`tests/test_persistence_reaper_conformance.py` asserts the registry exactly
matches the live schema (control + per-job), so a new migration CANNOT add a
table without someone making the bounded-growth decision here — the
generalization of the `settle-outcomes`/`settle-prestage`/`reap-orphan-jobs`
reapers from three artifacts to the whole schema. Mirrors the A6 firewall-
conformance suite (a named index that fails if a member is added/dropped).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Persistence:
    """Exactly one of `reaper` / `grows_by_design` is set (validated)."""

    reaper: str | None = None  # the bounded reaper, if REAPED
    grows_by_design: str | None = None  # the finite-domain bound, if GROWS_BY_DESIGN

    def __post_init__(self) -> None:
        if bool(self.reaper) == bool(self.grows_by_design):
            raise ValueError("set exactly one of reaper / grows_by_design (non-empty)")


def _reaped(mechanism: str) -> Persistence:
    return Persistence(reaper=mechanism)


def _grows(bound: str) -> Persistence:
    return Persistence(grows_by_design=bound)


# ── Control DB (coordinator.db) ──────────────────────────────────────────────
CONTROL_DB_PERSISTENCE: dict[str, Persistence] = {
    "schema_migrations": _grows("migration ledger — 1 row per applied migration (framework)"),
    "accounts": _grows("account identities — permanent, bounded by real accounts"),
    "account_keys": _grows("account signing keys — permanent identity record, per account"),
    "account_oauth_bindings": _grows("account↔OAuth identity bindings — permanent, per account"),
    "tenants": _grows(
        "tenant identities — permanent (manual DELETE for cleanup is not a growth reaper)"
    ),
    "tenant_applications": _grows(
        "tenant application records — permanent, bounded by #applications"
    ),
    "workers": _grows(
        "worker roster / identity — permanent; a delete-reaper is VERIFIED not warranted (2026-07-07): "
        "a withdrawn worker's pubkey lives in retired_keys to BLOCK re-enrollment (M7a), so deleting it "
        "would re-open a withdrawn key (a security regression); 'offline' is computed from the heartbeat "
        "(no stale-roster growth surface); live 0 reapable. Bounded by real workers, negligible"
    ),
    "vouches": _grows("the vouch / trust graph — permanent, bounded by #vouches"),
    "experiments": _grows(
        "the permanent research record — bounded by real experiments; never deleted in-code "
        "(the per-job DB FILE is reaped when orphaned → reap-orphan-jobs)"
    ),
    "manifests": _grows("experiment manifests — permanent, bounded by #experiments"),
    "receipt_index": _grows("the trust ledger — 1 row per issued receipt (1/result); permanent"),
    "receipt_outcomes": _grows(
        "D22-B terminal receipt-outcome markers — bounded by #results; permanent"
    ),
    "anchor_outcomes": _grows(
        "Rekor anchor retry/terminal state (A11) — bounded by #anchorable artifacts; "
        "transient rows self-clear on success, terminal rows are the permanent un-anchorable record"
    ),
    "divergence_index": _grows(
        "divergence events (firewall #1 signal) — bounded by #results; permanent"
    ),
    "schema_rejection_index": _grows("schema-rejection events — bounded by #results; permanent"),
    "attestations": _grows(
        "result-set attestations — permanent signed record, bounded by #result-sets"
    ),
    "certified_profiles": _grows("promotion-gate certifications — permanent signed record"),
    "pre_registrations": _grows(
        "pre-registrations (design≺data) — permanent, bounded by #experiments"
    ),
    "pre_registration_deviations": _grows("design-side deviation records — permanent (D16.2)"),
    "publication_records": _grows(
        "benchmark publications — permanent signed record, bounded by #publications"
    ),
    "driver_status": _grows(
        "driver-liveness telemetry (0059) — 1 upserted row per experiment, bounded by "
        "#experiments (which are never deleted in-code); the driver's small last-known state"
    ),
    "doi_mints": _grows(
        "DOI-mint bookkeeping (0060) — 1 upserted row per experiment for idempotent/resumable "
        "Zenodo mints; permanent, bounded by #experiments-with-a-DOI"
    ),
    "audit_log": _grows(
        "the audit trail — append-only BY DESIGN; permanent governance/contestation evidence"
    ),
    "retired_keys": _grows("key-rotation history — permanent (needed to verify old signatures)"),
    "releases": _grows("release records — permanent, bounded by #releases"),
    "result_transfers": _grows("result-transfer bookkeeping — bounded by #results"),
    "assessment_policy": _grows("singleton policy row (assessment auto-approval gate) — ~1 row"),
    "promotion_policy": _grows("singleton policy row (trust-promotion gate) — ~1 row"),
    "trust_model_policy": _grows("singleton policy row (equal-trust flip toggle) — ~1 row"),
    "model_requests": _grows("DORMANT — retired model-request queue (AUD-18); no active producer"),
    "software_requests": _grows(
        "DORMANT — retired software-request queue (AUD-18); no active producer"
    ),
    "orcid_oauth_states": _reaped("DELETE on consume/expiry — transient OAuth handshake state"),
    "model_prestage": _reaped(
        "settle-prestage timer — abandon stale 'requested' + reap dead-worker rows; UNIQUE(model,worker)-bounded"
    ),
}

# ── Per-job DB (jobs/<experiment_id>.db) ─────────────────────────────────────
PER_JOB_DB_PERSISTENCE: dict[str, Persistence] = {
    "work_units": _grows(
        "the experiment's units — bounded by unit count; settled (not deleted) by settle/settle-outcomes"
    ),
    "assignments": _grows("unit->worker offers — bounded by units x offers within the per-job DB"),
    "results": _grows(
        "result rows — permanent research record; heavy payload_json blanked by age-off past retention"
    ),
    "receipts": _grows("per-job receipt cache — bounded by results within the per-job DB"),
    "unit_consensus": _grows("per-unit consensus records — bounded by units within the per-job DB"),
}

# ── Persistent artifacts that are NOT SQL tables (documented; not schema-discoverable) ──
# Listed for completeness; the file-layer reapers are covered by their own tests.
NON_TABLE_ARTIFACTS: dict[str, Persistence] = {
    "jobs/<experiment_id>.db (per-job DB FILES)": _reaped(
        "reap-orphan-jobs (orphans: no experiment row); grows-by-design for live experiments (the permanent record)"
    ),
    "hf_catalog.json (D23 HF catalog cache)": _reaped(
        "single-file atomic overwrite — self-bounding (no growth)"
    ),
}
