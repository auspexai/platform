"""D16.2 — coordinator-side pre-registration validation + the submit-time anchor
(preregistration_design.md).

Like `feature_schema.py`, this is a MIRROR of the tenant SDK's declaration
contract — the coordinator does NOT import `auspexai_tenant`; the manifest is a
published contract both sides implement independently. KEEP IN LOCKSTEP with
auspexai_tenant.manifest.PreRegistration and schemas/manifest_v0_4.json.

Two public surfaces:
  * validate_pre_registration(manifest) — SUBMIT time (api/experiments.py):
    the declared block is well-formed, §7-safe (design-only fields), and
    CHECKABLE against the same manifest — every named feature exists in the
    feature_schema and carries the `comparison` envelope the design
    pre-registers (referenced, never duplicated — nothing to drift; the D16.5
    epistemic seam). Returns [] when valid.
  * build_pre_registration_predicate(...) — the canonical predicate the
    coordinator COSE-signs at submit and (via the hourly backfill) anchors in
    Rekor. Its anchor timestamp precedes the result attestation's anchor —
    `design ≺ data`, publicly provable (the design's "strong tier").
"""

from __future__ import annotations

import hashlib
import json as _json
from typing import Any

import cbor2

TIMESCALES = frozenset({"intra_experiment_rounds", "long_horizon", "inter_experiment"})

# (field, min_len, max_len) — the required free-text design fields. Length
# bounds mirror the SDK model; §7-safe because they describe the DESIGN, and
# they are bounded (never a raw-output channel).
_REQUIRED_TEXT = (
    ("hypothesis", 20, 2000),
    ("analysis_method", 10, 2000),
    ("decision_rule", 10, 2000),
    ("expected_result", 5, 2000),
    ("stopping_rule", 10, 1000),
)
_KNOWN_FIELDS = frozenset(
    {
        "version",
        "hypothesis",
        "analysis_method",
        "features",
        "timescale",
        "decision_rule",
        "expected_result",
        "stopping_rule",
        "comparison_keys",
        "min_replication",
    }
)


def validate_pre_registration(manifest: dict[str, Any]) -> list[str]:
    """Return a list of human-readable problems with a manifest's declared
    `pre_registration` (empty ⇒ valid). Mirrors the SDK PreRegistration model +
    the Manifest checkability validator. Assumes the caller only invokes this
    when the member is present."""
    errors: list[str] = []
    pr = manifest.get("pre_registration")
    if not isinstance(pr, dict):
        return ["pre_registration must be an object"]

    unknown = set(pr) - _KNOWN_FIELDS
    if unknown:
        errors.append(f"pre_registration has unknown fields: {sorted(unknown)}")
    # Blacklist form (mirrors the SDK validator): pre_registration entered the
    # contract at 0.4; any LATER superset version (0.5+) carries it too.
    if str(manifest.get("schema_version")) in ("0.1", "0.2", "0.3"):
        errors.append(
            'a manifest declaring pre_registration must set schema_version "0.4" or later'
        )

    version = pr.get("version", "0.1")
    if version != "0.1":
        errors.append(f"pre_registration version {version!r} is not supported (expect '0.1')")

    for field, lo, hi in _REQUIRED_TEXT:
        v = pr.get(field)
        if not isinstance(v, str) or not (lo <= len(v) <= hi):
            errors.append(f"pre_registration.{field} must be a string of {lo}..{hi} chars")

    if pr.get("timescale") not in TIMESCALES:
        errors.append(f"pre_registration.timescale must be one of {sorted(TIMESCALES)}")

    feats = pr.get("features")
    if not isinstance(feats, list) or not feats or not all(isinstance(f, str) for f in feats):
        errors.append("pre_registration.features must be a non-empty list of feature paths")
        feats = []
    keys = pr.get("comparison_keys", [])
    if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
        errors.append("pre_registration.comparison_keys must be a list of feature paths")
        keys = []
    min_repl = pr.get("min_replication")
    if min_repl is not None and (not isinstance(min_repl, int) or min_repl < 1):
        errors.append("pre_registration.min_replication must be a positive integer")

    # Checkability against the SAME manifest: the design is declared over
    # self-describing features, and the pre-registered envelope IS each named
    # feature's `comparison` (D16.1 §5 reconciliation — one declaration).
    fs = manifest.get("feature_schema")
    if not isinstance(fs, dict) or not fs:
        errors.append("pre_registration requires a feature_schema (D16.1)")
        return errors
    for path in feats:
        decl = fs.get(path)
        if not isinstance(decl, dict):
            errors.append(f"pre_registration feature {path!r} is not in feature_schema")
        elif not isinstance(decl.get("comparison"), dict):
            errors.append(
                f"pre_registration feature {path!r} declares no 'comparison' — "
                "the pre-registered envelope is the feature's comparison"
            )
    for key in keys:
        if key not in fs:
            errors.append(f"pre_registration comparison_key {key!r} is not in feature_schema")
    return errors


def build_pre_registration_predicate(
    *,
    manifest_hash: str,
    tenant_id: str,
    tenant_experiment_label: str,
    pre_registration: dict[str, Any],
    submitted_at: str,
) -> bytes:
    """Canonical CBOR predicate for the submit-time anchor. Binds the FULL
    manifest hash (the design lives inside the signed, content-addressed
    manifest — anchoring the hash anchors the design) plus the block itself for
    self-contained verification, and the coordinator-observed submit time.
    Deterministic given its inputs."""
    predicate = {
        "manifest_hash": manifest_hash,
        "tenant_id": tenant_id,
        "experiment_id": tenant_experiment_label,
        "pre_registration": pre_registration,
        "submitted_at": submitted_at,
    }
    return cbor2.dumps(predicate, canonical=True)


# ── D16.2-D: deviations (§5) ──────────────────────────────────────────────────

# Length bounds for the declaration's free-text members (mirrored by the SDK).
DEVIATION_TEXT_BOUNDS = (10, 2000)


def canonical_deviation_bytes(manifest_hash: str, what_changed: str, why: str) -> bytes:
    """The canonical declaration the TENANT signs (mirrored byte-for-byte by the
    SDK's `experiment deviate`): the original design's manifest hash + what
    changed + why. Sorted keys, compact separators — the manifest-signing
    convention applied to the deviation."""
    return _json.dumps(
        {"manifest_hash": manifest_hash, "what_changed": what_changed, "why": why},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def build_deviation_predicate(
    *,
    tenant_experiment_label: str,
    tenant_id: str,
    manifest_hash: str,
    what_changed: str,
    why: str,
    tenant_pubkey_hex: str,
    tenant_signature_b64: str,
    declared_at: str,
) -> bytes:
    """Canonical CBOR predicate for a deviation's coordinator anchor. Binds the
    ORIGINAL design (manifest_hash), the declaration digest, the DECLARER's own
    signature (accountability travels into the public log), and the
    coordinator-observed declared_at — so WHEN the analysis changed is publicly
    provable, separately from the immutable original."""
    predicate = {
        "experiment_id": tenant_experiment_label,
        "tenant_id": tenant_id,
        "manifest_hash": manifest_hash,
        "declaration_sha256": hashlib.sha256(
            canonical_deviation_bytes(manifest_hash, what_changed, why)
        ).hexdigest(),
        "tenant_pubkey_hex": tenant_pubkey_hex,
        "tenant_signature_b64": tenant_signature_b64,
        "declared_at": declared_at,
    }
    return cbor2.dumps(predicate, canonical=True)
