"""Promotion-gate certification primitive (RFC 0001 / Research Ethics Policy §6.7).

A certification's signed body is a `CertificateEnvelope` — the content-bound,
canonical record of what is certified. The maintainer's `certify` command builds
one from a released starter's manifest, runs the machine-checkable subset of the
§6.7.2 bar (`auto_check`), and COSE-signs the canonical bytes with the coordinator
key (low-risk path: maintainer-token-authenticated; an external advisor co-signs
for high-risk). At submit, the coordinator resolves the submission's
`package_sha256` in the registry and runs `match()` — the locked-field check
(§6.7.3) deciding whether the run is the EXACT certified profile and thus rides
its standing approval (§6.7.5).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from auspexai_platform.assessment import class_track
from auspexai_platform.receipts.signing import SigningKey, cose_sign1_encode


@dataclass(frozen=True)
class CertificateEnvelope:
    """The canonical, signed body of a certification."""

    package_sha256: str
    snapshot_version: str
    tenant_id: str
    profile_name: str
    research_class: str | None
    sensitive_content_flags: list[str]
    model_ids: list[str]
    replication_floor: int
    max_units_ceiling: int | None
    duration_hours_ceiling: float | None
    certified_by: str
    advisor: str | None
    certified_at: str  # ISO-8601 UTC
    # C7: the LOCKED tolerance envelope — {feature_path: comparison-rule} for every
    # feature_schema entry with a `comparison`. Binding it makes §9.2 enforceable
    # (a run can't silently WIDEN the envelope and still resolve as certified).
    # None = a legacy cert issued before envelope-binding (not locked; reissue to bind).
    comparison_envelope: dict[str, Any] | None = None

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization the certificate signs. Sorted keys +
        normalized list order, so the same envelope always yields the same bytes
        (sign-time and verify-time agree)."""
        d = asdict(self)
        d["sensitive_content_flags"] = sorted(d["sensitive_content_flags"])
        d["model_ids"] = sorted(d["model_ids"])
        # Legacy (unbound) certs omit the key entirely, so their canonical bytes stay
        # byte-identical to pre-binding — old signatures keep verifying.
        if d.get("comparison_envelope") is None:
            d.pop("comparison_envelope", None)
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class CheckResult:
    passed: bool
    failures: list[str]


def auto_check(manifest: dict[str, Any]) -> CheckResult:
    """The MACHINE-checkable subset of the §6.7.2 safe-to-expose bar. The human
    signs the JUDGMENT criteria (benign probe panel, genuinely low risk, §4
    compliance); these are the mechanical gates the tool verifies and presents:

      §6.7.2(2) no sensitive-content flags · (6) routable at low sensitivity → a
      routine research_class · (7) no high-risk capability → a builtin reducer and
      no real-execution/training-adjacent escape hatch.

    A pass here is NECESSARY, not sufficient — the maintainer's signature is the
    sufficient condition."""
    failures: list[str] = []

    flags = manifest.get("sensitive_content_flags") or []
    if flags:
        failures.append(f"§6.7.2(2): sensitive_content_flags must be empty (got {sorted(flags)})")

    rc = manifest.get("research_class")
    if class_track(rc) != "routine":
        failures.append(
            f"§6.7.2(7): research_class {rc!r} is not a routine class "
            "(elevated/unknown class → not a certified starter)"
        )

    reducer_kind = (manifest.get("reducer") or {}).get("kind", "")
    if not str(reducer_kind).startswith("builtin"):
        failures.append(
            f"§6.7.2(7): reducer {reducer_kind!r} is not a builtin "
            "(custom reducer dispatch is a high-risk capability)"
        )

    if manifest.get("requires_real_execution"):
        failures.append(
            "§6.7.2(7): requires_real_execution is out of scope for a certified starter"
        )

    return CheckResult(passed=not failures, failures=failures)


def envelope_from_manifest(
    manifest: dict[str, Any],
    *,
    snapshot_version: str,
    profile_name: str,
    certified_by: str,
    advisor: str | None = None,
    certified_at: str | None = None,
    replication_floor: int | None = None,
    max_units_ceiling: int | None = None,
    duration_hours_ceiling: float | None = None,
) -> CertificateEnvelope:
    """Assemble the certificate envelope from a built starter manifest. Locked
    fields are read from the manifest; the floor and ceilings default to the
    manifest's declared values unless the certifier overrides them."""
    executor = manifest.get("executor") or {}
    package_sha256 = executor.get("package_sha256")
    if not package_sha256:
        raise ValueError("manifest has no executor.package_sha256 — build the package first")
    tenant_id = manifest.get("tenant_id")
    if not tenant_id:
        raise ValueError("manifest has no tenant_id")

    comparison_envelope = comparison_envelope_from_manifest(manifest)

    declared_duration = manifest.get("expected_duration_hours")
    if duration_hours_ceiling is None and declared_duration is not None:
        duration_hours_ceiling = float(declared_duration)

    return CertificateEnvelope(
        package_sha256=package_sha256,
        snapshot_version=snapshot_version,
        tenant_id=tenant_id,
        profile_name=profile_name,
        research_class=manifest.get("research_class"),
        sensitive_content_flags=list(manifest.get("sensitive_content_flags") or []),
        model_ids=[m["id"] for m in (manifest.get("models") or []) if m.get("id")],
        replication_floor=(
            replication_floor
            if replication_floor is not None
            else int(manifest.get("replication_factor", 1))
        ),
        max_units_ceiling=max_units_ceiling,
        duration_hours_ceiling=duration_hours_ceiling,
        certified_by=certified_by,
        advisor=advisor,
        certified_at=certified_at or datetime.now(UTC).isoformat(),
        comparison_envelope=comparison_envelope,
    )


def comparison_envelope_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """The tolerance envelope the cert LOCKS: {feature_path: comparison-rule} for
    every feature_schema entry that declares a `comparison` (the agreement predicate
    features + the exact anchor). Deterministic — the same feature_schema always
    yields the same envelope. Empty {} for a manifest with no comparison features
    (still bound, distinct from a legacy unbound cert's None)."""
    fs = manifest.get("feature_schema") or {}
    out: dict[str, Any] = {}
    if isinstance(fs, dict):
        for feature, decl in fs.items():
            if isinstance(decl, dict) and isinstance(decl.get("comparison"), dict):
                out[feature] = decl["comparison"]
    return out


def sign_certificate(envelope: CertificateEnvelope, *, signing_key: SigningKey) -> bytes:
    """COSE_Sign1 over the canonical envelope. Low-risk path: the coordinator key,
    maintainer-token-authenticated. A high-risk advisor co-signature is layered
    separately (not in this primitive)."""
    return cose_sign1_encode(payload=envelope.canonical_bytes(), signing_key=signing_key)


def match(manifest: dict[str, Any], cert: Any) -> CheckResult:
    """The submit-time locked-field check (§6.7.3): does this submitted manifest
    run the EXACT certified profile? `cert` is a CertifiedProfileRecord. Only the
    declared SAFE knobs (driver cadence/rounds — which are not in the manifest)
    may differ; every LOCKED field must match the certified envelope."""
    failures: list[str] = []

    executor = manifest.get("executor")
    pkg = executor.get("package_sha256") if isinstance(executor, dict) else None
    if pkg != cert.package_sha256:
        failures.append("executor package digest differs from the certified profile")
    if manifest.get("research_class") != cert.research_class:
        failures.append("research_class differs from the certified profile")
    if sorted(manifest.get("sensitive_content_flags") or []) != sorted(
        cert.sensitive_content_flags
    ):
        failures.append("sensitive_content_flags differ from the certified profile")
    man_models = sorted(m["id"] for m in (manifest.get("models") or []) if m.get("id"))
    if man_models != sorted(cert.model_ids):
        failures.append("model set differs from the certified profile")
    if int(manifest.get("replication_factor", 1)) < cert.replication_floor:
        failures.append(
            f"replication_factor is below the certified floor ({cert.replication_floor})"
        )
    declared_duration = manifest.get("expected_duration_hours")
    if (
        cert.duration_hours_ceiling is not None
        and declared_duration is not None
        and float(declared_duration) > cert.duration_hours_ceiling
    ):
        failures.append(
            f"expected_duration_hours exceeds the certified ceiling ({cert.duration_hours_ceiling})"
        )
    # C7 §9.2: the cert LOCKS the tolerance envelope. A cert issued before
    # envelope-binding (comparison_envelope is None) is legacy → skip (it predates
    # the lock; reissue to bind it). A bound cert must match EXACTLY — any drift
    # (tighten OR widen) requires a reissue; widening additionally trips the §9.2
    # review at reissue time. This is what makes "widening re-issues the cert"
    # enforceable rather than declarative.
    cert_env = getattr(cert, "comparison_envelope", None)
    if cert_env is not None and comparison_envelope_from_manifest(manifest) != cert_env:
        failures.append(
            "tolerance envelope differs from the certified profile (§9.2 widening review)"
        )
    return CheckResult(passed=not failures, failures=failures)


def is_newer_build(manifest: dict[str, Any], cert: Any) -> bool:
    """True iff `manifest` is a NEWER BUILD of `cert`'s certified profile: it
    matches the certification on every locked field EXCEPT the executor package
    digest (same models / research_class / sensitive flags / replication /
    duration, different package). That is the precise "re-certify this" signal —
    an unrelated experiment from the same tenant fails on more than just the
    package, so it is not flagged. A run that fully matches is already certified.
    """
    res = match(manifest, cert)
    return (not res.passed) and len(res.failures) == 1 and "package digest" in res.failures[0]


def certified_match(manifest: dict[str, Any], repo: Any) -> Any:
    """Resolve a submitted manifest to its ACTIVE certification, or None — the
    single check both the submit-time floor exemption and the auto-approval branch
    use. Combines the registry lookup (by content-addressed package digest) with
    the §6.7.3 locked-field `match`. `repo` is a CertifiedProfileRepository."""
    executor = manifest.get("executor")
    pkg = executor.get("package_sha256") if isinstance(executor, dict) else None
    if not pkg:
        return None
    cert = repo.get_by_package(pkg)
    if cert is None or not cert.is_active:
        return None
    return cert if match(manifest, cert).passed else None
