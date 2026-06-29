"""D16.1 — coordinator-side validation + §7 enforcement of the self-describing
feature schema (feature_schema_design.md).

This is a byte-for-byte MIRROR of the tenant SDK's declaration contract — the
same pattern packages.py uses for `compute_package_digest`. The coordinator does
NOT import `auspexai_tenant`; the manifest is a published contract both sides
implement independently, so the coordinator stays decoupled from the SDK version
(and the CDDL/JSON-Schema mirrors in tenant-sdk are the normative spec).

KEEP IN LOCKSTEP with auspexai_tenant.manifest.FeatureDeclaration /
FeatureRange / ValidWhen / FeatureComparison (tenant-sdk/src/auspexai_tenant/
manifest.py) and schemas/manifest_v0_3.json. The per-kind §7 bounds rules are
deliberately NOT expressible in JSON Schema (the v0.3 schema punts them to "the
SDK model + the coordinator"), so they live here as code.

Two public surfaces, one declaration:
  * validate_feature_schema(schema) — SUBMIT time (api/experiments.py): the
    declared schema is well-formed and §7-safe (no free-text kind, per-kind
    bounds present, no nonsense cross-kind bounds). Returns [] when valid.
  * check_payload_conformance(schema, payload) — INGEST time (api/assignments.py):
    a worker's emitted result payload conforms to the declared schema (every
    emitted field declared, of its kind, within its bounds; no surprise fields).
    Returns [] when conforming. This turns §7 from "trust the executor" into "the
    coordinator enforces the contained shape."
"""

from __future__ import annotations

import re
from typing import Any

# Mirror of FeatureKind / FeatureRole / SetElementKind (manifest.py). There is
# DELIBERATELY no "text"/free-string kind — a string feature is a closed
# `categorical` or a `hash`. That is the §7 no-raw-text guarantee made structural.
KINDS = frozenset({"hash", "count", "numeric", "categorical", "ordinal", "set"})
ROLES = frozenset({"anchor", "summary", "provenance", "key", "diagnostic"})
SET_ELEMENT_KINDS = frozenset({"categorical", "numeric", "count", "hash"})
COMPARISON_RULES = frozenset({"exact", "numeric", "set_jaccard", "categorical_exact"})
VALID_WHEN_OPS = frozenset({">=", "<=", ">", "<", "==", "!="})

_CORE_FIELDS = ("meaning", "kind", "role", "change_means")
_KNOWN_FIELDS = frozenset(
    {
        *_CORE_FIELDS,
        "unit",
        "range",
        "categories",
        "algorithm",
        "element_kind",
        "max_cardinality",
        "invariant_to",
        "valid_when",
        "comparison",
    }
)

# A digest is lowercase hex of a fixed width per algorithm (sha256 ⇒ 64). Unknown
# algorithms fall back to "non-empty lowercase hex" so the contract still binds.
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_HASH_HEX_WIDTH = {"sha256": 64, "sha1": 40, "sha512": 128, "md5": 32}


# ── submit-time: validate the declaration itself ─────────────────────────────


def validate_feature_schema(schema: Any) -> list[str]:
    """Return a list of human-readable problems with a declared feature_schema
    (empty ⇒ valid). Mirrors the SDK FeatureDeclaration validators."""
    errors: list[str] = []
    if not isinstance(schema, dict):
        return ["feature_schema must be a table keyed by result-payload path"]
    if not schema:
        return ["feature_schema must declare at least one feature"]
    for path, decl in schema.items():
        errors.extend(_validate_declaration(path, decl))
    return errors


def _validate_declaration(path: Any, decl: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(path, str) or not _is_well_formed_path(path):
        errors.append(f"feature key {path!r} is not a well-formed dotted result path")
        # keep checking the body — a bad key + bad body should report both
    if not isinstance(decl, dict):
        return [*errors, f"feature {path!r}: declaration must be a table"]

    where = f"feature {path!r}"
    unknown = set(decl) - _KNOWN_FIELDS
    if unknown:
        errors.append(f"{where}: unknown field(s) {sorted(unknown)}")

    for f in _CORE_FIELDS:
        if f not in decl:
            errors.append(f"{where}: missing required '{f}'")
    for f in ("meaning", "change_means"):
        v = decl.get(f)
        if f in decl and (not isinstance(v, str) or not v.strip()):
            errors.append(f"{where}: '{f}' must be a non-empty string")

    kind = decl.get("kind")
    if "kind" in decl and kind not in KINDS:
        errors.append(
            f"{where}: kind {kind!r} is not §7-safe (use one of {sorted(KINDS)}; "
            "there is no free-text kind)"
        )
    role = decl.get("role")
    if "role" in decl and role not in ROLES:
        errors.append(f"{where}: role {role!r} must be one of {sorted(ROLES)}")

    # Per-kind bounds + cross-kind rejection (mirror manifest.py _kind_bounds).
    if kind in KINDS:
        errors.extend(_validate_kind_bounds(where, kind, decl))

    if "valid_when" in decl:
        errors.extend(_validate_valid_when(where, decl["valid_when"]))
    if "comparison" in decl:
        errors.extend(_validate_comparison(where, decl["comparison"]))
    if "invariant_to" in decl and not _is_str_list(decl["invariant_to"]):
        errors.append(f"{where}: 'invariant_to' must be a list of strings")
    return errors


def _validate_kind_bounds(where: str, kind: str, decl: dict) -> list[str]:
    errors: list[str] = []
    rng = decl.get("range")
    categories = decl.get("categories")

    # Required FOR THE KIND.
    if kind == "numeric" and rng is None:
        errors.append(f"{where}: kind 'numeric' requires a 'range'")
    if kind in ("categorical", "ordinal") and not categories:
        errors.append(
            f"{where}: kind '{kind}' requires a non-empty 'categories' "
            "(a CLOSED set — the §7 no-free-text guarantee)"
        )
    if kind == "hash" and not decl.get("algorithm"):
        errors.append(f"{where}: kind 'hash' requires an 'algorithm' (e.g. 'sha256')")
    if kind == "set" and (decl.get("element_kind") is None or decl.get("max_cardinality") is None):
        errors.append(f"{where}: kind 'set' requires 'element_kind' and 'max_cardinality'")

    # Bounds that do not belong to the kind are nonsense.
    if rng is not None and kind not in ("numeric", "count"):
        errors.append(f"{where}: 'range' is only valid for numeric/count, not '{kind}'")
    if categories is not None and kind not in ("categorical", "ordinal", "set"):
        errors.append(
            f"{where}: 'categories' is only valid for categorical/ordinal/set, not '{kind}'"
        )
    if decl.get("algorithm") is not None and kind != "hash":
        errors.append(f"{where}: 'algorithm' is only valid for hash, not '{kind}'")
    if (
        decl.get("element_kind") is not None or decl.get("max_cardinality") is not None
    ) and kind != "set":
        errors.append(
            f"{where}: 'element_kind'/'max_cardinality' are only valid for set, not '{kind}'"
        )

    # Shape of the bounds themselves.
    if rng is not None:
        errors.extend(_validate_range(where, rng))
    if categories is not None and not _is_str_list(categories):
        errors.append(f"{where}: 'categories' must be a list of strings")
    ek = decl.get("element_kind")
    if ek is not None and ek not in SET_ELEMENT_KINDS:
        errors.append(f"{where}: 'element_kind' {ek!r} must be one of {sorted(SET_ELEMENT_KINDS)}")
    mc = decl.get("max_cardinality")
    if mc is not None and not (isinstance(mc, int) and not isinstance(mc, bool) and mc >= 1):
        errors.append(f"{where}: 'max_cardinality' must be an integer >= 1")
    return errors


def _validate_range(where: str, rng: Any) -> list[str]:
    if not isinstance(rng, dict):
        return [f"{where}: 'range' must be a table with 'min' (and optional 'max')"]
    errors: list[str] = []
    if "min" not in rng:
        errors.append(f"{where}: 'range' requires 'min'")
    lo, hi = rng.get("min"), rng.get("max")
    if lo is not None and not _is_number(lo):
        errors.append(f"{where}: 'range.min' must be a number")
    if hi is not None and not _is_number(hi):
        errors.append(f"{where}: 'range.max' must be a number")
    if _is_number(lo) and _is_number(hi) and hi < lo:
        errors.append(f"{where}: 'range.max' ({hi}) < 'range.min' ({lo})")
    return errors


def _validate_valid_when(where: str, vw: Any) -> list[str]:
    if not isinstance(vw, dict):
        return [f"{where}: 'valid_when' must be a table {{field, op, value}}"]
    errors: list[str] = []
    if not isinstance(vw.get("field"), str) or not vw.get("field"):
        errors.append(f"{where}: 'valid_when.field' must be a non-empty string")
    if vw.get("op") not in VALID_WHEN_OPS:
        errors.append(f"{where}: 'valid_when.op' must be one of {sorted(VALID_WHEN_OPS)}")
    if "value" not in vw:
        errors.append(f"{where}: 'valid_when' requires a 'value'")
    return errors


def _validate_comparison(where: str, cmp: Any) -> list[str]:
    if not isinstance(cmp, dict):
        return [f"{where}: 'comparison' must be a table with a 'rule'"]
    errors: list[str] = []
    rule = cmp.get("rule")
    if rule not in COMPARISON_RULES:
        return [f"{where}: 'comparison.rule' must be one of {sorted(COMPARISON_RULES)}"]
    rel, abs_, mn = cmp.get("rel"), cmp.get("abs"), cmp.get("min")
    if rule == "numeric" and rel is None and abs_ is None:
        errors.append(f"{where}: comparison rule 'numeric' needs 'rel' or 'abs'")
    if rule == "set_jaccard" and not (_is_number(mn) and 0.0 <= mn <= 1.0):
        errors.append(f"{where}: comparison rule 'set_jaccard' needs 'min' in [0,1]")
    if rule in ("exact", "categorical_exact") and (
        rel is not None or abs_ is not None or mn is not None
    ):
        errors.append(f"{where}: comparison rule '{rule}' takes no rel/abs/min")
    return errors


# ── ingest-time: a payload conforms to the declared schema (§7) ──────────────


def check_payload_conformance(schema: dict, payload: Any) -> list[str]:
    """Return the §7 violations of `payload` against the declared `schema`
    (empty ⇒ conforming). Every emitted leaf must be a declared feature of its
    declared kind, within its bounds; every declared feature must be present.

    `schema` is assumed already structurally valid (validate_feature_schema ran
    at submit); this checks the DATA against it."""
    if not isinstance(payload, dict):
        return ["result payload is not an object"]
    flat = _flatten(payload)
    violations: list[str] = []

    for path, value in flat.items():
        decl = schema.get(path)
        if decl is None:
            violations.append(
                f"undeclared field {path!r} in result (not in the signed feature_schema — "
                "a §7 leak or executor/schema mismatch)"
            )
            continue
        violations.extend(_check_value(path, decl, value))

    for path in schema:
        if path not in flat:
            violations.append(f"declared feature {path!r} is absent from the result")
    return violations


def _check_value(path: str, decl: dict, value: Any) -> list[str]:
    kind = decl.get("kind")
    if value is None:
        return [f"feature {path!r} ({kind}) is null"]

    if kind == "hash":
        algo = decl.get("algorithm")
        if not isinstance(value, str) or not _HEX_RE.match(value):
            return [f"feature {path!r}: hash must be lowercase hex, got {_short(value)}"]
        width = _HASH_HEX_WIDTH.get(algo or "")
        if width is not None and len(value) != width:
            return [f"feature {path!r}: {algo} hash must be {width} hex chars, got {len(value)}"]
        return []

    if kind == "count":
        if not _is_integral(value):
            return [f"feature {path!r}: count must be an integer, got {_short(value)}"]
        return _check_range(path, decl.get("range"), int(value))

    if kind == "numeric":
        if not _is_number(value):
            return [f"feature {path!r}: numeric must be a number, got {_short(value)}"]
        return _check_range(path, decl.get("range"), float(value))

    if kind in ("categorical", "ordinal"):
        cats = decl.get("categories") or []
        if value not in cats:
            return [f"feature {path!r}: {_short(value)} not in declared categories {cats}"]
        return []

    if kind == "set":
        if not isinstance(value, (list, tuple)):
            return [f"feature {path!r}: set must be a list, got {_short(value)}"]
        mc = decl.get("max_cardinality")
        if isinstance(mc, int) and len(value) > mc:
            return [
                f"feature {path!r}: set has {len(value)} elements, exceeds max_cardinality {mc}"
            ]
        # element_kind is documentary here: top_tokens carries [token, count]
        # pairs, so element conformance is intentionally not strictly typed (the
        # design flags this feature as a §7 boundary handled at the certify gate).
        return []

    # Unknown kind: schema validation should have rejected it at submit.
    return [f"feature {path!r}: unknown kind {kind!r}"]


def _check_range(path: str, rng: Any, value: float) -> list[str]:
    if not isinstance(rng, dict):
        return []
    lo, hi = rng.get("min"), rng.get("max")
    if _is_number(lo) and value < lo:
        return [f"feature {path!r}: {value} < range.min {lo}"]
    if _is_number(hi) and value > hi:
        return [f"feature {path!r}: {value} > range.max {hi}"]
    return []


# ── helpers ──────────────────────────────────────────────────────────────────


def _flatten(payload: dict, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts to dotted paths, mirroring evidence.py `_flatten_into`:
    recurse INTO dicts only; lists/scalars are leaves (so `lexical.top_tokens`,
    a list, is one leaf keyed `lexical.top_tokens`). Keys are NOT `output.`-
    prefixed here — the manifest feature_schema keys the raw payload path."""
    out: dict[str, Any] = {}
    for k, v in payload.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out


def _is_well_formed_path(path: str) -> bool:
    # dotted identifiers, e.g. "lexical.type_token_ratio" / "response_sha256".
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", path))


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_integral(v: Any) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and v.is_integer()


def _is_str_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _short(v: Any, n: int = 40) -> str:
    s = repr(v)
    return s if len(s) <= n else s[:n] + "…"
