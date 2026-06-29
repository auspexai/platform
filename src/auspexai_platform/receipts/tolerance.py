"""C7 within_cell_tolerance — the declared-envelope agreement predicate.

Partitions a unit's replica results into those that AGREE (every predicate
feature within its declared `comparison` envelope of a deterministic
representative) and the OUTLIERS. The envelope IS the per-feature `comparison`
in the signed feature_schema (feature_schema_design.md §5) — this reducer READS
it, never re-declares it. Bounded, in-coordinator, no tenant code (C7 is a
BUILTIN reducer; arbitrary reduction stays C9, gated to T3/R3 — D1 amendment).

The C15 fix made concrete: under within_cell_exact one version-skewed worker
zeroes the whole unit; here it is one OUTLIER among the floor-many agreeing
workers, recorded but not consensus-blocking.

§7: compares only the contained, structured features the executor already emits
(counts, categories, rounded numerics, set cardinalities) — never raw text.
See tolerance_consensus_design.md (RATIFIED 2026-06-29).
"""

from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass
from typing import Any

from auspexai_platform.feature_schema import _flatten, _is_number
from auspexai_platform.hashing import semantic_hash

# The comparison rules that form the agreement predicate. A pure `exact` rule
# (the hash anchor, e.g. response_sha256) deliberately does NOT appear here: it
# STRENGTHENS the basis (Inc 2) but never blocks consensus (§9 Q3).
_PREDICATE_RULES = frozenset({"numeric", "set_jaccard", "categorical_exact"})


@dataclass(frozen=True)
class ToleranceAgreement:
    """The partition of a unit's results under the tolerance envelope."""

    agreed: bool
    agreeing_indices: list[int]  # indices into the input results list
    outlier_indices: list[int]
    representative: dict[str, Any]  # the deterministic per-feature consensus value
    representative_hash: str | None  # canonical hash of `representative` (None when no consensus)
    per_feature_spread: dict[str, float]  # Inc 2 evidence seed (numeric range / set distance)


def predicate_features(feature_schema: dict, tolerance_features: list[str] | None) -> list[str]:
    """Resolve the feature paths whose `comparison` forms the agreement predicate.

    Explicit `tolerance_features` wins (validated at submit to reference declared
    features); otherwise every declared feature carrying a non-`exact` comparison.
    Returned sorted for determinism."""
    if tolerance_features:
        return sorted(p for p in tolerance_features if p in feature_schema)
    out = [
        path
        for path, decl in feature_schema.items()
        if isinstance((decl or {}).get("comparison"), dict)
        and decl["comparison"].get("rule") in _PREDICATE_RULES
    ]
    return sorted(out)


def validate_tolerance_reducer(reducer: dict, feature_schema: dict | None) -> list[str]:
    """Submit-time validation for a within_cell_tolerance reducer (empty ⇒ valid).

    The envelope is READ from the feature_schema, so a tolerance reducer must have
    something to compare: a feature_schema with at least one predicate feature (a
    non-`exact` `comparison`), and any explicit `tolerance_features` must name
    declared features that carry a `comparison`. This rejects, at submit, a
    manifest whose reducer would silently have no agreement predicate."""
    fs = feature_schema or {}
    if not fs:
        return ["within_cell_tolerance requires a feature_schema (the tolerance envelope)"]
    errors: list[str] = []
    tf = reducer.get("tolerance_features")
    if tf is not None:
        if not isinstance(tf, list) or not tf:
            errors.append("tolerance_features must be a non-empty list of feature paths")
            tf = None
        else:
            for path in tf:
                decl = fs.get(path)
                if decl is None:
                    errors.append(f"tolerance_features references undeclared feature {path!r}")
                elif not isinstance((decl or {}).get("comparison"), dict):
                    errors.append(f"tolerance feature {path!r} declares no 'comparison' envelope")
    if not predicate_features(fs, tf):
        errors.append(
            "within_cell_tolerance needs at least one feature with a non-'exact' 'comparison' "
            "(or a tolerance_features list naming features that declare one)"
        )
    return errors


def tolerance_agreement(
    results: list,  # objects exposing `.payload` (dict)
    *,
    feature_schema: dict,
    tolerance_features: list[str] | None,
    floor: int,
) -> ToleranceAgreement:
    """Partition `results` into envelope-agreeing vs outliers; agreed iff at
    least `floor`-many agree. Deterministic given the result set (median /
    modal representative + a stable tiebreak), independent of input order."""
    n = len(results)
    floor = max(int(floor or 1), 1)
    if n == 0:
        return ToleranceAgreement(False, [], [], {}, None, {})

    feats = predicate_features(feature_schema or {}, tolerance_features)
    if not feats:
        # Nothing to corroborate on → no tolerance consensus. Defensive: submit
        # validation rejects a tolerance reducer with no predicate feature.
        return ToleranceAgreement(False, [], list(range(n)), {}, None, {})

    flats = [
        _flatten(r.payload) if isinstance(getattr(r, "payload", None), dict) else {}
        for r in results
    ]

    representative: dict[str, Any] = {}
    spread: dict[str, float] = {}
    for path in feats:
        rule = feature_schema[path]["comparison"]["rule"]
        rep, sp = _representative(rule, [f.get(path) for f in flats])
        representative[path] = rep
        spread[path] = sp

    agreeing: list[int] = []
    outliers: list[int] = []
    for i, flat in enumerate(flats):
        ok = all(
            _within(feature_schema[p]["comparison"], representative[p], flat.get(p)) for p in feats
        )
        (agreeing if ok else outliers).append(i)

    agreed = len(agreeing) >= floor
    rep_hash = semantic_hash(0, representative) if agreed else None
    return ToleranceAgreement(agreed, agreeing, outliers, representative, rep_hash, spread)


# ── representative + envelope per rule ───────────────────────────────────────


def _representative(rule: str, values: list[Any]) -> tuple[Any, float]:
    """The deterministic consensus value for a feature + a coarse spread."""
    present = [v for v in values if v is not None]
    if rule == "numeric":
        nums = [float(v) for v in present if _is_number(v)]
        if not nums:
            return None, 0.0
        return statistics.median(nums), (max(nums) - min(nums))
    if rule == "categorical_exact":
        if not present:
            return None, 0.0
        return _mode(present), float(len(set(map(_hashable, present))) - 1)
    if rule == "set_jaccard":
        sets = [_as_frozenset(v) for v in present]
        if not sets:
            return [], 0.0
        rep = _modal_set(sets)
        rep_fs = _as_frozenset(rep)
        worst = min((_jaccard(s, rep_fs) for s in sets), default=1.0)
        return rep, float(1.0 - worst)
    return None, 0.0


def _within(cmp: dict, rep: Any, value: Any) -> bool:
    """Whether `value` falls within the comparison envelope of `rep`."""
    rule = cmp.get("rule")
    if value is None or rep is None:
        return value is None and rep is None
    if rule == "numeric":
        if not _is_number(value):
            return False
        v, r = float(value), float(rep)
        tol = 0.0
        if cmp.get("abs") is not None:
            tol = max(tol, abs(float(cmp["abs"])))
        if cmp.get("rel") is not None:
            tol = max(tol, abs(float(cmp["rel"])) * abs(r))
        return abs(v - r) <= tol
    if rule == "categorical_exact":
        return _hashable(value) == _hashable(rep)
    if rule == "set_jaccard":
        return _jaccard(_as_frozenset(value), _as_frozenset(rep)) >= float(cmp["min"])
    return False


# ── small deterministic helpers ──────────────────────────────────────────────


def _mode(values: list[Any]) -> Any:
    """Most common value; ties broken by the smallest canonical key (stable)."""
    counts = Counter(_hashable(v) for v in values)
    top = max(counts.values())
    winners = [k for k, c in counts.items() if c == top]
    return min(winners, key=_sort_key)


def _modal_set(sets: list[frozenset]) -> list:
    """Modal frozenset → sorted list (JSON-serializable); ties → smallest key."""
    counts = Counter(sets)
    top = max(counts.values())
    winners = [s for s, c in counts.items() if c == top]
    chosen = min(winners, key=lambda s: _sort_key(sorted(s, key=_sort_key)))
    return sorted(chosen, key=_sort_key)


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    union = len(a | b)
    return (len(a & b) / union) if union else 1.0


def _as_frozenset(value: Any) -> frozenset:
    """A set feature is a list (elements may be [token, count] pairs); make the
    elements hashable so jaccard is well-defined."""
    if not isinstance(value, (list, tuple)):
        return frozenset()
    return frozenset(_hashable(el) for el in value)


def _hashable(v: Any) -> Any:
    if isinstance(v, (list, tuple)):
        return tuple(_hashable(x) for x in v)
    return v


def _sort_key(v: Any) -> str:
    """A total, type-stable ordering key for tiebreaks (repr is deterministic)."""
    return repr(v)
