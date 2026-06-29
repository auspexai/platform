"""Unit tests for the coordinator-side feature_schema mirror (D16.1).

These exercise the pure validator + conformance checker (auspexai_platform.
feature_schema), the coordinator's independent mirror of the SDK
FeatureDeclaration contract. KEEP IN LOCKSTEP with tenant-sdk
tests/test_feature_schema.py — the SDK fixture VIGILES_FEATURE_SCHEMA is the
shared exemplar; this asserts the coordinator agrees with it.
"""

from __future__ import annotations

import copy

from auspexai_platform.feature_schema import (
    check_payload_conformance,
    validate_feature_schema,
)

# The ratified 11-feature Vigiles exemplar (§8). Mirrors the SDK test fixture.
VIGILES_SCHEMA = {
    "schema": {
        "meaning": "result schema id",
        "kind": "categorical",
        "role": "provenance",
        "change_means": "x",
        "categories": ["vigiles-drift-probe/v0"],
    },
    "probe_id": {
        "meaning": "probe",
        "kind": "categorical",
        "role": "key",
        "change_means": "x",
        "categories": ["p-greeting", "p-instruction", "p-refusal"],
    },
    "response_sha256": {
        "meaning": "output hash",
        "kind": "hash",
        "role": "anchor",
        "algorithm": "sha256",
        "change_means": "x",
        "comparison": {"rule": "exact"},
    },
    "response_chars": {
        "meaning": "chars",
        "kind": "count",
        "role": "summary",
        "unit": "characters",
        "range": {"min": 0},
        "change_means": "x",
    },
    "eval_count": {
        "meaning": "tokens",
        "kind": "count",
        "role": "summary",
        "unit": "tokens",
        "range": {"min": 0},
        "change_means": "x",
    },
    "lexical.tokens": {
        "meaning": "tok",
        "kind": "count",
        "role": "summary",
        "unit": "whitespace_tokens",
        "range": {"min": 0},
        "change_means": "x",
    },
    "lexical.unique_tokens": {
        "meaning": "uniq",
        "kind": "count",
        "role": "summary",
        "unit": "whitespace_tokens",
        "range": {"min": 0},
        "change_means": "x",
    },
    "lexical.type_token_ratio": {
        "meaning": "ttr",
        "kind": "numeric",
        "role": "summary",
        "unit": "ratio",
        "range": {"min": 0.0, "max": 1.0},
        "valid_when": {"field": "lexical.tokens", "op": ">=", "value": 5},
        "invariant_to": ["token_order", "whitespace", "punctuation"],
        "change_means": "x",
        "comparison": {"rule": "numeric", "rel": 0.05},
    },
    "lexical.top_tokens": {
        "meaning": "top",
        "kind": "set",
        "role": "summary",
        "element_kind": "categorical",
        "max_cardinality": 8,
        "invariant_to": ["token_order"],
        "change_means": "x",
        "comparison": {"rule": "set_jaccard", "min": 0.9},
    },
    "model.id": {
        "meaning": "model",
        "kind": "categorical",
        "role": "provenance",
        "categories": ["gemma-3-1b-it-q4"],
        "change_means": "x",
    },
    "model.gguf_sha256": {
        "meaning": "weights",
        "kind": "hash",
        "role": "provenance",
        "algorithm": "sha256",
        "change_means": "x",
    },
}

# A conforming real-shape Vigiles result payload (executor.run_one).
GOOD_PAYLOAD = {
    "schema": "vigiles-drift-probe/v0",
    "probe_id": "p-greeting",
    "response_sha256": "a" * 64,
    "response_chars": 146,
    "eval_count": 7,
    "lexical": {
        "tokens": 20,
        "unique_tokens": 18,
        "type_token_ratio": 0.9,
        "top_tokens": [["the", 4], ["a", 2]],
    },
    "model": {"id": "gemma-3-1b-it-q4", "gguf_sha256": "b" * 64},
}


def _decl(**over):
    base = {"meaning": "m", "kind": "count", "role": "summary", "change_means": "c"}
    base.update(over)
    return {"x": base}


# ── submit-time: validate_feature_schema ─────────────────────────────────────


def test_exemplar_is_valid() -> None:
    assert validate_feature_schema(VIGILES_SCHEMA) == []


def test_empty_or_nondict_rejected() -> None:
    assert validate_feature_schema({}) != []
    assert validate_feature_schema([]) != []  # type: ignore[arg-type]
    assert validate_feature_schema("nope") != []  # type: ignore[arg-type]


def test_no_free_text_kind() -> None:
    errs = validate_feature_schema(_decl(kind="text"))
    assert any("§7-safe" in e or "free-text" in e for e in errs)


def test_numeric_requires_range() -> None:
    assert any("requires a 'range'" in e for e in validate_feature_schema(_decl(kind="numeric")))


def test_categorical_requires_closed_categories() -> None:
    assert any("categories" in e for e in validate_feature_schema(_decl(kind="categorical")))


def test_hash_requires_algorithm() -> None:
    assert any("algorithm" in e for e in validate_feature_schema(_decl(kind="hash")))


def test_set_requires_element_kind_and_cardinality() -> None:
    assert any(
        "element_kind" in e
        for e in validate_feature_schema(_decl(kind="set", element_kind="categorical"))
    )


def test_cross_kind_bounds_rejected() -> None:
    assert any(
        "only valid for" in e
        for e in validate_feature_schema(_decl(kind="hash", algorithm="sha256", range={"min": 0}))
    )


def test_range_max_below_min_rejected() -> None:
    errs = validate_feature_schema(_decl(kind="numeric", range={"min": 1.0, "max": 0.0}))
    assert any("range.max" in e for e in errs)


def test_missing_core_fields_rejected() -> None:
    errs = validate_feature_schema({"x": {"kind": "count", "role": "summary"}})
    assert any("missing required 'meaning'" in e for e in errs)
    assert any("missing required 'change_means'" in e for e in errs)


def test_unknown_field_rejected() -> None:
    assert any("unknown field" in e for e in validate_feature_schema(_decl(surprise=1)))


def test_bad_dotted_path_rejected() -> None:
    assert any(
        "dotted result path" in e for e in validate_feature_schema({"1bad.path!": _decl()["x"]})
    )


def test_comparison_numeric_needs_rel_or_abs() -> None:
    errs = validate_feature_schema(
        _decl(kind="numeric", range={"min": 0, "max": 1}, comparison={"rule": "numeric"})
    )
    assert any("needs 'rel' or 'abs'" in e for e in errs)


def test_valid_when_must_be_structured() -> None:
    errs = validate_feature_schema(
        _decl(
            kind="numeric",
            range={"min": 0, "max": 1},
            valid_when={"field": "x", "op": "??", "value": 1},
        )
    )
    assert any("valid_when.op" in e for e in errs)


# ── ingest-time: check_payload_conformance ───────────────────────────────────


def test_good_payload_conforms() -> None:
    assert check_payload_conformance(VIGILES_SCHEMA, GOOD_PAYLOAD) == []


def test_undeclared_field_is_a_leak() -> None:
    p = copy.deepcopy(GOOD_PAYLOAD)
    p["raw_response"] = "hello world the cat sat"  # a §7 raw-text leak
    v = check_payload_conformance(VIGILES_SCHEMA, p)
    assert any("undeclared field 'raw_response'" in x for x in v)


def test_bad_hash_rejected() -> None:
    p = copy.deepcopy(GOOD_PAYLOAD)
    p["response_sha256"] = "NOT-HEX"
    assert any(
        "hash must be lowercase hex" in x for x in check_payload_conformance(VIGILES_SCHEMA, p)
    )


def test_wrong_hash_width_rejected() -> None:
    p = copy.deepcopy(GOOD_PAYLOAD)
    p["response_sha256"] = "abcd"  # hex but not 64 chars
    assert any("64 hex chars" in x for x in check_payload_conformance(VIGILES_SCHEMA, p))


def test_numeric_out_of_range_rejected() -> None:
    p = copy.deepcopy(GOOD_PAYLOAD)
    p["lexical"]["type_token_ratio"] = 1.5
    assert any("> range.max" in x for x in check_payload_conformance(VIGILES_SCHEMA, p))


def test_categorical_not_in_set_rejected() -> None:
    p = copy.deepcopy(GOOD_PAYLOAD)
    p["probe_id"] = "p-unknown"
    assert any(
        "not in declared categories" in x for x in check_payload_conformance(VIGILES_SCHEMA, p)
    )


def test_count_must_be_integer() -> None:
    p = copy.deepcopy(GOOD_PAYLOAD)
    p["eval_count"] = 7.5
    assert any(
        "count must be an integer" in x for x in check_payload_conformance(VIGILES_SCHEMA, p)
    )


def test_set_over_cardinality_rejected() -> None:
    p = copy.deepcopy(GOOD_PAYLOAD)
    p["lexical"]["top_tokens"] = [["t", 1]] * 9
    assert any("exceeds max_cardinality" in x for x in check_payload_conformance(VIGILES_SCHEMA, p))


def test_missing_declared_feature_rejected() -> None:
    p = copy.deepcopy(GOOD_PAYLOAD)
    del p["eval_count"]
    assert any("absent from the result" in x for x in check_payload_conformance(VIGILES_SCHEMA, p))


def test_null_value_rejected() -> None:
    p = copy.deepcopy(GOOD_PAYLOAD)
    p["model"]["id"] = None
    assert any("is null" in x for x in check_payload_conformance(VIGILES_SCHEMA, p))
