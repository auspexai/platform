"""C7 within_cell_tolerance — the agreement predicate, submit validation, and the
reducer dispatch (which must leave exact hash-agreement unchanged)."""

from __future__ import annotations

from types import SimpleNamespace

from auspexai_platform.receipts.issuance import TOLERANCE_METHOD, _reduce_unit
from auspexai_platform.receipts.tolerance import (
    predicate_features,
    tolerance_agreement,
    validate_tolerance_reducer,
)

# A Vigiles-shaped feature_schema subset: an exact hash anchor (strengthener, not
# a predicate), two numeric/set predicates, a categorical predicate, and a
# comparison-less provenance field (never a predicate).
FS = {
    "response_sha256": {"kind": "hash", "comparison": {"rule": "exact"}},
    "lexical.type_token_ratio": {"kind": "numeric", "comparison": {"rule": "numeric", "rel": 0.05}},
    "lexical.top_tokens": {"kind": "set", "comparison": {"rule": "set_jaccard", "min": 0.9}},
    "refusal": {"kind": "categorical", "comparison": {"rule": "categorical_exact"}},
    "model.id": {"kind": "categorical"},  # no comparison → never a predicate feature
}


_TOL = {"kind": "builtin_within_cell_tolerance"}


def _r(payload: dict, exit_code: int = 0):
    return SimpleNamespace(payload=payload, exit_code=exit_code)


def _payload(ttr: float, tokens: list, refusal: str = "no") -> dict:
    return {
        "response_sha256": "a" * 64,
        "lexical": {"type_token_ratio": ttr, "top_tokens": tokens},
        "refusal": refusal,
        "model": {"id": "gemma"},
    }


class TestPredicateFeatures:
    def test_default_excludes_exact_and_comparisonless(self) -> None:
        feats = predicate_features(FS, None)
        assert "response_sha256" not in feats  # exact anchor strengthens, never blocks
        assert "model.id" not in feats  # no comparison declared
        assert set(feats) == {"lexical.type_token_ratio", "lexical.top_tokens", "refusal"}

    def test_explicit_subset_wins_and_drops_undeclared(self) -> None:
        assert predicate_features(FS, ["lexical.type_token_ratio"]) == ["lexical.type_token_ratio"]
        assert predicate_features(FS, ["nope", "refusal"]) == ["refusal"]


class TestToleranceAgreement:
    def test_exact_agree(self) -> None:
        rs = [_r(_payload(0.50, [["a", 1], ["b", 1]])) for _ in range(3)]
        out = tolerance_agreement(rs, feature_schema=FS, tolerance_features=None, floor=2)
        assert out.agreed
        assert len(out.agreeing_indices) == 3 and out.outlier_indices == []
        assert out.representative_hash is not None

    def test_within_numeric_tolerance_agrees(self) -> None:
        rs = [_r(_payload(t, [["a", 1]])) for t in (0.50, 0.51, 0.49)]
        out = tolerance_agreement(rs, feature_schema=FS, tolerance_features=None, floor=2)
        assert out.agreed and len(out.agreeing_indices) == 3

    def test_one_outlier_still_agrees_at_floor(self) -> None:
        # two tight, one far-off on ttr AND top_tokens → outlier; floor=2 met by the pair.
        rs = [
            _r(_payload(0.50, [["a", 1]])),
            _r(_payload(0.50, [["a", 1]])),
            _r(_payload(0.95, [["z", 1]])),
        ]
        out = tolerance_agreement(rs, feature_schema=FS, tolerance_features=None, floor=2)
        assert out.agreed
        assert len(out.agreeing_indices) == 2 and out.outlier_indices == [2]

    def test_floor_not_met_diverges(self) -> None:
        rs = [_r(_payload(t, [["a", 1]])) for t in (0.30, 0.60, 0.90)]
        out = tolerance_agreement(rs, feature_schema=FS, tolerance_features=None, floor=3)
        assert not out.agreed and out.representative_hash is None

    def test_categorical_exact_outlier(self) -> None:
        rs = [
            _r(_payload(0.5, [["a", 1]], "no")),
            _r(_payload(0.5, [["a", 1]], "no")),
            _r(_payload(0.5, [["a", 1]], "yes")),
        ]
        out = tolerance_agreement(rs, feature_schema=FS, tolerance_features=None, floor=2)
        assert out.agreed and out.outlier_indices == [2]

    def test_set_jaccard_below_min_is_outlier(self) -> None:
        rs = [
            _r(_payload(0.5, [["a", 1], ["b", 1]])),
            _r(_payload(0.5, [["a", 1], ["b", 1]])),
            _r(_payload(0.5, [["x", 1], ["y", 1]])),  # disjoint → jaccard 0 < 0.9
        ]
        out = tolerance_agreement(rs, feature_schema=FS, tolerance_features=None, floor=2)
        assert out.agreed and out.outlier_indices == [2]

    def test_single_result_repl1_trivially_agrees(self) -> None:
        out = tolerance_agreement(
            [_r(_payload(0.5, [["a", 1]]))], feature_schema=FS, tolerance_features=None, floor=1
        )
        assert out.agreed and len(out.agreeing_indices) == 1

    def test_empty_results(self) -> None:
        assert not tolerance_agreement(
            [], feature_schema=FS, tolerance_features=None, floor=1
        ).agreed

    def test_deterministic_order_independent(self) -> None:
        payloads = [
            _payload(0.50, [["a", 1]]),
            _payload(0.51, [["a", 1]]),
            _payload(0.95, [["z", 1]]),
        ]
        o1 = tolerance_agreement(
            [_r(p) for p in payloads], feature_schema=FS, tolerance_features=None, floor=2
        )
        o2 = tolerance_agreement(
            [_r(p) for p in reversed(payloads)], feature_schema=FS, tolerance_features=None, floor=2
        )
        assert o1.agreed == o2.agreed
        assert o1.representative_hash == o2.representative_hash  # representative is set-order-free


class TestValidateToleranceReducer:
    def test_valid(self) -> None:
        assert validate_tolerance_reducer(_TOL, FS) == []

    def test_requires_feature_schema(self) -> None:
        errs = validate_tolerance_reducer(_TOL, None)
        assert errs and "feature_schema" in errs[0]

    def test_undeclared_tolerance_feature(self) -> None:
        errs = validate_tolerance_reducer({**_TOL, "tolerance_features": ["nope"]}, FS)
        assert any("undeclared" in e for e in errs)

    def test_tolerance_feature_without_comparison(self) -> None:
        errs = validate_tolerance_reducer({**_TOL, "tolerance_features": ["model.id"]}, FS)
        assert any("no 'comparison'" in e for e in errs)

    def test_no_predicate_feature(self) -> None:
        errs = validate_tolerance_reducer(_TOL, {"model.id": {"kind": "categorical"}})
        assert any("at least one feature" in e for e in errs)


class TestReduceUnitDispatch:
    def test_tolerance_dispatch_partitions(self) -> None:
        exp = SimpleNamespace(replication_floor=2)
        manifest = {"reducer": {"kind": TOLERANCE_METHOD}, "feature_schema": FS}
        rs = [
            _r(_payload(0.50, [["a", 1]])),
            _r(_payload(0.50, [["a", 1]])),
            _r(_payload(0.95, [["z", 1]])),
        ]
        outcome, agreeing, outliers = _reduce_unit(rs, experiment=exp, manifest=manifest)
        assert outcome.agreed and outcome.method == TOLERANCE_METHOD
        assert outcome.agreeing_workers == 2
        assert len(agreeing) == 2 and len(outliers) == 1

    def test_default_is_hash_agreement(self) -> None:
        exp = SimpleNamespace(replication_floor=2)
        rs = [_r({"x": 1}), _r({"x": 1})]
        outcome, agreeing, outliers = _reduce_unit(rs, experiment=exp, manifest=None)
        assert outcome.agreed and outcome.method == "builtin_hash_agreement"
        assert len(agreeing) == 2 and outliers == []

    def test_hash_disagreement_all_outliers(self) -> None:
        exp = SimpleNamespace(replication_floor=2)
        rs = [_r({"x": 1}), _r({"x": 2})]
        outcome, agreeing, outliers = _reduce_unit(rs, experiment=exp, manifest=None)
        assert not outcome.agreed
        assert agreeing == [] and len(outliers) == 2
