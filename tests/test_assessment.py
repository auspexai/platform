"""§9 #48 admission policy — the pure classxtier auto-approval logic."""

from __future__ import annotations

from auspexai_platform.assessment import (
    AUTO_APPROVE_TIER,
    ELEVATED_CLASSES,
    RESEARCH_CLASSES,
    ROUTINE_CLASSES,
    assess_envelope,
    class_track,
    decide,
)
from auspexai_platform.db.models import TrustTier


def _manifest(**over):
    m = {
        "executor": {"package_sha256": "a" * 64},
        "models": [{"id": "gemma-3-1b-it-q4"}],
        "sensitive_content_flags": [],
    }
    m.update(over)
    return m


def _envelope(research_class="behavioral_drift", **kw):
    return assess_envelope(
        manifest_json=_manifest(),
        research_class=research_class,
        tenant_approved_classes=["behavioral_drift"],
        **kw,
    )


# ── taxonomy ────────────────────────────────────────────────────────────────


def test_taxonomy_matches_application_source():
    """Drift guard: the auto-approval taxonomy must equal the application one."""
    from auspexai_platform.api.tenant_applications import RESEARCH_CLASSES as APP_CLASSES

    assert RESEARCH_CLASSES == APP_CLASSES
    assert ROUTINE_CLASSES | ELEVATED_CLASSES | {"other"} == set(RESEARCH_CLASSES)


def test_class_track():
    assert class_track("behavioral_drift") == "routine"
    assert class_track("cross_model_comparison") == "routine"
    assert class_track("refusal_boundary_mapping") == "elevated"
    assert class_track("other") == "unknown"
    assert class_track(None) == "unknown"
    assert class_track("made_up") == "unknown"


# ── envelope ────────────────────────────────────────────────────────────────


def test_envelope_passes_clean():
    assert _envelope().passed is True


def test_envelope_unknown_class_fails():
    r = _envelope(research_class="made_up")
    assert r.passed is False and "class_known" in r.failures


def test_envelope_out_of_tenant_scope_fails():
    r = assess_envelope(
        manifest_json=_manifest(),
        research_class="quantization_effects",
        tenant_approved_classes=["behavioral_drift"],  # not quantization
    )
    assert r.passed is False and "class_in_tenant_scope" in r.failures


def test_envelope_no_recorded_scope_is_not_evaluated():
    r = assess_envelope(
        manifest_json=_manifest(),
        research_class="behavioral_drift",
        tenant_approved_classes=None,
    )
    assert r.passed is True


def test_envelope_unpinned_package_fails():
    r = assess_envelope(
        manifest_json=_manifest(executor={"package_sha256": "short"}),
        research_class="behavioral_drift",
        tenant_approved_classes=["behavioral_drift"],
    )
    assert r.passed is False and "package_pinned" in r.failures


def test_envelope_routine_with_sensitive_flag_fails():
    r = assess_envelope(
        manifest_json=_manifest(sensitive_content_flags=["jailbreak"]),
        research_class="behavioral_drift",
        tenant_approved_classes=["behavioral_drift"],
    )
    assert r.passed is False and "routine_no_sensitive_flags" in r.failures


def test_envelope_unservable_model_fails():
    r = assess_envelope(
        manifest_json=_manifest(),
        research_class="behavioral_drift",
        tenant_approved_classes=["behavioral_drift"],
        served_model_ids={"some-other-model"},
    )
    assert r.passed is False and "model_servable" in r.failures


def test_envelope_over_unit_cap_fails():
    r = assess_envelope(
        manifest_json=_manifest(max_units=10_000),
        research_class="behavioral_drift",
        tenant_approved_classes=["behavioral_drift"],
        max_units_cap=500,
    )
    assert r.passed is False and "within_unit_cap" in r.failures


# ── decide ──────────────────────────────────────────────────────────────────


def test_routine_trusted_clean_auto_approves():
    d = decide(research_class="behavioral_drift", tenant_tier=2, envelope=_envelope())
    assert d.decision == "auto" and d.track == "routine"


def test_routine_but_sub_tier_reviews():
    d = decide(research_class="behavioral_drift", tenant_tier=1, envelope=_envelope())
    assert d.decision == "review" and "below" in d.rationale


def test_elevated_never_auto_even_at_max_tier():
    """The construction guarantee: refusal_boundary_mapping cannot auto-approve
    at ANY tier, even T3, even with a clean envelope."""
    env = _envelope(research_class="refusal_boundary_mapping")
    d = decide(research_class="refusal_boundary_mapping", tenant_tier=3, envelope=env)
    assert d.decision == "review" and d.track == "elevated"


def test_unknown_class_reviews():
    d = decide(research_class=None, tenant_tier=3, envelope=_envelope(research_class=None))
    assert d.decision == "review" and d.track == "unknown"


def test_failed_envelope_reviews_even_when_routine_and_trusted():
    env = assess_envelope(
        manifest_json=_manifest(executor={"package_sha256": "bad"}),
        research_class="behavioral_drift",
        tenant_approved_classes=["behavioral_drift"],
    )
    d = decide(research_class="behavioral_drift", tenant_tier=2, envelope=env)
    assert d.decision == "review" and "envelope" in d.rationale


def test_auto_tier_is_t2():
    assert AUTO_APPROVE_TIER == TrustTier.T2_TRUSTED
