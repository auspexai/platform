"""E11 judgment-tier mechanics (judgment_tier_promotion_mechanics_design.md,
RATIFIED 2026-07-03): demote preserves identity (D2), whoami exposes the
verification stamp (D3a), and the promote checklist lands verbatim in the
audit record (D1)."""

from __future__ import annotations

from auspexai_platform.db.models import IdentityVerificationMethod, TrustTier


def _mk_account(account_repository, account_id="acct-e11"):
    from auspexai_platform.db.models import IdentityProvider

    return account_repository.create(
        account_id=account_id,
        idp=IdentityProvider.GITHUB,
        idp_sub=f"{account_id}-sub",
        trust_tier=TrustTier.T2_TRUSTED,
    )


def test_demote_below_t2_preserves_identity_verification(account_repository):
    """E11 D2 (the ratified behavior change): trust and identity are orthogonal —
    a routine demotion must not destroy the verification stamp (the old
    clear-on-demote stranded accounts linked-but-unverified with no UI path
    back, and made demote→re-promote lossy)."""
    _mk_account(account_repository)
    account_repository.link_orcid("acct-e11", orcid_id="0000-0001-2345-6789")
    account_repository.verify_identity(
        "acct-e11",
        verified_by="maintainer",
        method=IdentityVerificationMethod.ORCID,
        note="e2e",
    )
    before = account_repository.get_by_id("acct-e11")
    assert before.identity_verified_at is not None

    demoted = account_repository.demote("acct-e11", target_tier=TrustTier.T1_AUTHENTICATED)
    assert demoted.trust_tier == TrustTier.T1_AUTHENTICATED
    assert demoted.identity_verified_at is not None  # PRESERVED (D2)
    assert demoted.orcid_id == "0000-0001-2345-6789"

    # The deliberate action still exists and still clears BOTH.
    account_repository.revoke_identity("acct-e11")
    revoked = account_repository.get_by_id("acct-e11")
    assert revoked.identity_verified_at is None
    assert revoked.orcid_id is None
