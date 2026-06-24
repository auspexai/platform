"""AccountRepository — IdP-bound human accounts + short-lived binding tokens.

Two resources, one repository:

  - accounts: persistent human identities (one row per (idp, idp_sub) pair)
  - account_oauth_bindings: ephemeral one-shot tokens that flow from the
    OAuth-exchange endpoint to a downstream binder (M6b worker upgrade,
    researcher SDK init). 5-min TTL; deleted on consumption logically (kept
    in DB with consumed_at set for audit). Storing them in the DB rather
    than memory means coordinator restarts don't void in-flight tokens.

The Pydantic `Account` / `OAuthBinding` models in `db/models.py` are the
canonical row shapes.
"""

from __future__ import annotations

import secrets
import sqlite3
from datetime import UTC, datetime, timedelta

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import (
    R2_REVIEW_THRESHOLD,
    Account,
    IdentityProvider,
    IdentityVerificationMethod,
    OAuthBinding,
    ResearchStanding,
    ResearchStandingSummary,
    TrustTier,
)

# 5 minutes: long enough for the caller to round-trip the exchange + binder
# call, short enough that a leaked token has tight blast radius.
DEFAULT_BINDING_TTL = timedelta(minutes=5)


class AccountNotFoundError(Exception):
    """Raised when an account_id is unknown or retired."""


class DuplicateAccountError(Exception):
    """Raised when an (idp, idp_sub) pair is already bound to another account."""


class BindingTokenNotFoundError(Exception):
    """Raised when a binding_token is unknown."""


class BindingTokenExpiredError(Exception):
    """Raised when a binding_token's expires_at is in the past."""


class BindingTokenConsumedError(Exception):
    """Raised when a binding_token has already been consumed."""


class AccountRepository:
    def __init__(self, db: Database):
        self.db = db

    # ---- account writes ----

    def create(
        self,
        *,
        account_id: str,
        idp: IdentityProvider,
        idp_sub: str,
        display_name: str | None = None,
        email: str | None = None,
        trust_tier: TrustTier = TrustTier.T1_AUTHENTICATED,
    ) -> Account:
        """Insert an account. Raises DuplicateAccountError on (idp, idp_sub) collision."""
        created_at = datetime.now(UTC).isoformat()
        try:
            self.db.execute(
                """
                INSERT INTO accounts (
                    account_id, idp, idp_sub, display_name, email,
                    trust_tier, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    account_id,
                    idp.value,
                    idp_sub,
                    display_name,
                    email,
                    int(trust_tier),
                    created_at,
                ),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateAccountError(str(e)) from e
        got = self.get_by_id(account_id)
        assert got is not None
        return got

    # ---- trust escalation (§6.2.3) ----

    def promote(
        self,
        account_id: str,
        *,
        target_tier: TrustTier,
        set_by_class: object | None = None,
    ) -> Account:
        """Bump trust_tier to target_tier. Caller is responsible for gate
        validation (receipt thresholds, identity gate). Raises AccountNotFoundError
        if account_id is unknown or retired. `set_by_class` (F4) records WHO did it
        ('system' auto / 'maintainer' manual) for the governance footprint."""
        set_by = getattr(set_by_class, "value", set_by_class)
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE accounts SET trust_tier = ?, tier_set_by_class = ?
                WHERE account_id = ? AND retired_at IS NULL AND suspended_at IS NULL
                """,
                (int(target_tier), set_by, account_id),
            )
            if cur.rowcount == 0:
                raise AccountNotFoundError(account_id)
        got = self.get_by_id(account_id)
        assert got is not None
        return got

    def demote(
        self,
        account_id: str,
        *,
        target_tier: TrustTier,
        set_by_class: object | None = None,
    ) -> Account:
        """Drop trust_tier to target_tier. Revokes identity verification if
        crossing below T2. Raises AccountNotFoundError if unknown/retired.
        `set_by_class` (F4) records WHO did it for the governance footprint."""
        set_by = getattr(set_by_class, "value", set_by_class)
        with self.db.transaction() as cur:
            if target_tier < TrustTier.T2_TRUSTED:
                cur.execute(
                    """
                    UPDATE accounts
                    SET trust_tier = ?,
                        tier_set_by_class = ?,
                        identity_verified_at = NULL,
                        identity_verified_by = NULL,
                        identity_verification_method = NULL,
                        identity_verification_note = NULL
                    WHERE account_id = ? AND retired_at IS NULL
                    """,
                    (int(target_tier), set_by, account_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE accounts SET trust_tier = ?, tier_set_by_class = ?
                    WHERE account_id = ? AND retired_at IS NULL
                    """,
                    (int(target_tier), set_by, account_id),
                )
            if cur.rowcount == 0:
                raise AccountNotFoundError(account_id)
        got = self.get_by_id(account_id)
        assert got is not None
        return got

    def suspend(self, account_id: str, reason: str | None = None) -> Account:
        """Freeze account. Raises AccountNotFoundError if unknown/retired.
        Idempotent on re-suspend (timestamp preserved on first call; reason
        can be updated on subsequent calls — mirrors worker quarantine)."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE accounts SET suspended_at = COALESCE(suspended_at, ?),
                    suspension_reason = ?
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (now, reason, account_id),
            )
            if cur.rowcount == 0:
                raise AccountNotFoundError(account_id)
        got = self.get_by_id(account_id)
        assert got is not None
        return got

    def unsuspend(self, account_id: str) -> Account:
        """Clear suspension. Idempotent. Raises AccountNotFoundError if unknown."""
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE accounts SET suspended_at = NULL, suspension_reason = NULL
                WHERE account_id = ?
                """,
                (account_id,),
            )
            if cur.rowcount == 0:
                raise AccountNotFoundError(account_id)
        got = self.get_by_id(account_id)
        assert got is not None
        return got

    # ---- identity verification (§6.2.1) ----

    def verify_identity(
        self,
        account_id: str,
        *,
        verified_by: str,
        method: IdentityVerificationMethod,
        note: str | None = None,
    ) -> Account:
        """Mark identity as verified. Raises AccountNotFoundError if unknown."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE accounts
                SET identity_verified_at = ?,
                    identity_verified_by = ?,
                    identity_verification_method = ?,
                    identity_verification_note = ?
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (now, verified_by, method.value, note, account_id),
            )
            if cur.rowcount == 0:
                raise AccountNotFoundError(account_id)
        got = self.get_by_id(account_id)
        assert got is not None
        return got

    def link_orcid(
        self, account_id: str, *, orcid_id: str, display_name: str | None = None
    ) -> Account:
        """Link an ORCID iD to the account (D8) and mark identity verified.

        Stores the ORCID iD AND sets identity_verified_* with method=ORCID in one
        transaction — the ORCID link IS the identity verification the R2→R3 gate
        reads. `identity_verified_by` records the linked iD for the audit trail.
        Raises AccountNotFoundError if unknown."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE accounts
                SET orcid_id = ?,
                    identity_verified_at = ?,
                    identity_verified_by = ?,
                    identity_verification_method = ?,
                    identity_verification_note = ?
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (
                    orcid_id,
                    now,
                    f"orcid:{orcid_id}",
                    IdentityVerificationMethod.ORCID.value,
                    display_name,
                    account_id,
                ),
            )
            if cur.rowcount == 0:
                raise AccountNotFoundError(account_id)
        got = self.get_by_id(account_id)
        assert got is not None
        return got

    # ---- ORCID OAuth link flow (D8) ----

    def create_orcid_state(self, state: str, account_id: str) -> None:
        """Store a single-use ORCID OAuth state bound to an account."""
        now = datetime.now(UTC).isoformat()
        with self.db.transaction() as cur:
            cur.execute(
                "INSERT INTO orcid_oauth_states (state, account_id, created_at) VALUES (?, ?, ?)",
                (state, account_id, now),
            )

    def consume_orcid_state(self, state: str, *, max_age_seconds: int = 600) -> str | None:
        """Pop a state, returning its account_id if present and not expired —
        single-use: the row is deleted regardless. None if unknown or too old."""
        rows = self.db.execute(
            "SELECT account_id, created_at FROM orcid_oauth_states WHERE state = ?",
            (state,),
        )
        with self.db.transaction() as cur:
            cur.execute("DELETE FROM orcid_oauth_states WHERE state = ?", (state,))
        if not rows:
            return None
        age = (datetime.now(UTC) - datetime.fromisoformat(rows[0]["created_at"])).total_seconds()
        if age > max_age_seconds:
            return None
        return rows[0]["account_id"]

    def revoke_identity(self, account_id: str) -> Account:
        """Clear identity verification. Raises AccountNotFoundError if unknown."""
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE accounts
                SET identity_verified_at = NULL,
                    identity_verified_by = NULL,
                    identity_verification_method = NULL,
                    identity_verification_note = NULL,
                    orcid_id = NULL
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (account_id,),
            )
            if cur.rowcount == 0:
                raise AccountNotFoundError(account_id)
        got = self.get_by_id(account_id)
        assert got is not None
        return got

    # ---- account reads ----

    def set_attribution(
        self, account_id: str, *, public_attribution: bool, attribution_name: str | None
    ) -> Account:
        """Set the account's public-citation consent (System B opt-in) and the name
        it wishes to be credited as. Idempotent. Raises AccountNotFoundError."""
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE accounts SET public_attribution = ?, attribution_name = ?
                WHERE account_id = ? AND retired_at IS NULL
                """,
                (1 if public_attribution else 0, attribution_name, account_id),
            )
            if cur.rowcount == 0:
                raise AccountNotFoundError(account_id)
        got = self.get_by_id(account_id)
        assert got is not None
        return got

    def get_by_id(self, account_id: str) -> Account | None:
        rows = self.db.execute(
            "SELECT * FROM accounts WHERE account_id = ?",
            (account_id,),
        )
        return self._row_to_account(rows[0]) if rows else None

    def list_all(self) -> list[Account]:
        """Return all accounts, newest first."""
        rows = self.db.execute("SELECT * FROM accounts ORDER BY created_at DESC")
        return [self._row_to_account(r) for r in rows]

    def get_by_idp_subject(self, idp: IdentityProvider, idp_sub: str) -> Account | None:
        rows = self.db.execute(
            "SELECT * FROM accounts WHERE idp = ? AND idp_sub = ?",
            (idp.value, idp_sub),
        )
        return self._row_to_account(rows[0]) if rows else None

    def research_standing_summary(self, account_id: str) -> ResearchStandingSummary:
        """Recompute (never store) the account's research-standing evidence — the
        count of DISTINCT-config, completed, evidence-attested experiments it has
        run — and whether that clears the R2-review threshold. Reward-independent,
        derived from attested history (the firewall property): it earns the human
        R2 ethics review, it does NOT promote (R1→R2 is a human act). See
        vigiles_onramp_phase4_design.md §1.2/§1.3.

        - distinct  = distinct experiments.manifest_hash (content-addressed config;
          trivial reruns share a hash → counted once),
        - completed = experiments.status == 'completed' (terminal consensus; an
          aborted/declined run is excluded — the increment-1 proxy for ethics-clean,
          refinable later with a finer violation signal),
        - verified  = a FINAL attestation (partial = 0) exists for the experiment.
        """
        rows = self.db.execute(
            """
            SELECT COUNT(DISTINCT e.manifest_hash) AS n
            FROM experiments e
            JOIN tenants t ON e.tenant_id = t.tenant_id
            JOIN attestations a
              ON a.experiment_id = e.experiment_id AND a.partial = 0
            WHERE t.account_id = ? AND e.status = 'completed'
            """,
            (account_id,),
        )
        count = int(rows[0]["n"]) if rows else 0
        acct = self.get_by_id(account_id)
        current = acct.research_standing if acct else ResearchStanding.R0_UNVERIFIED
        eligible = current == ResearchStanding.R1_VERIFIED and count >= R2_REVIEW_THRESHOLD
        return ResearchStandingSummary(
            account_id=account_id,
            current=current,
            distinct_clean_completed_verified=count,
            threshold=R2_REVIEW_THRESHOLD,
            eligible_for_r2_review=eligible,
        )

    def research_standing_history(self, account_id: str) -> list[dict]:
        """The attested experiment history behind the summary — the DOSSIER a
        reviewer judges (D8): WHAT the researcher actually ran, not just a count.
        One row per completed, evidence-attested experiment, newest first. The
        human R2/R3 review reads this (plus the §6.1 application materials surfaced
        in the tenant-applications queue), so the gate isn't a rubber-stamp on a
        GitHub handle. See vigiles_onramp_phase4_design.md §1.4."""
        rows = self.db.execute(
            """
            SELECT e.experiment_id, e.tenant_id, e.manifest_hash, e.research_class,
                   e.completed_at, a.rekor_log_index
            FROM experiments e
            JOIN tenants t ON e.tenant_id = t.tenant_id
            JOIN attestations a
              ON a.experiment_id = e.experiment_id AND a.partial = 0
            WHERE t.account_id = ? AND e.status = 'completed'
            ORDER BY e.completed_at DESC
            """,
            (account_id,),
        )
        return [
            {
                "experiment_id": r["experiment_id"],
                "tenant_id": r["tenant_id"],
                "manifest_hash": r["manifest_hash"],
                "research_class": r["research_class"],
                "completed_at": r["completed_at"],
                "rekor_log_index": r["rekor_log_index"],
            }
            for r in rows
        ]

    def set_research_standing(self, account_id: str, *, new_standing: ResearchStanding) -> Account:
        """Set the account's research_standing — a HUMAN act (ethics review /
        maintainer vetting), NEVER auto: the standing summary only earns the review.
        Caller does the gate validation + audit (the API endpoint). Raises
        AccountNotFoundError if unknown / retired / suspended."""
        with self.db.transaction() as cur:
            cur.execute(
                """
                UPDATE accounts SET research_standing = ?
                WHERE account_id = ? AND retired_at IS NULL AND suspended_at IS NULL
                """,
                (int(new_standing), account_id),
            )
            if cur.rowcount == 0:
                raise AccountNotFoundError(account_id)
        got = self.get_by_id(account_id)
        assert got is not None
        return got

    # ---- binding-token writes ----

    def issue_binding(
        self,
        account_id: str,
        *,
        ttl: timedelta = DEFAULT_BINDING_TTL,
    ) -> OAuthBinding:
        """Mint a short-lived one-shot binding token for `account_id`.

        The caller (OAuth-exchange route) returns this to the worker/dashboard,
        which then submits it to the binder endpoint (M6b worker upgrade).
        """
        binding_token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        expires_at = now + ttl
        self.db.execute(
            """
            INSERT INTO account_oauth_bindings (
                binding_token, account_id, created_at, expires_at
            ) VALUES (?, ?, ?, ?)
            """,
            (
                binding_token,
                account_id,
                now.isoformat(),
                expires_at.isoformat(),
            ),
        )
        got = self.get_binding(binding_token)
        assert got is not None
        return got

    def consume_binding(self, binding_token: str) -> OAuthBinding:
        """Mark a binding token as consumed and return its row.

        Raises BindingTokenNotFoundError / BindingTokenExpiredError /
        BindingTokenConsumedError as appropriate. Atomic via the transaction —
        consume is single-shot even under concurrent calls.
        """
        with self.db.transaction() as cur:
            cur.execute(
                "SELECT * FROM account_oauth_bindings WHERE binding_token = ?",
                (binding_token,),
            )
            row = cur.fetchone()
            if row is None:
                raise BindingTokenNotFoundError(binding_token)
            if row["consumed_at"] is not None:
                raise BindingTokenConsumedError(binding_token)
            expires_at = datetime.fromisoformat(row["expires_at"])
            if expires_at < datetime.now(UTC):
                raise BindingTokenExpiredError(binding_token)
            consumed_at = datetime.now(UTC)
            cur.execute(
                "UPDATE account_oauth_bindings SET consumed_at = ? WHERE binding_token = ?",
                (consumed_at.isoformat(), binding_token),
            )
            return OAuthBinding(
                binding_token=row["binding_token"],
                account_id=row["account_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
                expires_at=expires_at,
                consumed_at=consumed_at,
            )

    # ---- binding-token reads ----

    def get_binding(self, binding_token: str) -> OAuthBinding | None:
        rows = self.db.execute(
            "SELECT * FROM account_oauth_bindings WHERE binding_token = ?",
            (binding_token,),
        )
        return self._row_to_binding(rows[0]) if rows else None

    # ---- helpers ----

    @staticmethod
    def _row_to_account(row: sqlite3.Row) -> Account:
        return Account(
            account_id=row["account_id"],
            idp=IdentityProvider(row["idp"]),
            idp_sub=row["idp_sub"],
            display_name=row["display_name"],
            email=row["email"],
            trust_tier=TrustTier(row["trust_tier"]),
            research_standing=ResearchStanding(
                row["research_standing"] if "research_standing" in row.keys() else 1
            ),
            created_at=datetime.fromisoformat(row["created_at"]),
            retired_at=(datetime.fromisoformat(row["retired_at"]) if row["retired_at"] else None),
            identity_verified_at=(
                datetime.fromisoformat(row["identity_verified_at"])
                if row["identity_verified_at"]
                else None
            ),
            identity_verified_by=row["identity_verified_by"],
            identity_verification_method=(
                IdentityVerificationMethod(row["identity_verification_method"])
                if row["identity_verification_method"]
                else None
            ),
            identity_verification_note=row["identity_verification_note"],
            orcid_id=(row["orcid_id"] if "orcid_id" in row.keys() else None),
            suspended_at=(
                datetime.fromisoformat(row["suspended_at"]) if row["suspended_at"] else None
            ),
            suspension_reason=row["suspension_reason"],
            tier_set_by_class=(
                row["tier_set_by_class"] if "tier_set_by_class" in row.keys() else None
            ),
            public_attribution=bool(
                row["public_attribution"] if "public_attribution" in row.keys() else 0
            ),
            attribution_name=(
                row["attribution_name"] if "attribution_name" in row.keys() else None
            ),
        )

    @staticmethod
    def _row_to_binding(row: sqlite3.Row) -> OAuthBinding:
        return OAuthBinding(
            binding_token=row["binding_token"],
            account_id=row["account_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            consumed_at=(
                datetime.fromisoformat(row["consumed_at"]) if row["consumed_at"] else None
            ),
        )
