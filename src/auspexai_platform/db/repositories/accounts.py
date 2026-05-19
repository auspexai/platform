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
    Account,
    IdentityProvider,
    OAuthBinding,
    TrustTier,
)

# 5 minutes: long enough for the caller to round-trip the exchange + binder
# call, short enough that a leaked token has tight blast radius.
DEFAULT_BINDING_TTL = timedelta(minutes=5)


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
        trust_tier: TrustTier = TrustTier.T1_VERIFIED,
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

    # ---- account reads ----

    def get_by_id(self, account_id: str) -> Account | None:
        rows = self.db.execute(
            "SELECT * FROM accounts WHERE account_id = ?",
            (account_id,),
        )
        return self._row_to_account(rows[0]) if rows else None

    def get_by_idp_subject(self, idp: IdentityProvider, idp_sub: str) -> Account | None:
        rows = self.db.execute(
            "SELECT * FROM accounts WHERE idp = ? AND idp_sub = ?",
            (idp.value, idp_sub),
        )
        return self._row_to_account(rows[0]) if rows else None

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
            created_at=datetime.fromisoformat(row["created_at"]),
            retired_at=(datetime.fromisoformat(row["retired_at"]) if row["retired_at"] else None),
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
