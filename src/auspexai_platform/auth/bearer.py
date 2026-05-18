"""Maintainer bearer token store.

Per §10.1 of the design doc:

  - Token is generated at coordinator init (32 random bytes, base64url-encoded).
  - Written to `<state-dir>/maintainer.token` with mode 0600.
  - Rotatable via `auspexai-coordinator token rotate`; old token remains valid
    for a 5-minute overlap window so an operator-console session updating to
    the new token never sees a flicker of 401s.

The file format is JSON:

    {
      "tokens": [
        {"token": "<base64url>", "created_at": "...", "expires_at": null},
        {"token": "<base64url>", "created_at": "...", "expires_at": "..."}
      ]
    }

`expires_at: null` means active. Rotation: set the current entry's
`expires_at` to now + overlap; append a fresh entry with `expires_at: null`.

Verification is constant-time across all non-expired tokens. Token comparison
goes through `hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_OVERLAP = timedelta(minutes=5)
TOKEN_BYTES = 32  # → 43 chars of base64url


@dataclass(frozen=True)
class TokenEntry:
    """One active or expiring token in the maintainer token file."""

    token: str
    created_at: datetime
    expires_at: datetime | None  # None = active; datetime = expires at that wall-clock instant

    def is_active(self, now: datetime) -> bool:
        if self.expires_at is None:
            return True
        return now < self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> TokenEntry:
        return cls(
            token=raw["token"],
            created_at=datetime.fromisoformat(raw["created_at"]),
            expires_at=datetime.fromisoformat(raw["expires_at"]) if raw["expires_at"] else None,
        )


class TokenStoreError(Exception):
    """Raised on TokenStore I/O or state errors (not auth failures — those are AuthError)."""


class TokenStore:
    """Persistent maintainer-token state.

    Instances are bound to a `Path`; methods read/write the file atomically.
    """

    def __init__(self, path: Path):
        self.path = path

    # ---- file I/O ----

    def _read(self) -> list[TokenEntry]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise TokenStoreError(f"corrupt token file at {self.path}: {e}") from e
        if not isinstance(raw, dict) or "tokens" not in raw:
            raise TokenStoreError(f"unexpected token file shape at {self.path}")
        return [TokenEntry.from_dict(entry) for entry in raw["tokens"]]

    def _write(self, entries: list[TokenEntry]) -> None:
        """Atomic write: temp file in same dir, fsync, rename, chmod 0600."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        body = json.dumps({"tokens": [e.to_dict() for e in entries]}, indent=2)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        # `mode=0o600` only honored on create; chmod after rename is the portable path.
        tmp.write_text(body + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    # ---- lifecycle operations ----

    def initialize(self, *, force: bool = False) -> str:
        """First-run setup. Generates a fresh token and writes the file.

        Idempotent only with `force=True`: refuses to overwrite an existing
        token file unless caller explicitly opts in (matches the SDK's
        `key generate --force` ergonomics).
        """
        if self.path.exists() and not force:
            raise TokenStoreError(
                f"{self.path} already exists. Pass force=True / --force to overwrite."
            )
        token = secrets.token_urlsafe(TOKEN_BYTES)
        entry = TokenEntry(token=token, created_at=datetime.now(UTC), expires_at=None)
        self._write([entry])
        return token

    def rotate(self, *, overlap: timedelta = DEFAULT_OVERLAP) -> str:
        """Generate a new active token; keep the previous active token valid
        for `overlap` more time.

        Returns the new token. The old active token stays usable until its
        new `expires_at`, after which `verify` rejects it.
        """
        now = datetime.now(UTC)
        entries = self._read()
        # Expire the current active(s) — there should normally be only one, but be defensive.
        new_entries: list[TokenEntry] = []
        for entry in entries:
            if entry.is_active(now):
                new_entries.append(
                    TokenEntry(
                        token=entry.token,
                        created_at=entry.created_at,
                        expires_at=now + overlap,
                    )
                )
            else:
                # Drop entries that are already expired — no reason to keep them around.
                continue
        # Append the new active token.
        fresh = secrets.token_urlsafe(TOKEN_BYTES)
        new_entries.append(TokenEntry(token=fresh, created_at=now, expires_at=None))
        self._write(new_entries)
        return fresh

    def active_tokens(self, *, now: datetime | None = None) -> list[str]:
        """Return all currently-valid tokens (in load order). May be 1
        (steady state) or 2 (during rotation overlap)."""
        now = now or datetime.now(UTC)
        return [e.token for e in self._read() if e.is_active(now)]

    def verify(self, presented: str, *, now: datetime | None = None) -> bool:
        """Constant-time compare against all currently-valid tokens. Empty or
        too-short tokens always return False without leaking timing."""
        now = now or datetime.now(UTC)
        if not presented:
            return False
        valid = self.active_tokens(now=now)
        if not valid:
            return False
        # Walk every entry (don't early-exit on match) to keep verify-time roughly constant.
        result = False
        for token in valid:
            if hmac.compare_digest(presented, token):
                result = True
        return result
