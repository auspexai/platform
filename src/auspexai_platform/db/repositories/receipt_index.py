"""ReceiptIndexRepository — control-DB pointer to per-job receipt rows.

Populated by M7c's receipt-issuance hook (one index row per issued
receipt) so cross-experiment queries don't need to walk every per-job DB.
The full receipt content (COSE-Sign1 bytes + inner CBOR) still lives on
the per-job DB; this table just maps `receipt_id -> experiment_id` plus
denormalizes worker_id + worker_pubkey for fast filtering.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from auspexai_platform.db.database import Database


class DuplicateReceiptIndexError(Exception):
    """Raised when the same receipt_id is indexed twice."""


@dataclass(frozen=True)
class ReceiptIndexEntry:
    """One row of the receipt_index table — points at where the receipt
    actually lives + carries the worker identity for scope checks."""

    receipt_id: str
    experiment_id: str  # coord-side exp- id (locates the per-job DB)
    worker_id: str
    worker_pubkey: str  # 64 lowercase hex
    issued_at: datetime
    result_id: str | None = None  # M7-tail: backreference to the worker's result row
    unit_id: str | None = None  # A4 (0035): the work unit, for per-account-per-unit trust
    ran_under_strict: bool = False  # A2 (0037): STRICT containment — equal-trust accrual gate
    public_attribution_at_issue: bool = False  # System B (0039): opt-in snapshot at issue
    account_id_at_issue: str | None = None  # 0041: account snapshot, survives worker unbind


class ReceiptIndexRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- writes ----

    def _resolve_account_id(self, worker_id: str) -> str | None:
        """The worker's CURRENT account_id, snapshotted onto the index row at
        issuance (0041). Returns None for anonymous/T0 workers (no binding) or
        an unknown worker_id — both correctly snapshot a NULL account, matching
        the INNER JOIN on workers that the account-scoped queries used before."""
        rows = self.db.execute(
            "SELECT account_id FROM workers WHERE worker_id = ?",
            (worker_id,),
        )
        return rows[0]["account_id"] if rows else None

    def record(
        self,
        *,
        receipt_id: str,
        experiment_id: str,
        worker_id: str,
        worker_pubkey: str,
        result_id: str | None = None,
        unit_id: str | None = None,
        ran_under_strict: bool = False,
        public_attribution_at_issue: bool = False,
    ) -> ReceiptIndexEntry:
        """Index a newly-issued receipt. Raises DuplicateReceiptIndexError if
        receipt_id is already indexed (should not happen during normal
        operation — surfaces real bugs).

        `result_id` is M7-tail's backreference: it lets the worker fetch the
        canonical receipt for one of its results via a single index hit.
        `unit_id` (A4, 0035) is the work unit, so per-account trust can count
        distinct units rather than raw receipts. `ran_under_strict` (A2, 0037)
        records the containment the agreeing worker ran under, so the equal-trust
        accrual can keep only STRICT-contained units. Nullable/defaulted for
        backward compatibility with rows created before their respective migrations.
        """
        worker_pubkey = worker_pubkey.lower()
        issued_at = datetime.now(UTC).isoformat()
        # Snapshot the worker's account_id at issuance (0041) so a later worker
        # unbind (account_id -> NULL) can't retroactively orphan this receipt.
        account_id_at_issue = self._resolve_account_id(worker_id)
        try:
            self.db.execute(
                """
                INSERT INTO receipt_index
                  (receipt_id, experiment_id, worker_id, worker_pubkey, issued_at,
                   result_id, unit_id, ran_under_strict, public_attribution_at_issue,
                   account_id_at_issue)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_id,
                    experiment_id,
                    worker_id,
                    worker_pubkey,
                    issued_at,
                    result_id,
                    unit_id,
                    1 if ran_under_strict else 0,
                    1 if public_attribution_at_issue else 0,
                    account_id_at_issue,
                ),
            )
        except sqlite3.IntegrityError as e:
            # Distinguish duplicate-PK from FK-violation by inspecting the
            # sqlite error text. UNIQUE violations on receipt_id are
            # caller-recoverable (idempotent retries); FK violations are
            # bugs (worker_id doesn't exist) and bubble up unchanged.
            if "UNIQUE" in str(e):
                raise DuplicateReceiptIndexError(str(e)) from e
            raise
        got = self.get_by_id(receipt_id)
        assert got is not None
        return got

    def record_divergence(
        self,
        *,
        experiment_id: str,
        worker_id: str,
        worker_pubkey: str,
        unit_id: str,
        ran_under_strict: bool,
    ) -> None:
        """Index one diverging worker's honest work on a diverged unit (A2, 0037).

        The disagreement class is NOT minted as a Receipt object (firewall #1
        design §11) — it gets this parallel trust-index instead. Recorded for
        every diverged unit (evidentiary now, D7's "issue now"); the equal-trust
        accrual only COUNTS it once `trust_model_policy.equal_trust_enabled` is ON,
        and only the `ran_under_strict` rows. Idempotent (INSERT OR IGNORE on the
        (worker_id, unit_id) unique key) so a re-finalization sweep is a no-op."""
        # Snapshot the worker's account_id at issuance (0041) — same permanence
        # guarantee as receipt_index, so a later unbind can't orphan divergence.
        account_id_at_issue = self._resolve_account_id(worker_id)
        self.db.execute(
            """
            INSERT OR IGNORE INTO divergence_index
              (experiment_id, worker_id, worker_pubkey, unit_id, ran_under_strict,
               account_id_at_issue)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                experiment_id,
                worker_id,
                worker_pubkey.lower(),
                unit_id,
                1 if ran_under_strict else 0,
                account_id_at_issue,
            ),
        )

    # ---- reads ----

    def get_by_id(self, receipt_id: str) -> ReceiptIndexEntry | None:
        rows = self.db.execute(
            "SELECT * FROM receipt_index WHERE receipt_id = ?",
            (receipt_id,),
        )
        return self._row_to_entry(rows[0]) if rows else None

    def list_for_worker(self, worker_id: str) -> list[ReceiptIndexEntry]:
        """All receipts attributable to one worker_id, newest first."""
        rows = self.db.execute(
            "SELECT * FROM receipt_index WHERE worker_id = ? ORDER BY issued_at DESC",
            (worker_id,),
        )
        return [self._row_to_entry(r) for r in rows]

    def list_for_account(self, account_id: str) -> list[ReceiptIndexEntry]:
        """All receipts attributed to one account_id at issuance, newest first.

        Filters on the denormalized `account_id_at_issue` snapshot (0041) rather
        than the live workers.account_id, so a contribution stays attributed even
        if its worker later unbinds. Rows snapshotted with a NULL account
        (anonymous / T0 workers) are not returned — account-scoped listing only
        makes sense for accounts.
        """
        rows = self.db.execute(
            """
            SELECT * FROM receipt_index
            WHERE account_id_at_issue = ?
            ORDER BY issued_at DESC
            """,
            (account_id,),
        )
        return [self._row_to_entry(r) for r in rows]

    def account_receipt_summary(self, account_id: str) -> tuple[int, int]:
        """(total_receipts, distinct_tenants) for an account — joins
        receipt_index → workers → experiments to count DISTINCT tenant_id (not
        experiments). Powers the §6.2.2 anti-Sybil vouch gate; the
        compute_receipt_stats `distinct_tenants` is only an experiment-count
        upper bound, too weak for an anti-Sybil threshold. Receipts whose
        experiment row is gone (e.g. a clean-slate) don't count — the INNER JOIN
        keeps the gate to receipts tied to known tenants."""
        rows = self.db.execute(
            """
            SELECT COUNT(*) AS total, COUNT(DISTINCT e.tenant_id) AS tenants
            FROM receipt_index ri
            INNER JOIN experiments e ON e.experiment_id = ri.experiment_id
            WHERE ri.account_id_at_issue = ?
            """,
            (account_id,),
        )
        if not rows:
            return (0, 0)
        return (int(rows[0]["total"]), int(rows[0]["tenants"]))

    def account_corroboration_summary(
        self, account_id: str, *, equal_trust_enabled: bool = False
    ) -> tuple[int, int]:
        """(distinct_units, distinct_tenants) — the firewall #3 (A4) ACCOUNT-WEIGHTED
        trust metric. Counts DISTINCT work units the account corroborated, NOT raw
        receipts: an operator's N workers under one account corroborating the same
        unit earn ONE unit of trust, not N — closing within-account receipt-farming
        toward T2 / the vouch gate. `COALESCE(unit_id, receipt_id)` keeps pre-0035
        rows (unit_id NULL) at their prior one-each behavior, so the dedup engages
        only on rows carrying unit_id. `account_receipt_summary` (raw totals) stays
        for display; this is the count the trust GATES consult.

        `equal_trust_enabled` (A2 / the firewall #1 flip): when FALSE (the default,
        and the live state until the activation gate) the count is unchanged — it
        reads agreement receipts regardless of containment. When TRUE (post-flip),
        trust accrues from the process bundle, which REQUIRES STRICT containment
        and is EQUAL for agreement AND divergence (firewall_1 D7): the count becomes
        distinct STRICT-contained units across `receipt_index` (agreement) UNION
        `divergence_index` (disagreement) — never reading `integrity_basis`/agreement.
        Permissive units carry no bundle, so they don't count."""
        if not equal_trust_enabled:
            rows = self.db.execute(
                """
                SELECT COUNT(DISTINCT COALESCE(ri.unit_id, ri.receipt_id)) AS units,
                       COUNT(DISTINCT e.tenant_id) AS tenants
                FROM receipt_index ri
                INNER JOIN experiments e ON e.experiment_id = ri.experiment_id
                WHERE ri.account_id_at_issue = ?
                """,
                (account_id,),
            )
            if not rows:
                return (0, 0)
            return (int(rows[0]["units"]), int(rows[0]["tenants"]))

        # Equal-trust (flip ON): STRICT-contained units only, agreement UNION
        # divergence, counted equally per unit (D7). The UNION dedups so an account both
        # agreed and diverged on the same unit still counts it once (A4 per-unit).
        rows = self.db.execute(
            """
            SELECT COUNT(DISTINCT unit) AS units, COUNT(DISTINCT tenant) AS tenants
            FROM (
                SELECT COALESCE(ri.unit_id, ri.receipt_id) AS unit, e.tenant_id AS tenant
                FROM receipt_index ri
                INNER JOIN experiments e ON e.experiment_id = ri.experiment_id
                WHERE ri.account_id_at_issue = ? AND ri.ran_under_strict = 1
                UNION
                SELECT di.unit_id AS unit, e.tenant_id AS tenant
                FROM divergence_index di
                INNER JOIN experiments e ON e.experiment_id = di.experiment_id
                WHERE di.account_id_at_issue = ? AND di.ran_under_strict = 1
            )
            """,
            (account_id, account_id),
        )
        if not rows:
            return (0, 0)
        return (int(rows[0]["units"]), int(rows[0]["tenants"]))

    def get_for_worker_result(self, *, worker_id: str, result_id: str) -> ReceiptIndexEntry | None:
        """Find the receipt index entry for a specific (worker, result) pair
        (M7-tail). Returns None if no receipt was issued for this result
        (e.g., the unit's quorum disagreed) or if the receipt was indexed
        before M7-tail (result_id IS NULL)."""
        rows = self.db.execute(
            """
            SELECT * FROM receipt_index
            WHERE worker_id = ? AND result_id = ?
            """,
            (worker_id, result_id),
        )
        return self._row_to_entry(rows[0]) if rows else None

    def list_for_experiment(self, experiment_id: str) -> list[ReceiptIndexEntry]:
        """All receipts issued for one experiment, newest first.

        Powers the tenant-scoped researcher view (GET /experiments/{id}/
        receipts). Callers must enforce tenant ownership of the experiment
        before exposing these; the entries carry worker identity, which is
        NOT tenant-visible and must be stripped at the API layer."""
        rows = self.db.execute(
            "SELECT * FROM receipt_index WHERE experiment_id = ? ORDER BY issued_at DESC",
            (experiment_id,),
        )
        return [self._row_to_entry(r) for r in rows]

    def list_for_pubkey(self, pubkey_hex: str) -> list[ReceiptIndexEntry]:
        """All receipts where the contributing worker had this pubkey.

        For Phase 1 a worker's pubkey is unique, so this overlaps heavily
        with `list_for_worker`. Once Phase 2's key rotation lands (or the
        retired_keys registry is consulted for verifying old receipts),
        pubkey-keyed lookups are the more stable cross-reference."""
        rows = self.db.execute(
            "SELECT * FROM receipt_index WHERE worker_pubkey = ? ORDER BY issued_at DESC",
            (pubkey_hex.lower(),),
        )
        return [self._row_to_entry(r) for r in rows]

    def list_all(self) -> list[ReceiptIndexEntry]:
        rows = self.db.execute("SELECT * FROM receipt_index ORDER BY issued_at DESC")
        return [self._row_to_entry(r) for r in rows]

    # ---- helpers ----

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> ReceiptIndexEntry:
        # result_id is M7-tail; unit_id is A4/0035 — both nullable on rows from
        # before their respective migrations.
        try:
            result_id = row["result_id"]
        except (KeyError, IndexError):
            result_id = None
        try:
            unit_id = row["unit_id"]
        except (KeyError, IndexError):
            unit_id = None
        try:
            ran_under_strict = bool(row["ran_under_strict"])
        except (KeyError, IndexError):
            ran_under_strict = False
        try:
            public_attribution_at_issue = bool(row["public_attribution_at_issue"])
        except (KeyError, IndexError):
            public_attribution_at_issue = False
        try:
            account_id_at_issue = row["account_id_at_issue"]
        except (KeyError, IndexError):
            account_id_at_issue = None
        return ReceiptIndexEntry(
            receipt_id=row["receipt_id"],
            experiment_id=row["experiment_id"],
            worker_id=row["worker_id"],
            worker_pubkey=row["worker_pubkey"],
            issued_at=datetime.fromisoformat(row["issued_at"]),
            result_id=result_id,
            unit_id=unit_id,
            ran_under_strict=ran_under_strict,
            public_attribution_at_issue=public_attribution_at_issue,
            account_id_at_issue=account_id_at_issue,
        )
