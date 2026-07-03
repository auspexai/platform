"""Per-job database factory — one SQLite DB per experiment (§5.7).

Each experiment that receives work-unit submissions gets its own SQLite
file at `<jobs_dir>/<experiment_id>.db`. The factory lazily creates the
file (with parent dirs) and applies the per-job schema on first access,
then caches the open `Database` for the lifetime of the coordinator
process.

Why per-job DBs at all (per §5.7):
  - Control state stays small even as the network handles many experiments
  - Each per-job DB is an independent unit — can be moved, archived,
    sharded onto a different host later without coupling to control state
  - One experiment's hot writes don't lock another's reads
  - Foreclose the future-HA refactor — Phase 1 v0 is a single coordinator,
    but the data layout permits multi-coordinator sharding by experiment

Per-job DBs do not share migrations with the control DB; each is created
fresh from `PER_JOB_SCHEMA_SQL` and has exactly one schema version for v0.
Phase 2 may introduce per-job migration if the shape needs to evolve.

Closure: connections are closed via `close_all()` at app shutdown. Tests
isolate state through `state_dir` (a per-test temp dir) so each test gets
its own jobs/ tree.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from auspexai_platform.db.database import Database

# Per-job DB schema. M6c added `work_units`; M6d adds `assignments` and
# `results`. The constant is idempotent (CREATE TABLE IF NOT EXISTS) so
# adding tables here also extends existing per-job DBs on next-open.
PER_JOB_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS work_units (
    unit_id              TEXT    PRIMARY KEY,
    payload_json         TEXT    NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'pending',
    replication_target   INTEGER NOT NULL DEFAULT 3,
    completions_so_far   INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT    NOT NULL,
    pinned_worker_id     TEXT,
    CHECK (status IN ('pending', 'in_progress', 'completed', 'failed'))
);

CREATE INDEX IF NOT EXISTS work_units_status_idx ON work_units(status);


CREATE TABLE IF NOT EXISTS assignments (
    assignment_id        TEXT    PRIMARY KEY,
    unit_id              TEXT    NOT NULL,
    worker_id            TEXT    NOT NULL,
    worker_pubkey_hex    TEXT    NOT NULL,
    assigned_at          TEXT    NOT NULL,
    result_id            TEXT,
    refused_at           TEXT,
    refused_kind         TEXT,
    refused_reason       TEXT,
    attempt_count        INTEGER NOT NULL DEFAULT 1,
    UNIQUE (unit_id, worker_id),
    FOREIGN KEY (unit_id) REFERENCES work_units(unit_id)
);

CREATE INDEX IF NOT EXISTS assignments_unit_idx ON assignments(unit_id);
CREATE INDEX IF NOT EXISTS assignments_worker_idx ON assignments(worker_id);


CREATE TABLE IF NOT EXISTS results (
    result_id            TEXT    PRIMARY KEY,
    unit_id              TEXT    NOT NULL,
    worker_id            TEXT    NOT NULL,
    worker_pubkey_hex    TEXT    NOT NULL,
    exit_code            INTEGER NOT NULL,
    payload_json         TEXT    NOT NULL,
    worker_signature     TEXT    NOT NULL,
    completed_at         TEXT    NOT NULL,
    received_at          TEXT    NOT NULL,
    -- M-Results: retention + delivery. `semantic_hash` persists the reduce-time
    -- hash (so an aged-off row still self-describes its content); `is_consensus`
    -- marks the one durable T-C copy; `delivered_at` is the first tenant fetch;
    -- `payload_aged_off_at` (set when payload_json is blanked to '') is the
    -- authoritative aged-off signal — payload_json stays NOT NULL (blanked, not
    -- nulled), since SQLite can't drop the constraint without a table rebuild.
    semantic_hash        TEXT,
    is_consensus         INTEGER NOT NULL DEFAULT 0,
    delivered_at         TEXT,
    payload_expires_at   TEXT,
    payload_aged_off_at  TEXT,
    -- EB-1 (§9 #47): coordinator-asserted serving-environment snapshot taken
    -- at result submission (worker version / ollama_version / served model ids
    -- from the worker's last heartbeat). NULL = pre-EB-1 row or nothing known.
    environment_json     TEXT,
    -- §9 #13a: the worker-SIGNED schema version (NULL/0 = legacy 5-field body;
    -- 1 = body also signs served_weights) and the worker-ATTESTED served-weights
    -- digest map. Distinct from environment_json (coordinator-asserted): this is
    -- covered by the worker signature, so #13b enforces against it.
    schema_version       INTEGER,
    served_weights_json  TEXT,
    -- A2 #32 (equal-trust flip activation): the worker-SIGNED sandbox policy this
    -- result ran under (v2 body). Covered by the worker signature, so the
    -- containment guard is accountable, not heartbeat-self-reported. NULL = pre-v2
    -- result → falls back to the worker's reported capability.
    ran_under            TEXT,
    FOREIGN KEY (unit_id) REFERENCES work_units(unit_id)
);

CREATE INDEX IF NOT EXISTS results_unit_idx ON results(unit_id);
CREATE INDEX IF NOT EXISTS results_worker_idx ON results(worker_id);
CREATE INDEX IF NOT EXISTS results_consensus_idx ON results(is_consensus);


-- M7b: receipts table. One row per issued contribution receipt. Stores
-- both the canonical COSE-Sign1 wire bytes (what verifiers consume) and
-- the inner CBOR payload (handy for debug / aggregation queries / future
-- Rekor anchoring). `work_unit_ids_json` is a JSON array because a single
-- receipt may attest to multiple units in the same experiment.
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id              TEXT    PRIMARY KEY,
    work_unit_ids_json      TEXT    NOT NULL,
    cose_signed_blob        BLOB    NOT NULL,
    receipt_body_cbor       BLOB    NOT NULL,
    signing_key_pubkey_hex  TEXT    NOT NULL,
    issued_at               TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS receipts_issued_idx ON receipts(issued_at);


-- C7 Inc 4: per-unit tolerance-consensus evidence, persisted AT ISSUANCE (the
-- Inc 2 deferral). Written only for `builtin_within_cell_tolerance` units that
-- reached agreement; exact/process_only units have no row (their consensus hash
-- IS a replica's semantic hash — nothing extra to evidence). Issuance-time
-- persistence is load-bearing: raw replica payloads age off, so the partition
-- cannot be recomputed later. All JSON members are §7-contained (the
-- representative is composed of DECLARED features only — the same containment
-- boundary as the result payloads themselves).
CREATE TABLE IF NOT EXISTS unit_consensus (
    unit_id             TEXT    PRIMARY KEY,
    method              TEXT    NOT NULL,
    representative_json TEXT,            -- the deterministic per-feature consensus vector
    representative_hash TEXT,            -- semantic_hash(0, representative): the attestation-leaf hash for a tolerance unit
    spread_json         TEXT,            -- {feature: observed spread among ALL replicas}
    envelope_json       TEXT,            -- {feature: comparison rule} in force at issuance
    agreeing_workers    INTEGER NOT NULL,
    outlier_count       INTEGER NOT NULL DEFAULT 0,
    outlier_hashes_json TEXT,            -- D19: outlier semantic hashes (predicate-anchored; NULL pre-fix)
    recorded_at         TEXT    NOT NULL,
    FOREIGN KEY (unit_id) REFERENCES work_units(unit_id)
);
"""


class PerJobDatabaseFactory:
    """Lazily opens and caches one `Database` per experiment_id.

    Thread-safe: the internal cache is guarded by a lock so concurrent
    callers asking for the same experiment_id get back the same instance.
    """

    def __init__(self, jobs_dir: Path):
        self._jobs_dir = jobs_dir
        self._jobs_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, Database] = {}
        self._lock = threading.Lock()

    def get_or_create(self, experiment_id: str) -> Database:
        """Return the per-job Database for `experiment_id`, creating the
        file and applying the schema if it doesn't exist yet."""
        with self._lock:
            cached = self._cache.get(experiment_id)
            if cached is not None:
                return cached
            db_path = self._path_for(experiment_id)
            db = Database(db_path)
            db.executescript(PER_JOB_SCHEMA_SQL)
            _ensure_assignments_refused_columns(db)
            _ensure_results_retention_columns(db)
            _ensure_results_environment_column(db)
            _ensure_results_served_weights_columns(db)
            _ensure_results_ran_under_column(db)
            _ensure_work_units_pin_column(db)
            _ensure_unit_consensus_table(db)
            self._cache[experiment_id] = db
            return db

    def get(self, experiment_id: str) -> Database | None:
        """Return the cached DB if it exists, else None. Does NOT create.

        Useful for read paths where the experiment may not yet have
        received work-unit submissions (no per-job DB exists yet).
        """
        with self._lock:
            cached = self._cache.get(experiment_id)
            if cached is not None:
                return cached
            db_path = self._path_for(experiment_id)
            if not db_path.exists():
                return None
            # On a fresh coordinator process, the file may exist on disk
            # but not be cached yet — load it. Apply post-M6d schema
            # additions idempotently so pre-Option-A per-job DBs work.
            db = Database(db_path)
            _ensure_assignments_refused_columns(db)
            _ensure_results_retention_columns(db)
            _ensure_results_environment_column(db)
            _ensure_results_served_weights_columns(db)
            _ensure_results_ran_under_column(db)
            _ensure_work_units_pin_column(db)
            _ensure_unit_consensus_table(db)
            self._cache[experiment_id] = db
            return db

    def close_all(self) -> None:
        with self._lock:
            for db in self._cache.values():
                db.close()
            self._cache.clear()

    def iter_cached_dbs(self) -> list[tuple[str, Database]]:
        """Return [(experiment_id, db), ...] for all cached per-job DBs.

        Used by route handlers that need to scan for a (unit_id, worker_id)
        assignment without knowing the experiment_id in advance. Hot DBs
        are by definition cached, so this covers normal worker flow; cold-
        load (post-restart) is handled by `get(experiment_id)` once the
        caller learns the experiment_id.
        """
        with self._lock:
            return list(self._cache.items())

    def _path_for(self, experiment_id: str) -> Path:
        return self._jobs_dir / f"{experiment_id}.db"


def _ensure_assignments_refused_columns(db: Database) -> None:
    """Idempotently add the Option-A assignment-lifecycle columns to the
    per-job `assignments` table: refused_at / refused_kind / refused_reason
    (M3 refuse) + attempt_count (§2.1 #8 dispatch-retry — bumped each time a
    retryable refusal re-offers the unit to the same worker). The columns are
    part of PER_JOB_SCHEMA_SQL for newly-created DBs, but existing per-job DBs
    were created without them; ALTER TABLE ADD COLUMN is the cheap way to
    converge. attempt_count defaults to 1 so pre-existing rows read as their
    single original attempt.
    """
    _add_columns_idempotent(
        db,
        "assignments",
        (
            ("refused_at", "TEXT"),
            ("refused_kind", "TEXT"),
            ("refused_reason", "TEXT"),
            ("attempt_count", "INTEGER NOT NULL DEFAULT 1"),
        ),
    )


def _ensure_results_environment_column(db: Database) -> None:
    """Idempotently add `environment_json` (EB-1 §9 #47) to the per-job
    `results` table — the coordinator-asserted serving-environment snapshot
    captured at result submission. Pre-existing rows read NULL (= unknown,
    pre-EB-1), which the attestation builder passes through as absent."""
    _add_columns_idempotent(db, "results", (("environment_json", "TEXT"),))


def _ensure_results_served_weights_columns(db: Database) -> None:
    """Idempotently add the §9 #13a columns to the per-job `results` table:
    `schema_version` (the worker-signed canonical version; NULL/0 = legacy) and
    `served_weights_json` (the worker-ATTESTED served-weights digest map).
    Pre-existing rows read NULL — treated as v0 (no attested digest)."""
    _add_columns_idempotent(
        db,
        "results",
        (("schema_version", "INTEGER"), ("served_weights_json", "TEXT")),
    )


def _ensure_results_ran_under_column(db: Database) -> None:
    """Idempotently add `ran_under` (A2 #32) to the per-job `results` table — the
    worker-SIGNED sandbox policy the result ran under (v2 body). Part of
    PER_JOB_SCHEMA_SQL for new DBs; this converges existing per-job DBs. NULL =
    pre-v2 result → the trust resolver falls back to the worker's reported
    capability."""
    _add_columns_idempotent(db, "results", (("ran_under", "TEXT"),))


def _ensure_work_units_pin_column(db: Database) -> None:
    """Idempotently add `pinned_worker_id` to the per-job `work_units` table
    (M4-tail pin / force-assign). Part of PER_JOB_SCHEMA_SQL for new DBs; this
    converges existing per-job DBs. NULL = unpinned (every existing unit)."""
    _add_columns_idempotent(db, "work_units", (("pinned_worker_id", "TEXT"),))


def _ensure_unit_consensus_table(db: Database) -> None:
    """Idempotently create the C7 Inc 4 `unit_consensus` evidence table on
    existing per-job DBs (part of PER_JOB_SCHEMA_SQL for new ones). Old
    experiments simply have no rows — their attestation leaves keep the
    promoted replica's semantic hash, so already-persisted roots rebuild
    byte-identically."""
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS unit_consensus (
            unit_id             TEXT    PRIMARY KEY,
            method              TEXT    NOT NULL,
            representative_json TEXT,
            representative_hash TEXT,
            spread_json         TEXT,
            envelope_json       TEXT,
            agreeing_workers    INTEGER NOT NULL,
            outlier_count       INTEGER NOT NULL DEFAULT 0,
            outlier_hashes_json TEXT,
            recorded_at         TEXT    NOT NULL,
            FOREIGN KEY (unit_id) REFERENCES work_units(unit_id)
        )
        """
    )
    _ensure_unit_consensus_outlier_hashes_column(db)


def _ensure_unit_consensus_outlier_hashes_column(db: Database) -> None:
    """D19 forward-fix: tolerance OUTLIER result hashes were recorded nowhere
    signed (only `outlier_count`) — so outlier payloads could never be
    anchor-verified post-hoc. NULL on pre-fix rows: those outliers are simply
    never exported (anchor-or-omit)."""
    cols = {r["name"] for r in db.execute("PRAGMA table_info(unit_consensus)")}
    if "outlier_hashes_json" not in cols:
        db.execute("ALTER TABLE unit_consensus ADD COLUMN outlier_hashes_json TEXT")


def _ensure_results_retention_columns(db: Database) -> None:
    """Idempotently add the M-Results retention/delivery columns to the per-job
    `results` table. Part of PER_JOB_SCHEMA_SQL for new DBs; this converges
    existing per-job DBs created before M-Results. (Same pattern as the
    assignments refused-columns bump — per-job DBs have no PRAGMA user_version.)
    """
    _add_columns_idempotent(
        db,
        "results",
        (
            ("semantic_hash", "TEXT"),
            ("is_consensus", "INTEGER NOT NULL DEFAULT 0"),
            ("delivered_at", "TEXT"),
            ("payload_expires_at", "TEXT"),
            ("payload_aged_off_at", "TEXT"),
        ),
    )


def _add_columns_idempotent(db: Database, table: str, columns: tuple[tuple[str, str], ...]) -> None:
    """ALTER TABLE ADD COLUMN for each (name, sql_type), tolerating already-present
    columns. The cheap per-job 'migration' mechanism (no schema-version table)."""
    for column, sql_type in columns:
        try:
            db.executescript(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type};")
        except sqlite3.OperationalError as exc:
            # "duplicate column name" — column already present, fine.
            if "duplicate column" not in str(exc).lower():
                raise
