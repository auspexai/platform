-- 0020_model_prestage.sql — eager download conductor (M3b, §9 #39 §3b).
--
-- The lazy auto-acquire baseline (M3) pulls a model only when a worker is
-- assigned a unit needing it. The conductor PRE-stages a model onto a sized
-- subset of eligible workers BEFORE the experiment's units land there, so a
-- model-gated experiment isn't bottlenecked on first-assignment pulls. Each row
-- is one (model, worker) pre-stage directive the worker drains via
-- GET /workers/{id}/prestage and fulfils with its M3 auto-acquire path; the
-- coordinator marks it `acquired` once the worker declares the model in its
-- heartbeat inventory. Sizing is bounded by counting open rows + holders against
-- the experiment's replication need, so no thundering herd. Rows are created
-- either by the auto-conductor (on the worker's prestage poll) or the maintainer
-- trigger-prestage override (M4-tail).

CREATE TABLE model_prestage (
    prestage_id     TEXT    PRIMARY KEY,
    model_id        TEXT    NOT NULL,
    hf_repo         TEXT    NOT NULL,
    hf_filename     TEXT    NOT NULL,
    worker_id       TEXT    NOT NULL,
    experiment_id   TEXT,
    requested_by    TEXT    NOT NULL,   -- 'conductor' or a maintainer login
    requested_at    TEXT    NOT NULL,
    acquired_at     TEXT,
    status          TEXT    NOT NULL DEFAULT 'requested',  -- requested | acquired | abandoned
    UNIQUE (model_id, worker_id),
    FOREIGN KEY (worker_id) REFERENCES workers(worker_id)
);

CREATE INDEX model_prestage_worker_idx ON model_prestage(worker_id, status);
CREATE INDEX model_prestage_model_idx ON model_prestage(model_id, status);
