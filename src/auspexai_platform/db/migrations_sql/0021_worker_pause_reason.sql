-- 0021_worker_pause_reason.sql — make the operator pause reason worker-visible (§2.1 #11).
--
-- M4 made pause reason mandatory but only AUDITED it (operator-only); the worker
-- just saw "no work". §2.1 #11 ratifies that an operator pausing a volunteer's
-- worker should TELL the volunteer + why — same transparency as quarantine, but
-- still no-fault (a distinct `worker_paused` code, no trust impact). Store the
-- reason on the row so the /assignments 423 can carry it. NULL = no reason / not
-- paused (the default for every existing worker).

ALTER TABLE workers ADD COLUMN pause_reason TEXT;
