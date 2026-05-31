-- 0014_account_suspension_reason.sql — store the maintainer's reason for an
-- account-level suspension so it can be surfaced to the account holder.
--
-- Ratified 2026-05-30: account suspension decisions (and their reasoning) are
-- exposed to the account holder, mirroring the per-worker quarantine_reason
-- decision (0009 + the 2026-05-30 worker-status-reason ratification). A
-- researcher is entitled to know that — and why — their account was suspended
-- (trust-boundary transparency). The reason is account-scoped: visible to the
-- account itself and the maintainer, never to third parties.
--
-- Parallels accounts.suspended_at (0010 §6.2.3). suspension_reason is set when
-- suspend() is called and cleared on unsuspend(), exactly like the worker
-- quarantine_reason column.

ALTER TABLE accounts ADD COLUMN suspension_reason TEXT;
