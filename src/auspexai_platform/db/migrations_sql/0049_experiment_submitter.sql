-- 0049_experiment_submitter: record WHICH account submitted an experiment.
--
-- A connected researcher (Tier-1, CredentialClass.ACCOUNT) runs a public
-- tenant's certified starter UNDER that tenant — so the experiment's tenant_id
-- is the public tenant, not the runner. `submitted_by_account_id` is the
-- runner's account, so they can list + view their OWN runs (and citation
-- attributes to them) without being the tenant. For a tenant-owner submission
-- it is the tenant's own account_id. NULL for pre-0049 rows.

ALTER TABLE experiments ADD COLUMN submitted_by_account_id TEXT;
CREATE INDEX experiments_submitter_idx ON experiments(submitted_by_account_id);
