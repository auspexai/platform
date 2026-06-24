-- 0045_account_orcid: a linked ORCID iD on the account (D8).
--
-- ORCID is supported as a *linked* identity (the account stays GitHub-rooted;
-- accounts.idp / its CHECK are untouched). Linking stores the ORCID iD here and
-- marks the account identity-verified (method=ORCID) via the existing
-- identity_verified_* columns. The R2->R3 vetting gate reads identity_verified_at;
-- the iD is surfaced to the reviewer.

ALTER TABLE accounts ADD COLUMN orcid_id TEXT;
