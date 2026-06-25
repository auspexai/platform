-- 0048_account_keys: bind a researcher's dashboard/SDK key directly to an
-- account — Tier-1 onboarding ("connect, no tenant", like a worker connecting).
--
-- Until now a key only resolved to a credential if it was a tenant's
-- maintainer_pubkey (researcher) or an enrolled worker's pubkey. A connected
-- researcher with no tenant had no usable credential. This table is the
-- account-key registry the resolver consults AFTER tenants + workers, yielding
-- a CredentialClass.ACCOUNT. The pubkey is the PK (one identity per key); the
-- bind is an upsert (the latest connect wins, so re-connecting — even with a
-- different IdP — rebinds the key to the now-current account).

CREATE TABLE account_keys (
    pubkey_hex  TEXT    PRIMARY KEY,                 -- lowercase, 64 hex (32-byte Ed25519)
    account_id  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,                     -- ISO 8601 UTC
    FOREIGN KEY (account_id) REFERENCES accounts(account_id)
);

CREATE INDEX account_keys_account_idx ON account_keys(account_id);
