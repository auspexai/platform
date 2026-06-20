-- 0039_receipt_attribution_at_issue.sql — System B: non-retroactive citation consent.
--
-- The contributor citation must reflect the consent a contribution was MADE UNDER,
-- not the volunteer's CURRENT opt-in flag — else opting in later retroactively
-- credits PAST runs they contributed to anonymously (USER-flagged 2026-06-19, having
-- seen opting in name them on exp-TiCpw7K0). So we snapshot the account's
-- `public_attribution` AT RECEIPT ISSUANCE onto each receipt.
--
-- DEFAULT 0 on existing rows is CORRECT: those receipts predate any opt-in, so the
-- contributions stay anonymous (exactly the desired non-retroactive behavior). The
-- citation credits an account only if (at_issue = 1 AND the account is opted-in NOW):
-- the snapshot blocks retroactive opt-IN (forward), the current flag preserves
-- reversible opt-OUT (the ratified "reversible while live, frozen at DOI").
-- See citation_consent_snapshot.md.

ALTER TABLE receipt_index ADD COLUMN public_attribution_at_issue INTEGER NOT NULL DEFAULT 0;
