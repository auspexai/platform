-- 0033_account_tier_set_by_class.sql — firewall #2 (F4): record WHO set an
-- account's current trust tier — `system` (auto-promotion on receipt issuance)
-- vs `maintainer` (manual console promote/demote) — so the governance footprint
-- can state the promotion path auto-vs-human ON the evidence, completing the
-- firewall-#4 auto-vs-human record across both governance gates. Mirrors
-- `experiments.last_action_by_class`. NULL = birth tier (T1 at creation), never
-- set by an explicit tier action.
ALTER TABLE accounts ADD COLUMN tier_set_by_class TEXT;
