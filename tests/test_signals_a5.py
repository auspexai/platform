"""A5 firewall #5 — self-observation signals (the control-DB substrate).

Each signal is computed deterministically from recorded data (audit_log, workers,
accounts, vouches), reward-independent + externally verifiable, no writes, no
enforcement (a5_instrumentation_design.md). Several are honestly empty at
single-maintainer scale and grow with the pool.
"""

from __future__ import annotations

import json

from auspexai_platform.db.database import Database
from auspexai_platform.db.models import IdentityProvider
from auspexai_platform.db.repositories import AccountRepository, WorkerRepository
from auspexai_platform.signals import (
    autonomy_signal,
    compute_self_observation,
    fleet_diversity_signal,
    trust_flow_signal,
    vouch_topology_signal,
)

_TS = "2026-06-17T00:00:00+00:00"


def _audit(db, action, actor_class):
    db.execute(
        "INSERT INTO audit_log (occurred_at, actor_class, action) VALUES (?, ?, ?)",
        (_TS, actor_class, action),
    )


def test_autonomy_signal_counts_auto_vs_manual(db: Database):
    for _ in range(3):
        _audit(db, "account.auto_promote", "system")
    _audit(db, "account.promote", "maintainer")
    sig = autonomy_signal(db)
    assert sig["account_promotions_auto"] == 3
    assert sig["account_promotions_manual"] == 1
    assert sig["autonomy_ratio"] == 0.75
    assert "promotion_gate_mode" in sig  # default manual on a fresh policy


def test_autonomy_signal_empty_is_zero(db: Database):
    sig = autonomy_signal(db)
    assert sig["account_promotions_auto"] == 0
    assert sig["autonomy_ratio"] == 0.0


def test_fleet_diversity_counts_distinct_capability_values(db: Database):
    workers = WorkerRepository(db)
    caps = [
        {"os": "linux", "arch": "x86_64", "sandbox_policy": "strict"},
        {"os": "linux", "arch": "arm64", "sandbox_policy": "strict"},
        {"os": "linux", "arch": "x86_64"},  # sandbox_policy omitted
    ]
    for i, c in enumerate(caps):
        workers.enroll(worker_id=f"wkr-{i}", pubkey_hex=f"{i:02x}" * 32)
        db.execute(
            "UPDATE workers SET capabilities_json = ? WHERE worker_id = ?",
            (json.dumps(c), f"wkr-{i}"),
        )
    sig = fleet_diversity_signal(db)
    assert sig["active_workers"] == 3
    assert sig["distinct_os"] == 1
    assert sig["distinct_arch"] == 2
    assert sig["distinct_sandbox_policy"] == 1  # only "strict" declared, twice


def test_trust_flow_histogram_and_trusted_share(db: Database):
    accounts = AccountRepository(db)
    for i in range(3):
        accounts.create(account_id=f"acct-{i}", idp=IdentityProvider.GITHUB, idp_sub=str(100 + i))
    db.execute("UPDATE accounts SET trust_tier = 2 WHERE account_id = ?", ("acct-2",))
    sig = trust_flow_signal(db)
    assert sig["active_accounts"] == 3
    assert sig["tier_histogram"]["1"] == 2
    assert sig["tier_histogram"]["2"] == 1
    assert sig["trusted_share"] == 1 / 3


def test_vouch_topology_flags_mutual_and_self(db: Database):
    accounts = AccountRepository(db)
    for name, sub in (("a", "1"), ("b", "2"), ("c", "3")):
        accounts.create(account_id=name, idp=IdentityProvider.GITHUB, idp_sub=sub)

    def vouch(vid, voucher, target):
        db.execute(
            "INSERT INTO vouches (vouch_id, voucher_account_id, target_account_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (vid, voucher, target, _TS),
        )

    vouch("v1", "a", "b")
    vouch("v2", "b", "a")  # reciprocal with a→b → one mutual pair
    vouch("v3", "c", "c")  # self-vouch (API forbids it; the signal flags it if seen)
    sig = vouch_topology_signal(db)
    assert sig["active_vouches"] == 3
    assert sig["mutual_pairs"] == 1
    assert sig["self_vouches"] == 1
    assert sig["distinct_vouchers"] == 3


def test_compute_self_observation_assembles_all_and_is_empty_safe(db: Database):
    obs = compute_self_observation(db)
    assert set(obs) == {"autonomy", "fleet_diversity", "trust_flow", "vouch_topology"}
    # Honest empties at single-maintainer scale — no crash, no fabricated signal.
    assert obs["autonomy"]["autonomy_ratio"] == 0.0
    assert obs["fleet_diversity"]["active_workers"] == 0
    assert obs["trust_flow"]["active_accounts"] == 0
    assert obs["vouch_topology"]["active_vouches"] == 0
