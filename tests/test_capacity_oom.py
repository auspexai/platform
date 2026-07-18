"""C14 regime capacity honors the observed-OOM ground truth (routing == regime).

`eligible_capable_count` is the fleet's structural ceiling that decides whether a
below-floor regime-3 pause is STRUCTURAL (won't auto-resume). Once it shares the
router's `serve_fits` verdict, a model that demonstrably OOM'd on a worker no longer
counts toward that experiment's capacity — so a repl-2 run whose only serve-capable
worker is the Mac (the Jetsons OOM) reads as structurally 1 < floor 2 and regime-3
pauses it cleanly, instead of the router silently declining to offer it there while the
regime thinks it can still complete.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from auspexai_platform.db.database import Database
from auspexai_platform.db.repositories.model_serve_failures import ModelServeFailureRepository
from auspexai_platform.db.repositories.workers import WorkerRepository
from auspexai_platform.scheduler.capacity import eligible_capable_count


def _exp() -> SimpleNamespace:
    return SimpleNamespace(
        required_capabilities={"models": ["m"], "model_ram_gb": {"m": 3.0}},
        requires_real_execution=False,
        required_containment="permissive",
        replication_target=2,
    )


def _caps(usable: float) -> dict:
    return {
        "os": "linux",
        "execute_tenant_code": "provisioned",
        "auto_acquire": True,
        "usable_memory_gb": usable,
    }


def test_eligible_capable_count_drops_below_floor_on_observed_oom(db: Database) -> None:
    wr = WorkerRepository(db)
    now = datetime.now(UTC)
    fleet = [("wkr-jet1", "a" * 64, 4.44), ("wkr-jet2", "b" * 64, 4.44), ("wkr-mac", "c" * 64, 21.0)]
    for wid, pub, usable in fleet:
        wr.enroll(worker_id=wid, pubkey_hex=pub, capabilities=_caps(usable))
        wr.record_heartbeat(wid, capabilities=_caps(usable))  # recent hb → schedulable

    exp = _exp()
    # No OOM yet: the model's estimate (3.0 GB) fits all three (4.44 >= 3.0 * overhead).
    assert eligible_capable_count(exp, worker_repository=wr, now=now) == 3

    # The model demonstrably OOM'd on a 4.44 GB box → the two Jetsons no longer count; only
    # the Mac (21 > 4.44) does. A repl-2 run now has structural capacity 1 < floor 2, so the
    # settle-sweep's regime-3 sees it as structurally uncompletable and pauses it.
    ModelServeFailureRepository(db).record_oom("m", 4.44, now=now.isoformat())
    assert eligible_capable_count(exp, worker_repository=wr, now=now) == 1
