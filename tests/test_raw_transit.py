"""D20 raw-content live collection: the ephemeral transit buffer + the §7 gate
(raw_response permitted ONLY when capture is declared; never persisted)."""

from __future__ import annotations

from auspexai_platform.raw_transit import RawTransitBuffer


def test_buffer_scoping_ttl_and_bound():
    buf = RawTransitBuffer(max_items=3, ttl_seconds=100)
    buf.put(experiment_id="e1", result_id="r1", raw_text="alpha", now=1000.0)
    buf.put(experiment_id="e1", result_id="r2", raw_text="beta", now=1000.0)
    buf.put(experiment_id="e2", result_id="r3", raw_text="gamma", now=1000.0)
    # experiment-scoped collection
    assert buf.collect_experiment(experiment_id="e1", now=1001.0) == {"r1": "alpha", "r2": "beta"}
    # cross-experiment isolation on point-get
    assert buf.get(experiment_id="e2", result_id="r1", now=1001.0) is None
    assert buf.get(experiment_id="e1", result_id="r1", now=1001.0) == "alpha"
    # TTL eviction
    assert buf.get(experiment_id="e1", result_id="r1", now=2000.0) is None
    # count bound (oldest evicted)
    for i in range(5):
        buf.put(experiment_id="e3", result_id=f"x{i}", raw_text="z", now=3000.0)
    assert len(buf.collect_experiment(experiment_id="e3", now=3000.0)) == 3
