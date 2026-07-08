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


def test_buffer_carries_and_serves_detached_signature():
    """AUD-26: the buffer stores the detached raw signature + worker pubkey and
    the signed collector returns them (backward-compatible with the plain map)."""
    from auspexai_platform.raw_transit import RawTransitBuffer

    buf = RawTransitBuffer()
    buf.put(
        experiment_id="exp-1",
        result_id="res-1",
        raw_text="hello",
        raw_signature="sig-b64",
        worker_pubkey="ab" * 32,
        now=1000.0,
    )
    # plain map unchanged
    assert buf.collect_experiment(experiment_id="exp-1", now=1000.0) == {"res-1": "hello"}
    # signed map carries the detached signature + pubkey
    signed = buf.collect_experiment_signed(experiment_id="exp-1", now=1000.0)
    assert signed["res-1"]["raw"] == "hello"
    assert signed["res-1"]["raw_signature"] == "sig-b64"
    assert signed["res-1"]["worker_pubkey"] == "ab" * 32


def test_buffer_put_without_signature_still_works():
    """Legacy/no-sig path: put without a signature is fine (fields are None)."""
    from auspexai_platform.raw_transit import RawTransitBuffer

    buf = RawTransitBuffer()
    buf.put(experiment_id="exp-1", result_id="res-1", raw_text="hi", now=1.0)
    signed = buf.collect_experiment_signed(experiment_id="exp-1", now=1.0)
    assert signed["res-1"] == {"raw": "hi", "raw_signature": None, "worker_pubkey": None}
