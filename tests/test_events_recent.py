"""UI fix C: the replay ring rehydrates heartbeat views — tenant privacy and
maintainer scope mirror the SSE twins."""

from __future__ import annotations

from auspexai_platform.events.bus import EventBus


def test_ring_orders_filters_and_bounds():
    bus = EventBus()
    for i in range(10):
        bus.publish("unit_completed", experiment_id="exp-a" if i % 2 else "exp-b", data={"i": i})
    assert len(bus.recent()) == 10
    a = bus.recent(experiment_id="exp-a")
    assert [e.data["i"] for e in a] == [1, 3, 5, 7, 9]  # oldest→newest
    assert all(e.at for e in a)
    assert len(bus.recent(limit=3)) == 3
