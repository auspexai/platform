"""EventBus — in-process pub/sub fanout, channel scoping, drop-oldest (M8)."""

from __future__ import annotations

import asyncio

from auspexai_platform.events import GLOBAL, EventBus


async def test_publish_fans_to_experiment_and_global():
    bus = EventBus()
    with bus.subscribe("exp-1") as exp_q, bus.subscribe(GLOBAL) as glob_q:
        ev = bus.publish("unit.progress", experiment_id="exp-1", data={"n": 1})
        got_exp = await asyncio.wait_for(exp_q.get(), 1)
        got_glob = await asyncio.wait_for(glob_q.get(), 1)
    assert got_exp is ev and got_glob is ev
    assert ev.seq == 1
    assert ev.type == "unit.progress"


async def test_experiment_channel_isolation():
    bus = EventBus()
    with bus.subscribe("exp-1") as q1, bus.subscribe("exp-2") as q2:
        bus.publish("x", experiment_id="exp-1", data={})
        got = await asyncio.wait_for(q1.get(), 1)
        assert got.experiment_id == "exp-1"
        assert q2.empty()  # the other experiment's subscriber sees nothing


async def test_global_only_event_skips_experiment_channels():
    bus = EventBus()
    with bus.subscribe("exp-1") as q1, bus.subscribe(GLOBAL) as gq:
        bus.publish("system.note", experiment_id=None, data={})
        got = await asyncio.wait_for(gq.get(), 1)
        assert got.experiment_id is None
        assert q1.empty()


async def test_seq_is_monotonic_across_channels():
    bus = EventBus()
    with bus.subscribe(GLOBAL):
        a = bus.publish("a", experiment_id=None, data={})
        b = bus.publish("b", experiment_id="exp-1", data={})
    assert (a.seq, b.seq) == (1, 2)


async def test_unsubscribe_on_context_exit_prunes_channel():
    bus = EventBus()
    with bus.subscribe("exp-1"):
        assert bus.subscriber_count("exp-1") == 1
    assert bus.subscriber_count("exp-1") == 0


async def test_drop_oldest_when_queue_full():
    bus = EventBus(max_queue=2)
    with bus.subscribe(GLOBAL) as q:
        bus.publish("e", experiment_id=None, data={"i": 0})
        bus.publish("e", experiment_id=None, data={"i": 1})
        bus.publish("e", experiment_id=None, data={"i": 2})  # overflow → drop i=0
        first = await asyncio.wait_for(q.get(), 1)
        second = await asyncio.wait_for(q.get(), 1)
    assert [first.data["i"], second.data["i"]] == [1, 2]
    assert q.empty()


async def test_publish_with_no_subscribers_is_noop_but_assigns_seq():
    bus = EventBus()
    ev = bus.publish("e", experiment_id="exp-x", data={})
    assert ev.seq == 1  # nobody to deliver to, but seq still advances
