"""In-process async pub/sub event bus for live coordinator events (M8).

The dashboard and operator console poll today; this bus is the push side that
SSE endpoints (`api/events.py`) stream to them. Route handlers `publish()` an
event when something observable happens (a lifecycle transition, a work unit
completing, a receipt issuing); each connected SSE client holds a `subscribe()`
queue that the publish fans the event into.

Design constraints:
  - **Best-effort, never blocks a request.** `publish()` is synchronous and
    non-blocking — it `put_nowait`s into each subscriber queue and, if a slow
    consumer's bounded queue is full, drops that consumer's *oldest* event
    rather than blocking the publisher or growing memory without bound. SSE is
    a live convenience view; the durable record is the audit log + receipts.
  - **Process-local.** Subscribers and publishers share one asyncio loop (the
    single-process coordinator). A multi-process deploy would need a shared
    broker (Redis pub/sub, etc.) — explicitly out of scope for Phase 1/2.
  - **Two channel kinds:** each event is fanned to its experiment's channel
    (`experiment_id`) *and* to the global firehose (`GLOBAL`, the operator
    "watch everything" stream). An event with no `experiment_id` goes only to
    the firehose.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterator
from dataclasses import dataclass

# Channel key for the operator firehose — every event is also published here.
GLOBAL = "*"

# Per-subscriber queue depth. A subscriber that falls this far behind starts
# dropping its oldest events (see `_offer`). 256 is generous for a live UI feed.
DEFAULT_MAX_QUEUE = 256


@dataclass(frozen=True, slots=True)
class Event:
    """One published event. `seq` is a per-bus monotonic id so a client can
    detect gaps (e.g. after a drop); `data` is the JSON-serializable body."""

    seq: int
    type: str
    experiment_id: str | None
    data: dict


def _offer(queue: asyncio.Queue, event: Event) -> None:
    """Non-blocking enqueue with drop-oldest backpressure. Never raises."""
    try:
        queue.put_nowait(event)
    except asyncio.QueueFull:
        # Slow consumer: discard its oldest event to make room for the newest,
        # so a stalled client can't pin unbounded memory or wedge the publisher.
        with contextlib.suppress(asyncio.QueueEmpty):
            queue.get_nowait()
        with contextlib.suppress(asyncio.QueueFull):
            queue.put_nowait(event)


class EventBus:
    """Process-local async pub/sub. See module docstring."""

    def __init__(self, *, max_queue: int = DEFAULT_MAX_QUEUE) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = {}
        self._max_queue = max_queue
        self._seq = 0

    def publish(self, event_type: str, *, experiment_id: str | None, data: dict) -> Event:
        """Fan an event to its experiment channel and the global firehose.

        Synchronous and non-blocking — safe to call from inside an async route
        handler without `await`. Returns the constructed `Event` (handy for
        tests / callers that want the assigned `seq`).
        """
        self._seq += 1
        event = Event(seq=self._seq, type=event_type, experiment_id=experiment_id, data=data)
        channels = [GLOBAL] if experiment_id is None else [experiment_id, GLOBAL]
        for channel in channels:
            for queue in self._subscribers.get(channel, ()):
                _offer(queue, event)
        return event

    @contextlib.contextmanager
    def subscribe(self, channel: str) -> Iterator[asyncio.Queue]:
        """Subscribe to a channel for the duration of the context. Yields a
        bounded queue that receives matching events. The subscription is torn
        down (and the empty channel pruned) on exit — including when the SSE
        client disconnects and the generator is cancelled."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue)
        self._subscribers.setdefault(channel, set()).add(queue)
        try:
            yield queue
        finally:
            subs = self._subscribers.get(channel)
            if subs is not None:
                subs.discard(queue)
                if not subs:
                    del self._subscribers[channel]

    def subscriber_count(self, channel: str) -> int:
        """Live subscriber count for a channel (test/introspection helper)."""
        return len(self._subscribers.get(channel, ()))
