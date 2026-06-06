"""SSE live streams (M8) — frame format, the stream generator, the HTTP
endpoints' auth/connect behavior, and that route handlers actually publish.

The streaming generator is driven directly (same event loop) to avoid the
TestClient portal's cross-thread queue hazard; the HTTP tests only inspect the
response head (status + content-type) or short error bodies, never the infinite
stream body. Emit-wiring is checked through the real HTTP action path: a
synchronous `client.post` fully runs the handler (incl. the synchronous
`publish`) before returning, so the subscriber queue can be drained with
`get_nowait` deterministically."""

from __future__ import annotations

import asyncio
import json

from auspexai_platform.api.events import _sse_frame, _stream
from auspexai_platform.auth.signature import sign_request
from auspexai_platform.events import GLOBAL, Event, EventBus

AUTHORITY = "testserver"


class _FakeRequest:
    def __init__(self, disconnected: bool = False) -> None:
        self._disconnected = disconnected

    async def is_disconnected(self) -> bool:
        return self._disconnected


# ---- frame format ----------------------------------------------------------


def test_sse_frame_format():
    frame = _sse_frame(
        Event(seq=7, type="unit.progress", experiment_id="exp-1", data={"completions_so_far": 2})
    )
    assert "id: 7\n" in frame
    assert "event: unit.progress\n" in frame
    assert frame.endswith("\n\n")
    data_line = next(line for line in frame.splitlines() if line.startswith("data: "))
    payload = json.loads(data_line[len("data: ") :])
    # experiment_id is folded into the payload so a firehose client can route.
    assert payload == {"experiment_id": "exp-1", "completions_so_far": 2}


# ---- stream generator (driven directly, same loop) -------------------------


async def test_stream_emits_connected_then_delivers_event():
    bus = EventBus()
    agen = _stream(bus, "exp-1", _FakeRequest(), ping_interval=5.0)
    first = await agen.__anext__()
    assert first.startswith(": connected")
    bus.publish("unit.progress", experiment_id="exp-1", data={"n": 1})
    frame = await asyncio.wait_for(agen.__anext__(), 1)
    assert "event: unit.progress" in frame
    await agen.aclose()


async def test_stream_pings_on_idle():
    bus = EventBus()
    agen = _stream(bus, GLOBAL, _FakeRequest(), ping_interval=0.01)
    await agen.__anext__()  # ": connected"
    ping = await asyncio.wait_for(agen.__anext__(), 1)
    assert ping.startswith(": ping")
    await agen.aclose()


async def test_stream_stops_when_client_disconnected():
    bus = EventBus()
    agen = _stream(bus, GLOBAL, _FakeRequest(disconnected=True), ping_interval=5.0)
    assert (await agen.__anext__()).startswith(": connected")
    # is_disconnected() → True on the next loop iteration → generator ends.
    closed = False
    try:
        await asyncio.wait_for(agen.__anext__(), 1)
    except StopAsyncIteration:
        closed = True
    assert closed


async def test_stream_unsubscribes_on_close():
    bus = EventBus()
    agen = _stream(bus, "exp-9", _FakeRequest(), ping_interval=5.0)
    await agen.__anext__()
    assert bus.subscriber_count("exp-9") == 1
    await agen.aclose()
    assert bus.subscriber_count("exp-9") == 0


# ---- HTTP endpoint auth + connect ------------------------------------------


def _sign(privkey, pubkey_hex, path):
    return sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority=AUTHORITY,
        body=b"",
    )


# NOTE: the happy-path 200 + text/event-stream connect is intentionally NOT
# tested over TestClient — exiting an unconsumed infinite SSE body parks the
# server generator in its keepalive `wait_for` and the portal teardown blocks.
# The streaming behavior (connect frame, delivery, ping, disconnect, unsubscribe)
# is fully covered same-loop by the `_stream` generator tests above; the negative
# HTTP tests below prove the routes are wired (the handler is reached and gates).


def test_non_owner_experiment_stream_404(client, approved_experiment, tenant_registry):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _p, _b, experiment, _h = approved_experiment
    other = Ed25519PrivateKey.generate()
    other_pub = other.public_key().public_bytes_raw().hex()
    tenant_registry.register(tenant_id="other-tenant", pubkey_hex=other_pub)
    path = f"/api/v0/experiments/{experiment.experiment_id}/events"
    resp = client.get(path, headers=_sign(other, other_pub, path))
    assert resp.status_code == 404


def test_anonymous_experiment_stream_404(client, approved_experiment):
    _p, _b, experiment, _h = approved_experiment
    resp = client.get(f"/api/v0/experiments/{experiment.experiment_id}/events")
    assert resp.status_code == 404


def test_non_maintainer_firehose_forbidden(client, approved_experiment):
    privkey, binding, _experiment, _h = approved_experiment
    resp = client.get(
        "/api/v0/events", headers=_sign(privkey, binding.pubkey_hex, "/api/v0/events")
    )
    assert resp.status_code in (401, 403)


# ---- emit wiring (real HTTP action path) -----------------------------------


def test_lifecycle_action_publishes_status_event(client, approved_experiment, maintainer_token):
    """A pause through the real route publishes `experiment.status`. Proves the
    bus is wired create_app → experiments router → _transition → publish."""
    bus = client.app.state.event_bus
    _p, _b, experiment, _h = approved_experiment
    eid = experiment.experiment_id
    with bus.subscribe(GLOBAL) as q:
        r = client.post(
            f"/api/v0/experiments/{eid}/actions/pause",
            headers={"Authorization": f"Bearer {maintainer_token}"},
        )
        assert r.status_code == 200, r.text
        ev = q.get_nowait()  # publish completed during the synchronous POST
    assert ev.type == "experiment.status"
    assert ev.experiment_id == eid
    assert ev.data["status"] == "paused"
    assert ev.data["from_status"] == "approved"
