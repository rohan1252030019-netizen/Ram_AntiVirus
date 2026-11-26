"""Bounds on per-connection WebSocket topic subscriptions."""

from __future__ import annotations

from app.core.ws_push import MAX_TOPIC_LENGTH, MAX_TOPICS_PER_CLIENT, WSClient


class _FakeWS:
    """Minimal stand-in; WSClient only keeps a reference to the socket."""


def _client() -> WSClient:
    return WSClient(_FakeWS(), client_id="test-client")  # type: ignore[arg-type]


def test_topic_subscription_is_bounded():
    from app.core.ws_push import ws_push_manager

    client = _client()
    ws_push_manager.subscribe_topics(client, [f"topic-{i}" for i in range(500)])

    assert len(client.topics) == MAX_TOPICS_PER_CLIENT


def test_overlong_and_non_string_topics_are_dropped():
    from app.core.ws_push import ws_push_manager

    client = _client()
    ws_push_manager.subscribe_topics(
        client,
        ["ok.topic", "x" * (MAX_TOPIC_LENGTH + 1), "", "   ", 42, None],
    )

    assert client.topics == {"ok.topic"}


def test_non_list_payload_is_ignored():
    from app.core.ws_push import ws_push_manager

    client = _client()
    ws_push_manager.subscribe_topics(client, "incidents.new")  # type: ignore[arg-type]

    assert client.topics == set()


def test_unsubscribe_still_works():
    from app.core.ws_push import ws_push_manager

    client = _client()
    ws_push_manager.subscribe_topics(client, ["incidents.new", "actions.new"])
    ws_push_manager.unsubscribe_topics(client, ["incidents.new"])

    assert client.topics == {"actions.new"}
