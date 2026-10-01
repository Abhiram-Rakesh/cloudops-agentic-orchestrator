"""Slack client wrapper. ``steps/``/``handlers/`` business logic
depends only on the ``SlackClient`` protocol below (tests use a fake);
``WebClientSlackAdapter`` is the real ``slack_sdk.WebClient``-backed
implementation, used only by a handler's real ``lambda_handler`` path and
never exercised in tests — tests never make live Slack calls.
"""

from __future__ import annotations

from typing import Any, Protocol


class SlackClient(Protocol):
    def chat_post_message(
        self,
        *,
        channel: str,
        blocks: list[dict[str, Any]],
        text: str,
        thread_ts: str | None = None,
    ) -> tuple[str, str]:
        """Returns ``(channel, ts)`` of the posted message."""
        ...

    def chat_update(self, *, channel: str, ts: str, text: str) -> None: ...

    def post_ephemeral(self, *, channel: str, user: str, text: str) -> None: ...


class WebClientSlackAdapter:
    def __init__(self, token: str) -> None:
        from slack_sdk import WebClient

        self._client = WebClient(token=token)

    def chat_post_message(
        self,
        *,
        channel: str,
        blocks: list[dict[str, Any]],
        text: str,
        thread_ts: str | None = None,
    ) -> tuple[str, str]:
        kwargs: dict[str, Any] = {"channel": channel, "blocks": blocks, "text": text}
        if thread_ts is not None:
            kwargs["thread_ts"] = thread_ts
        response = self._client.chat_postMessage(**kwargs)
        return str(response["channel"]), str(response["ts"])

    def chat_update(self, *, channel: str, ts: str, text: str) -> None:
        self._client.chat_update(channel=channel, ts=ts, text=text)

    def post_ephemeral(self, *, channel: str, user: str, text: str) -> None:
        self._client.chat_postEphemeral(channel=channel, user=user, text=text)


__all__ = ["SlackClient", "WebClientSlackAdapter"]
