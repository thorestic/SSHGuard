import asyncio
import json
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from time import monotonic
from typing import Any, Protocol

from .repository import DatabaseUnavailable, SecurityReadRepository


class DisconnectAwareRequest(Protocol):
    async def is_disconnected(self) -> bool: ...


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def encode_sse_event(
    event: str,
    data: dict[str, Any],
    *,
    event_id: str | None = None,
    retry_milliseconds: int | None = None,
) -> str:
    """Encode one standards-compliant Server-Sent Event frame."""

    lines: list[str] = []

    if event_id is not None:
        lines.append(f"id: {event_id}")

    lines.append(f"event: {event}")

    if retry_milliseconds is not None:
        lines.append(f"retry: {retry_milliseconds}")

    lines.append(
        "data: "
        + json.dumps(
            data,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return "\n".join(lines) + "\n\n"


async def security_event_stream(
    request: DisconnectAwareRequest,
    repository: SecurityReadRepository,
    *,
    poll_seconds: float = 1.0,
    heartbeat_seconds: float = 15.0,
) -> AsyncIterator[str]:
    """Notify clients when the SSHGuard database changes.

    The stream carries invalidation signals, not security records. Clients
    fetch the latest typed snapshot from the versioned REST endpoints.
    """

    retry_seconds = max(poll_seconds, 1.0)
    retry_milliseconds = max(1000, round(retry_seconds * 1000))

    while not await request.is_disconnected():
        try:
            with repository.change_monitor() as monitor:
                yield encode_sse_event(
                    "ready",
                    {
                        "connected_at": _utc_now(),
                        "poll_seconds": poll_seconds,
                    },
                    retry_milliseconds=retry_milliseconds,
                )
                last_heartbeat = monotonic()

                while not await request.is_disconnected():
                    await asyncio.sleep(poll_seconds)

                    if await request.is_disconnected():
                        return

                    if monitor.poll():
                        changed_at = _utc_now()
                        yield encode_sse_event(
                            "security_update",
                            {"changed_at": changed_at},
                            event_id=changed_at,
                        )

                    current_time = monotonic()
                    if current_time - last_heartbeat >= heartbeat_seconds:
                        yield f": keep-alive {_utc_now()}\n\n"
                        last_heartbeat = current_time

        except DatabaseUnavailable:
            if await request.is_disconnected():
                return

            yield encode_sse_event(
                "unavailable",
                {
                    "observed_at": _utc_now(),
                    "retry_seconds": retry_seconds,
                },
                retry_milliseconds=retry_milliseconds,
            )
            await asyncio.sleep(retry_seconds)
