"""In-process asynchronous event bus for mcp-behave runtime monitor.

Provides decoupled publish-subscribe event routing for protocol monitors, OS tracers,
policy engines, and telemetry sinks. Supports namespaced subscription by `server_id`
to enable multi-server multiplexing in future gateway architectures (M7).
"""
from __future__ import annotations

import asyncio
import inspect
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from .events import BehavioralEvent


SubscriberCallback = Callable[[BehavioralEvent], Optional[Coroutine[Any, Any, None]]]


class EventBus:
    """Asynchronous in-memory event bus with server_id and event kind filtering."""

    def __init__(self):
        self._subscribers: List[Dict[str, Any]] = []
        self._closed = False

    def subscribe(
        self,
        callback: SubscriberCallback,
        server_id: Optional[str] = None,
        kinds: Optional[Set[str]] = None,
    ) -> Callable[[], None]:
        """Subscribe a callback to published events.

        Args:
            callback: Sync or async callable taking a BehavioralEvent.
            server_id: If specified, only events matching this server_id are routed.
            kinds: If specified, only events matching one of these kinds are routed.

        Returns:
            An unsubscribe function.
        """
        sub_record = {
            "callback": callback,
            "server_id": server_id,
            "kinds": kinds,
            "is_async": inspect.iscoroutinefunction(callback),
        }
        self._subscribers.append(sub_record)

        def unsubscribe():
            if sub_record in self._subscribers:
                self._subscribers.remove(sub_record)

        return unsubscribe

    def publish_sync(self, event: BehavioralEvent) -> None:
        """Publish an event synchronously to all non-async subscribers."""
        if self._closed:
            return

        for sub in list(self._subscribers):
            if sub["server_id"] is not None and event.server_id != sub["server_id"]:
                continue
            if sub["kinds"] is not None and event.kind not in sub["kinds"]:
                continue
            try:
                if not sub["is_async"]:
                    sub["callback"](event)
            except Exception:
                pass

    async def publish(self, event: BehavioralEvent) -> None:
        """Publish an event to all matching subscribers."""
        if self._closed:
            return

        for sub in list(self._subscribers):
            # Check server_id filter
            if sub["server_id"] is not None and event.server_id != sub["server_id"]:
                continue

            # Check kind filter
            if sub["kinds"] is not None and event.kind not in sub["kinds"]:
                continue

            try:
                if sub["is_async"]:
                    await sub["callback"](event)
                else:
                    sub["callback"](event)
            except Exception:
                # EventBus subscribers should never throw back into the publisher
                pass

    def close(self) -> None:
        """Close the event bus and clear all subscriptions."""
        self._closed = True
        self._subscribers.clear()
