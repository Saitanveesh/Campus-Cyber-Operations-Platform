from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass

from .models import Event


@dataclass(slots=True)
class Subscription:
    name: str
    queue: asyncio.Queue[Event]
    predicate: Callable[[Event], bool] | None = None
    dropped: int = 0


class EventBus:
    """Bounded fan-out bus with explicit per-subscriber drop accounting."""

    def __init__(self, queue_size: int = 2048) -> None:
        self._queue_size = queue_size
        self._subs: dict[str, Subscription] = {}
        self._lock = asyncio.Lock()

    async def subscribe(
        self,
        name: str,
        predicate: Callable[[Event], bool] | None = None,
    ) -> Subscription:
        async with self._lock:
            sub = Subscription(
                name=name,
                queue=asyncio.Queue(self._queue_size),
                predicate=predicate,
            )
            self._subs[name] = sub
            return sub

    async def unsubscribe(self, name: str) -> None:
        async with self._lock:
            self._subs.pop(name, None)

    async def publish(self, event: Event) -> None:
        async with self._lock:
            subscribers = tuple(self._subs.values())
        for sub in subscribers:
            if sub.predicate is not None and not sub.predicate(event):
                continue
            if sub.queue.full():
                try:
                    sub.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                else:
                    sub.dropped += 1
            sub.queue.put_nowait(event)

    def stats(self) -> dict[str, dict[str, int]]:
        return {
            name: {
                "queued": sub.queue.qsize(),
                "dropped": sub.dropped,
                "capacity": self._queue_size,
            }
            for name, sub in self._subs.items()
        }
