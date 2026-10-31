# Sentinel — © 2026 Abdullah Samir. All rights reserved.
"""A minimal synchronous event bus.

The orchestrator and (later) the display/dashboard use this to react to run
progress without modules importing one another. Subscribers are called inline;
a misbehaving subscriber is logged and never breaks the publisher.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Callable, DefaultDict, List

log = logging.getLogger("sentinel.events")

Handler = Callable[[str, Any], None]


class EventBus:
    def __init__(self) -> None:
        self._subs: DefaultDict[str, List[Handler]] = defaultdict(list)

    def subscribe(self, topic: str, handler: Handler) -> None:
        self._subs[topic].append(handler)

    def publish(self, topic: str, payload: Any = None) -> None:
        for handler in list(self._subs.get(topic, ())):
            try:
                handler(topic, payload)
            except Exception as e:  # noqa: BLE001 — a bad subscriber is non-fatal
                log.warning("event handler for %s failed: %s", topic, e)
