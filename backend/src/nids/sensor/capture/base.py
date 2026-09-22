"""The interface every capture backend implements."""

import threading
from collections.abc import Callable
from typing import Protocol

from nids.core.schemas.flow import FlowRecord

FlowSink = Callable[[FlowRecord], None]


class CaptureError(RuntimeError):
    """Capture couldn't start or died. The message says what to fix."""


class FlowSource(Protocol):
    name: str

    def run(self, emit: FlowSink, stop: threading.Event) -> None:
        """Capture until `stop` is set or the input ends, calling `emit` for every finished flow.

        Must flush open flows before returning. Raises CaptureError on failure.
        """
        ...

    def metrics(self) -> dict[str, int | float]:
        """Counters for the health view (packets, drops, flows...)."""
        ...
