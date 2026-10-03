"""Tiny in-process event bus: non-blocking publish, background writer thread."""
from __future__ import annotations

import logging
import queue
import threading
from typing import Callable

from .schemas import SecurityEvent

log = logging.getLogger("observability.bus")
Handler = Callable[[SecurityEvent], None]


class EventBus:
    """`publish` never blocks the proxy: if the queue is full the event is dropped and counted."""

    def __init__(self, *, async_mode: bool = True, max_queue: int = 10_000) -> None:
        self._handlers: list[Handler] = []
        self._async = async_mode
        self._q: "queue.Queue[SecurityEvent | None]" = queue.Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.dropped = 0

    def subscribe(self, handler: Handler) -> None:
        self._handlers.append(handler)

    def publish(self, event: SecurityEvent) -> None:
        if not self._async:
            self._dispatch(event)
            return
        self._ensure_worker()
        try:
            self._q.put_nowait(event)
        except queue.Full:
            self.dropped += 1
            log.warning("observability queue full; event dropped")

    def flush(self, timeout: float = 5.0) -> None:
        """Block until queued events are written (used by tests/shutdown)."""
        if not self._async:
            return
        done = threading.Event()
        threading.Thread(target=lambda: (self._q.join(), done.set()), daemon=True).start()
        done.wait(timeout)

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="obs-writer", daemon=True)
                self._thread.start()

    def _run(self) -> None:
        while True:
            ev = self._q.get()
            try:
                if ev is not None:
                    self._dispatch(ev)
            finally:
                self._q.task_done()

    def _dispatch(self, event: SecurityEvent) -> None:
        for h in self._handlers:
            try:
                h(event)
            except Exception:  # observability must never break the proxy
                log.exception("observability handler failed")
