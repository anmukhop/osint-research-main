"""
MCP Runtime: per-worker singleton MCP client.

Owns a single OSINTMCPClient per Gunicorn worker process, running on a
background asyncio event loop in a daemon thread. Connections to external
MCP servers (WhoisXML, Shodan, BuiltWith) are opened once at worker startup
and reused for the worker's lifetime.

Why: the previous design built a fresh OSINTMCPClient per request, which
meant spawning subprocesses (npx, python) and opening HTTP connections on
every search. With Gunicorn's 2 sync workers, 3 concurrent users would
stall as connection setup serialized.

Usage from sync Django views:

    from researcher.services.mcp_runtime import get_runtime

    runtime = get_runtime()
    result = runtime.process_query_sync(
        user_query="who owns google.com",
        progress_callback=my_callback,  # optional
    )
"""

import asyncio
import logging
import threading
from concurrent.futures import Future
from typing import Callable, Optional

from .mcp_client import (
    OSINTMCPClient,
    QueryResult,
    ProgressUpdate,
    get_default_servers,
)

logger = logging.getLogger(__name__)


class MCPRuntime:
    """Per-process singleton wrapping a long-lived OSINTMCPClient."""

    def __init__(self):
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None
        self._client: Optional[OSINTMCPClient] = None
        self._ready = threading.Event()
        self._startup_error: Optional[str] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the background loop and connect the MCP client.

        Idempotent — safe to call multiple times. Returns immediately;
        connection happens asynchronously. Use wait_ready() to block.
        """
        with self._lock:
            if self._loop_thread is not None:
                return

            self._loop_thread = threading.Thread(
                target=self._run_loop,
                name="mcp-runtime-loop",
                daemon=True,
            )
            self._loop_thread.start()

    def _run_loop(self) -> None:
        """Background thread entrypoint: own the event loop forever."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            self._loop.run_until_complete(self._connect_client())
            self._ready.set()
            self._loop.run_forever()
        except Exception as e:
            logger.exception("MCP runtime loop crashed")
            self._startup_error = str(e)
            self._ready.set()
        finally:
            try:
                if self._client is not None:
                    self._loop.run_until_complete(self._client.disconnect())
            except Exception:
                logger.exception("Error during MCP client disconnect")
            self._loop.close()

    async def _connect_client(self) -> None:
        """Build the OSINTMCPClient and connect to all configured servers."""
        servers = get_default_servers()
        logger.info(
            "MCP runtime: connecting to %d configured servers: %s",
            len(servers),
            [s.name for s in servers],
        )

        self._client = OSINTMCPClient(servers=servers)
        connected = await self._client.connect()

        if not connected:
            raise RuntimeError("MCP runtime: failed to connect to any servers")

        logger.info("MCP runtime: connected and ready")

    def wait_ready(self, timeout: float = 60.0) -> bool:
        """Block until the runtime is ready or timeout expires.

        Returns True if ready, False on timeout. If startup failed,
        returns True but self._startup_error will be set.
        """
        return self._ready.wait(timeout=timeout)

    @property
    def is_ready(self) -> bool:
        return self._ready.is_set() and self._startup_error is None

    @property
    def startup_error(self) -> Optional[str]:
        return self._startup_error

    def submit(self, coro) -> Future:
        """Submit a coroutine to the background loop. Returns a Future."""
        if self._loop is None or not self._loop.is_running():
            raise RuntimeError("MCP runtime not started")
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    def process_query_sync(
        self,
        user_query: str,
        progress_callback: Optional[Callable[[ProgressUpdate], None]] = None,
        timeout: float = 300.0,
        history: Optional[list[dict]] = None,
    ) -> QueryResult:
        """Run a query through the shared client and block for the result.

        Safe to call from sync Django views. Concurrent calls share the
        same loop and the same MCP connections.
        """
        if not self.wait_ready(timeout=60.0):
            return QueryResult(
                success=False,
                error="MCP runtime not ready (timed out waiting for startup)",
            )

        if self._startup_error:
            return QueryResult(
                success=False,
                error=f"MCP runtime startup failed: {self._startup_error}",
            )

        future = self.submit(
            self._client.process_query(
                user_query,
                progress_callback=progress_callback,
                history=history,
            )
        )

        try:
            return future.result(timeout=timeout)
        except Exception as e:
            logger.exception("process_query_sync failed")
            return QueryResult(success=False, error=str(e))


# Module-level singleton. One per Gunicorn worker process.
_runtime: Optional[MCPRuntime] = None
_runtime_lock = threading.Lock()


def get_runtime() -> MCPRuntime:
    """Get (and lazily start) the per-worker MCP runtime singleton."""
    global _runtime
    if _runtime is None:
        with _runtime_lock:
            if _runtime is None:
                _runtime = MCPRuntime()
                _runtime.start()
    return _runtime
