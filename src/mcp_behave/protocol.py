"""Protocol framing, parsing, and request-response correlation for mcp-behave wrap.

Provides high-throughput chunked NDJSON streaming framing, strict byte-faithful forwarding,
JSON-RPC batch handling, BOM stripping for parsing, and asynchronous telemetry emission.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import queue
import re
import threading
import time
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from .bus import EventBus
from .events import (
    BehavioralEvent,
    KIND_PROTOCOL_ANOMALY,
    KIND_PROTOCOL_NOTIFICATION,
    KIND_PROTOCOL_REQUEST,
    KIND_PROTOCOL_RESPONSE,
    KIND_STDOUT_POLLUTION,
)
from .telemetry import TelemetryStore, hash_content


class StreamingFramer:
    """Chunked streaming framer for newline-delimited JSON-RPC messages.

    Reads in chunks (default 1 MB) to avoid StreamReader.readline() limits,
    buffering arbitrary message sizes (>1 MB) and yielding complete line bytes immediately.
    On EOF, any trailing partial line is flushed as-is.
    """

    def __init__(self, reader: asyncio.StreamReader, chunk_size: int = 1048576):
        self.reader = reader
        self.chunk_size = chunk_size
        self.buffer = bytearray()

    async def __aiter__(self) -> AsyncIterator[Tuple[bytes, bool]]:
        """Yield (line_bytes, is_eof_flush)."""
        search_start = 0
        while True:
            try:
                chunk = await self.reader.read(self.chunk_size)
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                chunk = b""

            if not chunk:
                # EOF reached
                if self.buffer:
                    yield bytes(self.buffer), True
                    self.buffer.clear()
                break

            self.buffer.extend(chunk)

            while True:
                nl_idx = self.buffer.find(b"\n", search_start)
                if nl_idx == -1:
                    search_start = len(self.buffer)
                    break
                if nl_idx == len(self.buffer) - 1:
                    line = bytes(self.buffer)
                    self.buffer.clear()
                    search_start = 0
                    yield line, False
                    break
                else:
                    line = bytes(self.buffer[: nl_idx + 1])
                    del self.buffer[: nl_idx + 1]
                    search_start = 0
                    yield line, False


class ProtocolMonitor:
    """Monitors bidirectional JSON-RPC streams between MCP client and server."""

    def __init__(
        self,
        session_id: str,
        server_id: str,
        bus: EventBus,
        telemetry: TelemetryStore,
        log_content: bool = False,
        queue_size: int = 10000,
    ):
        self.session_id = session_id
        self.server_id = server_id
        self.bus = bus
        self.telemetry = telemetry
        self.log_content = log_content

        # Active request tracking: request_id -> {"start_ts": float, "method": str, "tool_name": Optional[str]}
        self._active_requests: Dict[Any, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        # Non-blocking raw line queue for background parsing and telemetry
        self._line_queue: queue.Queue[Optional[Tuple[bytes, str, float]]] = queue.Queue(maxsize=queue_size)
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name=f"protocol-monitor-{session_id[:8]}",
            daemon=True,
        )
        self._worker_thread.start()

    def get_active_request_ids(self) -> List[Any]:
        """Return list of currently active request IDs (for M4 attribution)."""
        with self._lock:
            return list(self._active_requests.keys())

    def enqueue_line(self, line_bytes: bytes, direction: str) -> None:
        """Enqueue a framed line synchronously for background worker consumption without creating an asyncio task."""
        now = time.time()
        try:
            self._line_queue.put_nowait((line_bytes, direction, now))
        except queue.Full:
            drop_event = BehavioralEvent(
                event="telemetry_drop",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_TELEMETRY_DROP,
                timestamp=now,
                payload={"dropped_line_bytes": len(line_bytes)},
            )
            self.telemetry.record(drop_event)

    async def process_line(self, line_bytes: bytes, direction: str, sync: bool = False) -> None:
        """Enqueue a framed line for background processing without blocking forwarding.
        
        If sync=True, processes synchronously immediately (useful for testing and deterministic inspection).
        """
        now = time.time()
        if sync:
            self._sync_process_line(line_bytes, direction, now)
            return

        try:
            self._line_queue.put_nowait((line_bytes, direction, now))
        except queue.Full:
            drop_event = BehavioralEvent(
                event="telemetry_drop",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_TELEMETRY_DROP,
                timestamp=now,
                payload={"dropped_line_bytes": len(line_bytes)},
            )
            self.telemetry.record(drop_event)

    def _worker_loop(self) -> None:
        """Background thread consuming raw lines off the hot path."""
        while not self._stop_event.is_set() or not self._line_queue.empty():
            try:
                item = self._line_queue.get(timeout=0.05)
            except queue.Empty:
                continue

            try:
                if item is None:
                    break
                line_bytes, direction, now = item
                self._sync_process_line(line_bytes, direction, now)
            finally:
                self._line_queue.task_done()

    def drain(self) -> None:
        """Wait for line queue to be fully processed."""
        self._line_queue.join()

    def close(self, timeout: float = 2.0) -> None:
        """Signal background worker to finish and wait for queue drain."""
        self._stop_event.set()
        try:
            self._line_queue.put(None, timeout=timeout)
        except (queue.Full, Exception):
            pass
        self._worker_thread.join(timeout=timeout)

    def _sync_process_line(self, line_bytes: bytes, direction: str, now: float) -> None:
        """Synchronous parsing and telemetry dispatch on background thread."""
        # Strip trailing newlines for inspection
        stripped = line_bytes.rstrip(b"\r\n")
        if not stripped:
            # Empty lines are forwarded as-is without protocol event
            return

        # Strip UTF-8 BOM if present
        if stripped.startswith(b"\xef\xbb\xbf"):
            stripped = stripped[3:]

        # For messages > 64 KB when log_content is False, parse envelope headers only
        # (id, method, params.name) to avoid full JSON tree allocation and GIL contention.
        if len(stripped) > 65536 and not self.log_content:
            self._handle_large_message_envelope_sync(stripped, len(line_bytes), direction, now)
            return

        # Attempt JSON parse directly on bytes (avoids large intermediate str allocation)
        try:
            data = json.loads(stripped)
        except Exception:
            decoded_preview = stripped[:256].decode("utf-8", errors="replace")
            # Check for stdout pollution or protocol anomaly
            if direction == "server_to_client":
                # A corrupted JSON-RPC message typically starts with '{' or '[{' or contains '"jsonrpc"'
                looks_like_jsonrpc = (
                    stripped.startswith(b"{")
                    or stripped.startswith(b"[{")
                    or b'"jsonrpc"' in stripped
                    or b'"method"' in stripped
                    or b'"result"' in stripped
                )
                if not looks_like_jsonrpc:
                    event = BehavioralEvent(
                        event="stdout_pollution",
                        session_id=self.session_id,
                        server_id=self.server_id,
                        kind=KIND_STDOUT_POLLUTION,
                        timestamp=now,
                        source="monitor",
                        evidence_tier="observed",
                        payload={
                            "size_bytes": len(line_bytes),
                            "preview": decoded_preview[:120],
                        },
                    )
                    self.bus.publish_sync(event)
                    self.telemetry.record(event)
                    return

            # Otherwise, malformed JSON is a protocol anomaly
            event = BehavioralEvent(
                event="protocol_anomaly",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_PROTOCOL_ANOMALY,
                timestamp=now,
                source="monitor",
                evidence_tier="observed",
                payload={
                    "direction": direction,
                    "size_bytes": len(line_bytes),
                    "error": "invalid_json",
                    "preview": decoded_preview[:120],
                },
            )
            self.bus.publish_sync(event)
            self.telemetry.record(event)
            return

        # Handle batch or single message
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    self._handle_single_message_sync(item, len(line_bytes), direction, now)
        elif isinstance(data, dict):
            self._handle_single_message_sync(data, len(line_bytes), direction, now)

    def _handle_single_message_sync(
        self, msg: Dict[str, Any], total_bytes: int, direction: str, now: float
    ) -> None:
        """Categorize and record a single JSON-RPC message object synchronously."""
        msg_id = msg.get("id")

        if direction == "client_to_server":
            method = msg.get("method")
            if method is not None:
                params = msg.get("params") or {}
                tool_name = None
                if method == "tools/call" and isinstance(params, dict):
                    tool_name = params.get("name")

                if msg_id is not None:
                    # Request with ID
                    with self._lock:
                        self._active_requests[msg_id] = {
                            "start_ts": now,
                            "method": method,
                            "tool_name": tool_name,
                        }
                    payload: Dict[str, Any] = {
                        "method": method,
                        "size_bytes": total_bytes,
                    }
                    if tool_name:
                        payload["tool_name"] = tool_name
                    if self.log_content:
                        payload["params"] = params
                    else:
                        payload["params_hash"] = hash_content(params)

                    event = BehavioralEvent(
                        event="protocol_request",
                        session_id=self.session_id,
                        server_id=self.server_id,
                        kind=KIND_PROTOCOL_REQUEST,
                        request_id=msg_id,
                        current_tool=tool_name,
                        target=tool_name or method,
                        timestamp=now,
                        source="monitor",
                        evidence_tier="observed",
                        payload=payload,
                    )
                    self.bus.publish_sync(event)
                    self.telemetry.record(event)
                else:
                    # Notification without ID
                    payload = {
                        "method": method,
                        "size_bytes": total_bytes,
                    }
                    if self.log_content:
                        payload["params"] = params
                    else:
                        payload["params_hash"] = hash_content(params)

                    event = BehavioralEvent(
                        event="protocol_notification",
                        session_id=self.session_id,
                        server_id=self.server_id,
                        kind=KIND_PROTOCOL_NOTIFICATION,
                        target=method,
                        timestamp=now,
                        source="monitor",
                        evidence_tier="observed",
                        payload=payload,
                    )
                    self.bus.publish_sync(event)
                    self.telemetry.record(event)

        elif direction == "server_to_client":
            # Response matching a client request
            if msg_id is not None and ("result" in msg or "error" in msg):
                with self._lock:
                    req_info = self._active_requests.pop(msg_id, None)
                start_ts = req_info["start_ts"] if req_info else None
                tool_name = req_info.get("tool_name") if req_info else None
                method = req_info.get("method") if req_info else None
                duration_ms = (now - start_ts) * 1000.0 if start_ts is not None else None

                is_error = "error" in msg
                content_obj = msg.get("error") if is_error else msg.get("result")

                payload = {
                    "size_bytes": total_bytes,
                    "is_error": is_error,
                }
                if method:
                    payload["method"] = method
                if tool_name:
                    payload["tool_name"] = tool_name
                if duration_ms is not None:
                    payload["duration_ms"] = round(duration_ms, 3)

                if self.log_content:
                    payload["content"] = content_obj
                else:
                    payload["content_hash"] = hash_content(content_obj)

                event = BehavioralEvent(
                    event="protocol_response",
                    session_id=self.session_id,
                    server_id=self.server_id,
                    kind=KIND_PROTOCOL_RESPONSE,
                    request_id=msg_id,
                    current_tool=tool_name,
                    target=tool_name or method,
                    timestamp=now,
                    source="monitor",
                    evidence_tier="observed",
                    payload=payload,
                )
                self.bus.publish_sync(event)
                self.telemetry.record(event)

            elif "method" in msg:
                # Server-initiated notification or request
                method = msg.get("method")
                params = msg.get("params") or {}
                payload = {
                    "method": method,
                    "size_bytes": total_bytes,
                }
                if self.log_content:
                    payload["params"] = params
                else:
                    payload["params_hash"] = hash_content(params)

                event = BehavioralEvent(
                    event="protocol_notification",
                    session_id=self.session_id,
                    server_id=self.server_id,
                    kind=KIND_PROTOCOL_NOTIFICATION,
                    request_id=msg_id,
                    target=method,
                    timestamp=now,
                    source="monitor",
                    evidence_tier="observed",
                    payload=payload,
                )
                self.bus.publish_sync(event)
                self.telemetry.record(event)

    def _handle_large_message_envelope_sync(
        self, stripped: bytes, total_bytes: int, direction: str, now: float
    ) -> None:
        """Extract id, method, and params.name without full JSON parsing for >64 KB messages."""
        header_chunk = stripped[:4096]

        msg_id: Any = None
        id_m = re.search(rb'"id"\s*:\s*([0-9]+|"[^"]+")', header_chunk)
        if id_m:
            raw_id = id_m.group(1).decode("utf-8", errors="replace")
            if raw_id.startswith('"') and raw_id.endswith('"'):
                msg_id = raw_id[1:-1]
            else:
                try:
                    msg_id = int(raw_id)
                except ValueError:
                    msg_id = raw_id

        # Compute sha256 in C (releases GIL)
        h = hashlib.sha256(stripped).hexdigest()
        prefix = stripped[:4].decode("utf-8", errors="replace")
        hashed_summary = {"sha256": h, "prefix": prefix, "length": len(stripped)}

        if direction == "client_to_server":
            method_m = re.search(rb'"method"\s*:\s*"([^"]+)"', header_chunk)
            method = method_m.group(1).decode("utf-8", errors="replace") if method_m else "unknown"

            name_m = re.search(rb'"name"\s*:\s*"([^"]+)"', header_chunk)
            tool_name = name_m.group(1).decode("utf-8", errors="replace") if name_m else None

            payload: Dict[str, Any] = {
                "method": method,
                "size_bytes": total_bytes,
                "params_hash": hashed_summary,
            }
            if tool_name:
                payload["tool_name"] = tool_name

            if msg_id is not None:
                with self._lock:
                    self._active_requests[msg_id] = {
                        "start_ts": now,
                        "method": method,
                        "tool_name": tool_name,
                    }
                event = BehavioralEvent(
                    event="protocol_request",
                    session_id=self.session_id,
                    server_id=self.server_id,
                    kind=KIND_PROTOCOL_REQUEST,
                    request_id=msg_id,
                    current_tool=tool_name,
                    target=tool_name or method,
                    timestamp=now,
                    source="monitor",
                    evidence_tier="observed",
                    payload=payload,
                )
            else:
                event = BehavioralEvent(
                    event="protocol_notification",
                    session_id=self.session_id,
                    server_id=self.server_id,
                    kind=KIND_PROTOCOL_NOTIFICATION,
                    target=method,
                    timestamp=now,
                    source="monitor",
                    evidence_tier="observed",
                    payload=payload,
                )
            self.bus.publish_sync(event)
            self.telemetry.record(event)

        elif direction == "server_to_client":
            is_error = b'"error"' in header_chunk
            req_info = None
            if msg_id is not None:
                with self._lock:
                    req_info = self._active_requests.pop(msg_id, None)

            start_ts = req_info["start_ts"] if req_info else None
            tool_name = req_info.get("tool_name") if req_info else None
            method = req_info.get("method") if req_info else None
            duration_ms = (now - start_ts) * 1000.0 if start_ts is not None else None

            payload = {
                "size_bytes": total_bytes,
                "is_error": is_error,
                "content_hash": hashed_summary,
            }
            if method:
                payload["method"] = method
            if tool_name:
                payload["tool_name"] = tool_name
            if duration_ms is not None:
                payload["duration_ms"] = round(duration_ms, 3)

            event = BehavioralEvent(
                event="protocol_response",
                session_id=self.session_id,
                server_id=self.server_id,
                kind=KIND_PROTOCOL_RESPONSE,
                request_id=msg_id,
                current_tool=tool_name,
                target=tool_name or method,
                timestamp=now,
                source="monitor",
                evidence_tier="observed",
                payload=payload,
            )
            self.bus.publish_sync(event)
            self.telemetry.record(event)
