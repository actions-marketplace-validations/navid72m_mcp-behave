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
import sys
import threading
import time
from typing import Any, AsyncIterator, Callable, Coroutine, Dict, List, Optional, Tuple

from .bus import EventBus
from .events import (
    BehavioralEvent,
    KIND_CROSS_SESSION_DRIFT,
    KIND_MANIFEST_BASELINE,
    KIND_MANIFEST_DRIFT,
    KIND_PROTOCOL_ANOMALY,
    KIND_PROTOCOL_NOTIFICATION,
    KIND_PROTOCOL_REQUEST,
    KIND_PROTOCOL_RESPONSE,
    KIND_STDOUT_POLLUTION,
    KIND_TELEMETRY_DROP,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
)
from .canary import CanaryManager
from .manifest import ManifestTracker
from .scanner import ContentScanner
from .telemetry import TelemetryStore, hash_content


MAX_MESSAGE_BYTES = 16 * 1024 * 1024  # 16 MiB


class StreamingFramer:
    """Chunked streaming framer for newline-delimited JSON-RPC messages.

    Reads in chunks (default 1 MB) to avoid StreamReader.readline() limits,
    buffering messages up to max_line_bytes (default 16 MiB) and yielding complete
    line bytes immediately. On EOF, any trailing partial line is flushed as-is.
    Raises ValueError if an incoming line exceeds max_line_bytes.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        chunk_size: int = 1048576,
        max_line_bytes: int = MAX_MESSAGE_BYTES,
    ):
        self.reader = reader
        self.chunk_size = chunk_size
        self.max_line_bytes = max_line_bytes
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
                    if len(self.buffer) > self.max_line_bytes:
                        self.buffer.clear()
                        raise ValueError(
                            f"JSON-RPC message exceeded maximum supported size ({self.max_line_bytes} bytes)"
                        )
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
        send_probe_fn: Optional[Callable[[bytes], Coroutine[Any, Any, None]]] = None,
        reverify_interval: int = 20,
        reverify_period: float = 300.0,
        enable_reverify: bool = True,
        notify: bool = False,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        canary_mgr: Optional[CanaryManager] = None,
        enable_content_scan: bool = True,
        server_lock: Optional[Any] = None,
        enforce: bool = False,
        live_identity: Optional[Dict[str, Any]] = None,
        attribution_engine: Optional[Any] = None,
        prior_manifest: Optional[Dict[str, Any]] = None,
    ):
        self.session_id = session_id
        self.server_id = server_id
        self.bus = bus
        self.telemetry = telemetry
        self.log_content = log_content
        self.notify = notify
        self.loop = loop
        self.server_lock = server_lock
        self.enforce = enforce
        self.live_identity = live_identity
        self.attribution_engine = attribution_engine
        self.prior_manifest = prior_manifest

        # Payload content and canary scanner (Milestone 2b)
        self.canary_mgr = canary_mgr or CanaryManager()
        self.scanner = ContentScanner(
            session_id=session_id,
            server_id=server_id,
            canary_mgr=self.canary_mgr,
            enabled=enable_content_scan,
        )

        # Active request tracking: request_id -> {"start_ts": float, "method": str, "tool_name": Optional[str]}
        self._active_requests: Dict[Any, Dict[str, Any]] = {}
        self._translated_ids: Dict[str, Any] = {}  # proxy_id -> original_client_id
        self._translation_seq: int = 0
        self._lock = threading.Lock()

        # TOFU Manifest and Active Re-verification Tracker
        self.manifest_tracker = ManifestTracker(
            session_id=session_id,
            server_id=server_id,
            send_probe_fn=send_probe_fn,
            reverify_interval=reverify_interval,
            reverify_period=reverify_period,
            enable_reverify=enable_reverify,
            loop=loop,
            on_event_fn=self._on_tracker_event,
            get_active_ids_fn=self.get_active_request_ids,
            server_lock=server_lock,
            enforce=enforce,
            live_identity=live_identity,
            prior_manifest=prior_manifest,
        )

        # Non-blocking raw line queue for background parsing and telemetry
        self._line_queue: queue.Queue[Optional[Tuple[bytes, str, float]]] = queue.Queue(maxsize=queue_size)
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name=f"protocol-monitor-{session_id[:8]}",
            daemon=True,
        )
        self._worker_thread.start()

    def _on_tracker_event(self, event: BehavioralEvent) -> None:
        """Callback for tracker events (e.g. from pagination timeout)."""
        self.bus.publish_sync(event)
        self.telemetry.record(event)
        self._emit_alert(event)

    def _emit_alert(self, event: BehavioralEvent) -> None:
        """Emit clean stderr alert on HIGH/CRITICAL drift / would_block, and optional macOS notification."""
        payload = event.payload or {}
        if payload.get("would_block") or event.severity in (SEVERITY_HIGH, SEVERITY_CRITICAL):
            category = payload.get("category", event.event)
            tool = payload.get("tool", "")
            msg = payload.get("message", "")
            tool_suffix = f" in tool '{tool}'" if tool else ""
            if event.severity == SEVERITY_CRITICAL:
                alert_line = f"\n[mcp-behave] CRITICAL SECURITY ALERT: Behavioral alert detected{tool_suffix} ({category}): {msg}\n"
            else:
                alert_line = f"\n[mcp-behave] WARNING: High-severity behavioral drift detected{tool_suffix} ({category}): {msg}\n"
            sys.stderr.write(alert_line)
            sys.stderr.flush()
            if self.notify and sys.platform == "darwin":
                try:
                    import subprocess
                    clean_title = "mcp-behave security alert"
                    clean_msg = f"{category}{tool_suffix}: {msg}".replace('"', '\\"')
                    script = f'display notification "{clean_msg}" with title "{clean_title}"'
                    subprocess.Popen(["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass

    def is_synthetic_probe_response(self, line_bytes: bytes) -> bool:
        """Check if incoming server message is a response to an active/recent proxy probe."""
        if not self.manifest_tracker or not self.manifest_tracker.has_tracked_probes():
            return False
        if b'"id"' not in line_bytes and b'"\\u' not in line_bytes:
            return False
        try:
            msg = json.loads(line_bytes.decode("utf-8", errors="replace"))
        except Exception:
            return False
        if not isinstance(msg, dict):
            return False
        # Must be a JSON-RPC response (result or error), not a server-initiated request
        if "result" not in msg and "error" not in msg:
            return False
        msg_id = msg.get("id")
        if msg_id is None or isinstance(msg_id, (bool, dict, list)):
            return False
        return (
            self.manifest_tracker.is_probe_response(msg_id)
            or self.manifest_tracker.is_tombstoned_probe_id(msg_id)
        )

    def translate_colliding_client_request(self, line_bytes: bytes) -> bytes:
        """Translate a client request ID if it collides with an issued or tombstoned probe ID.

        Prevents both Case A (in-flight probe collision) and Case B (delayed probe
        response arriving after client reused a tombstoned ID) without rewriting
        non-colliding traffic.
        """
        if not self.manifest_tracker or not self.manifest_tracker.has_tracked_probes():
            return line_bytes
        if b'"id"' not in line_bytes and b'"\\u' not in line_bytes:
            return line_bytes
        try:
            msg = json.loads(line_bytes.decode("utf-8", errors="replace"))
        except Exception:
            return line_bytes
        if not isinstance(msg, dict) or "method" not in msg or "id" not in msg:
            return line_bytes
        orig_id = msg.get("id")
        if orig_id is None or isinstance(orig_id, (bool, dict, list)):
            return line_bytes
        if not (
            self.manifest_tracker.is_probe_response(orig_id)
            or self.manifest_tracker.is_tombstoned_probe_id(orig_id)
        ):
            return line_bytes
        with self._lock:
            if len(self._translated_ids) >= 10000:
                raise RuntimeError(
                    "Too many concurrent colliding request ID translations (10000 limit)"
                )
            self._translation_seq += 1
            proxy_id = f"mcpb-c-{self._translation_seq}"
            while (
                proxy_id in self._active_requests
                or proxy_id in self._translated_ids
                or self.manifest_tracker.is_probe_response(proxy_id)
                or self.manifest_tracker.is_tombstoned_probe_id(proxy_id)
            ):
                self._translation_seq += 1
                proxy_id = f"mcpb-c-{self._translation_seq}"
            self._translated_ids[proxy_id] = orig_id
        msg["id"] = proxy_id
        return json.dumps(msg, ensure_ascii=False).encode("utf-8") + b"\n"

    def restore_translated_server_response(self, line_bytes: bytes) -> bytes:
        """Restore original client request ID on a server response if it was translated."""
        with self._lock:
            if not self._translated_ids:
                return line_bytes
        if b'"id"' not in line_bytes and b'"\\u' not in line_bytes:
            return line_bytes
        try:
            msg = json.loads(line_bytes.decode("utf-8", errors="replace"))
        except Exception:
            return line_bytes
        if not isinstance(msg, dict) or "id" not in msg:
            return line_bytes
        if "result" not in msg and "error" not in msg:
            return line_bytes
        msg_id = msg.get("id")
        if not isinstance(msg_id, str):
            return line_bytes
        with self._lock:
            orig_id = self._translated_ids.pop(msg_id, None)
        if orig_id is None:
            return line_bytes
        msg["id"] = orig_id
        return json.dumps(msg, ensure_ascii=False).encode("utf-8") + b"\n"

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
        if self.manifest_tracker:
            self.manifest_tracker.stop()
        self._stop_event.set()
        try:
            self._line_queue.put(None, timeout=timeout)
        except (queue.Full, Exception):
            pass
        self._worker_thread.join(timeout=timeout)

    def _sync_process_line(self, line_bytes: bytes, direction: str, now: float) -> None:
        """Synchronous parsing and telemetry dispatch on background thread."""
        # Fast path for large messages (>64 KB): avoid intermediate copy of 1 MB byte string
        if len(line_bytes) > 65536 and not self.log_content:
            header_check = line_bytes[:4096]
            is_manifest_response = (
                b'"tools"' in header_check
                or b'"serverInfo"' in header_check
                or b'"capabilities"' in header_check
            )
            if not is_manifest_response:
                self._handle_large_message_envelope_sync(line_bytes, len(line_bytes), direction, now)
                return

        # Strip trailing newlines for inspection
        stripped = line_bytes.rstrip(b"\r\n")
        if not stripped:
            # Empty lines are forwarded as-is without protocol event
            return

        # Strip UTF-8 BOM if present
        if stripped.startswith(b"\xef\xbb\xbf"):
            stripped = stripped[3:]

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
                    tool_args = params.get("arguments") if "arguments" in params else params
                    if getattr(self, "scanner", None):
                        scan_events = self.scanner.scan_tool_call(tool_name, tool_args, request_id=msg_id, now=now)
                        for se in scan_events:
                            self.bus.publish_sync(se)
                            self.telemetry.record(se)
                            self._emit_alert(se)

                    if self.attribution_engine and tool_name and msg_id is not None:
                        tool_ann = None
                        if self.manifest_tracker and self.manifest_tracker.tools_baseline:
                            tool_def = self.manifest_tracker.tools_baseline.get(tool_name)
                            if tool_def and isinstance(tool_def, dict):
                                tool_ann = tool_def.get("annotations")
                        self.attribution_engine.on_tool_call_start(msg_id, tool_name, now, annotations=tool_ann)

                if self.manifest_tracker:
                    if msg_id is not None:
                        self.manifest_tracker.record_client_id_style(msg_id)
                    if method in ("notifications/initialized", "initialized"):
                        self.manifest_tracker.mark_client_initialized()
                    if tool_name:
                        self.manifest_tracker.schedule_client_tool_call(tool_name)

                if msg_id is not None:
                    # Request with ID (bounded tracking to prevent unbounded growth)
                    with self._lock:
                        if len(self._active_requests) >= 10000 and msg_id not in self._active_requests:
                            oldest_key = next(iter(self._active_requests))
                            self._active_requests.pop(oldest_key, None)
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
            # Check if this is a response to an active proxy synthetic probe
            if (
                msg_id is not None
                and self.manifest_tracker
                and (
                    self.manifest_tracker.is_probe_response(msg_id)
                    or self.manifest_tracker.is_tombstoned_probe_id(msg_id)
                )
            ):
                is_error = "error" in msg
                content_obj = msg.get("error") if is_error else msg.get("result")
                events, _ = self.manifest_tracker.handle_tools_list_response(
                    msg_id,
                    content_obj if not is_error else None,
                    is_error=is_error,
                )
                for evt in events:
                    self.bus.publish_sync(evt)
                    self.telemetry.record(evt)
                    self._emit_alert(evt)
                return

            # Response matching a client request
            if msg_id is not None and ("result" in msg or "error" in msg):
                with self._lock:
                    req_info = self._active_requests.pop(msg_id, None)
                start_ts = req_info["start_ts"] if req_info else None
                tool_name = req_info.get("tool_name") if req_info else None
                method = req_info.get("method") if req_info else None
                duration_ms = (now - start_ts) * 1000.0 if start_ts is not None else None

                if method == "tools/call" and self.attribution_engine and msg_id is not None:
                    self.attribution_engine.on_tool_call_end(msg_id, now)

                is_error = "error" in msg
                content_obj = msg.get("error") if is_error else msg.get("result")

                if method == "tools/call" and getattr(self, "scanner", None) and not is_error:
                    scan_events = self.scanner.scan_tool_result(tool_name, content_obj, request_id=msg_id, now=now)
                    for se in scan_events:
                        self.bus.publish_sync(se)
                        self.telemetry.record(se)
                        self._emit_alert(se)

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

                # Process TOFU Manifest and Drift Detection
                if self.manifest_tracker:
                    if method == "initialize" and not is_error and isinstance(content_obj, dict):
                        init_events = self.manifest_tracker.handle_initialize_response(content_obj)
                        for ievt in init_events:
                            self.bus.publish_sync(ievt)
                            self.telemetry.record(ievt)
                            self._emit_alert(ievt)

                    elif method == "tools/list":
                        if self.manifest_tracker.prior_manifest is None:
                            self.manifest_tracker.prior_manifest = self.telemetry.get_last_trusted_manifest(self.server_id)
                        list_events, _ = self.manifest_tracker.handle_tools_list_response(
                            msg_id,
                            content_obj if not is_error else None,
                            is_error=is_error,
                        )
                        for levt in list_events:
                            self.bus.publish_sync(levt)
                            self.telemetry.record(levt)
                            self._emit_alert(levt)

            elif "method" in msg:
                # Server-initiated notification or request
                method = msg.get("method")
                params = msg.get("params") or {}

                if self.manifest_tracker and msg_id is None:
                    if method == "notifications/tools/list_changed":
                        self.manifest_tracker.mark_list_changed("tools")
                    elif method == "notifications/resources/list_changed":
                        self.manifest_tracker.mark_list_changed("resources")
                    elif method == "notifications/prompts/list_changed":
                        self.manifest_tracker.mark_list_changed("prompts")

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
        self, raw_bytes: bytes, total_bytes: int, direction: str, now: float
    ) -> None:
        """Extract id, method, and params.name without full JSON parsing or intermediate copies for >64 KB messages."""
        header_chunk = raw_bytes[:4096]
        msg_id: Any = None
        tool_name: Optional[str] = None
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

        # Compute sha256 in C directly on bytes buffer (releases GIL)
        h = hashlib.sha256(raw_bytes).hexdigest()
        prefix = raw_bytes[:4].decode("utf-8", errors="replace")
        hashed_summary = {"sha256": h, "prefix": prefix, "length": len(raw_bytes)}

        if direction == "client_to_server":
            method_m = re.search(rb'"method"\s*:\s*"([^"]+)"', header_chunk)
            method = method_m.group(1).decode("utf-8", errors="replace") if method_m else "unknown"

            name_m = re.search(rb'"name"\s*:\s*"([^"]+)"', header_chunk)
            tool_name = name_m.group(1).decode("utf-8", errors="replace") if name_m else None

            if self.manifest_tracker:
                if msg_id is not None:
                    self.manifest_tracker.record_client_id_style(msg_id)
                if tool_name:
                    self.manifest_tracker.schedule_client_tool_call(tool_name)

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

        # Content scanning for large messages using fast byte pre-filters
        if getattr(self, "scanner", None):
            scan_events = self.scanner.scan_raw_bytes(
                raw_bytes, direction, tool_name=tool_name, request_id=msg_id, now=now
            )
            for se in scan_events:
                self.bus.publish_sync(se)
                self.telemetry.record(se)
                self._emit_alert(se)
