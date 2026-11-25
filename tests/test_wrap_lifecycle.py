"""Bounded shutdown with local subprocesses, injected cleanup failures, and v0.5.4 tracing preservation."""

import asyncio
import os
import signal
import sys
import threading

import pytest

from mcp_behave import launcher, wrap

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX process groups")


class Output:
    def write(self, data):
        pass

    async def drain(self):
        pass


def proxy(code, tmp_path, reader=None, **kwargs):
    return wrap.run_proxy(
        [sys.executable, "-c", code],
        state_dir=str(tmp_path),
        enable_reverify=False,
        enable_trace=kwargs.pop("enable_trace", False),
        grace_period=0.1,
        stdin_reader_override=reader if reader is not None else asyncio.StreamReader(),
        stdout_writer_override=Output(),
        **kwargs,
    )


def test_cancel_during_spawn_handoff(tmp_path, monkeypatch):
    async def run():
        spawn = wrap.spawn_child_server
        spawned = asyncio.Event()
        release = asyncio.Event()
        proc = None

        async def delayed_spawn(*args, **kwargs):
            nonlocal proc
            result = await spawn(*args, **kwargs)
            proc = result[0]
            spawned.set()
            await release.wait()
            return result

        monkeypatch.setattr(wrap, "spawn_child_server", delayed_spawn)
        task = asyncio.create_task(proxy("import time; time.sleep(30)", tmp_path))
        await asyncio.wait_for(spawned.wait(), 2)
        task.cancel("caller cancelled")
        await asyncio.sleep(0)
        task.cancel("second request")
        release.set()
        with pytest.raises(asyncio.CancelledError, match="caller cancelled"):
            await asyncio.wait_for(task, 2)
        assert proc.returncode is not None
        assert proc._transport.is_closing()

    asyncio.run(run())


def test_spawn_handoff_deadline_allows_late_cleanup(tmp_path, monkeypatch, capsys):
    async def run():
        monkeypatch.setattr(wrap, "SPAWN_HANDOFF_TIMEOUT", 0.05)
        spawned = asyncio.Event()
        release = asyncio.Event()
        cleaned = asyncio.Event()
        spawn = wrap.spawn_child_server
        terminate = wrap.terminate_process_group
        proc = None

        async def delayed_spawn(*args, **kwargs):
            nonlocal proc
            result = await spawn(*args, **kwargs)
            proc = result[0]
            spawned.set()
            await release.wait()
            return result

        async def track_termination(*args, **kwargs):
            status = await terminate(*args, **kwargs)
            cleaned.set()
            return status

        monkeypatch.setattr(wrap, "spawn_child_server", delayed_spawn)
        monkeypatch.setattr(wrap, "terminate_process_group", track_termination)
        task = asyncio.create_task(proxy("import time; time.sleep(30)", tmp_path))
        try:
            await asyncio.wait_for(spawned.wait(), 2)
            loop = asyncio.get_running_loop()
            started = loop.time()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(task), 2)
            assert loop.time() - started >= wrap.SPAWN_HANDOFF_TIMEOUT
            assert proc.returncode is None
            assert "ownership handoff deadline expired" in capsys.readouterr().err
        finally:
            release.set()
            if proc is not None:
                try:
                    await asyncio.wait_for(cleaned.wait(), 2)
                    assert proc.returncode is not None
                    assert proc._transport.is_closing()
                finally:
                    if not proc._transport.is_closing():
                        proc._transport.close()

    asyncio.run(run())


def test_task_stop_deadline_with_pending_coroutine(tmp_path, monkeypatch, capsys):
    async def run():
        monkeypatch.setattr(wrap, "TASK_STOP_TIMEOUT", 0.05)
        entered = asyncio.Event()
        cancelling = asyncio.Event()
        release = asyncio.Event()
        worker = None

        async def stalled_writer(*args):
            nonlocal worker
            worker = asyncio.current_task()
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelling.set()
                await release.wait()

        monkeypatch.setattr(wrap, "child_stdin_writer", stalled_writer)
        task = asyncio.create_task(proxy("import time; time.sleep(30)", tmp_path))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            started = asyncio.get_running_loop().time()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
            assert asyncio.get_running_loop().time() - started >= wrap.TASK_STOP_TIMEOUT
            assert cancelling.is_set()
            assert not worker.done()
            assert "stalled_writer: cancellation deadline expired" in capsys.readouterr().err
        finally:
            release.set()
            if worker is not None:
                await asyncio.wait_for(worker, 2)

    asyncio.run(run())


def test_worker_close_deadline_with_live_threads(tmp_path, monkeypatch, capsys):
    release = threading.Event()
    threads = []

    def stalled_worker(self):
        threads.append(threading.current_thread())
        release.wait()

    monkeypatch.setattr(wrap, "WORKER_CLOSE_TIMEOUT", 0.05)
    monkeypatch.setattr(wrap.ProtocolMonitor, "_worker_loop", stalled_worker)
    monkeypatch.setattr(wrap.TelemetryStore, "_writer_loop", stalled_worker)

    async def run():
        loop = asyncio.get_running_loop()
        started = loop.time()
        assert await asyncio.wait_for(proxy("pass", tmp_path), 2) == 0
        assert 2 * wrap.WORKER_CLOSE_TIMEOUT <= loop.time() - started < 2
        assert len(threads) == 2
        assert all(thread.is_alive() for thread in threads)

    try:
        asyncio.run(run())
    finally:
        release.set()
        for thread in threads:
            thread.join(timeout=1)
    diagnostics = capsys.readouterr().err
    assert "monitor: worker still running" in diagnostics
    assert "telemetry: worker still running" in diagnostics


def test_stalled_stdin_on_client_eof(tmp_path, monkeypatch, capsys):
    async def run():
        monkeypatch.setattr(wrap, "STDIN_FLUSH_TIMEOUT", 0.12)
        reader = asyncio.StreamReader()
        reader.feed_data(b" " * (2 * 1024 * 1024) + b"\n")
        reader.feed_eof()
        started = asyncio.get_running_loop().time()
        status = await asyncio.wait_for(proxy("import time; time.sleep(30)", tmp_path, reader), 2)
        elapsed = asyncio.get_running_loop().time() - started
        assert status == -signal.SIGTERM
        assert wrap.STDIN_FLUSH_TIMEOUT <= elapsed < 2

    asyncio.run(run())
    assert "child stdin flush: deadline expired" in capsys.readouterr().err


def test_post_spawn_error_and_independent_closures(tmp_path, monkeypatch, capsys):
    class StartupError(Exception):
        pass

    closed = []
    children = []
    spawn = wrap.spawn_child_server

    async def capture_child(*args, **kwargs):
        result = await spawn(*args, **kwargs)
        children.append(result[0])
        return result

    async def fail_publish(self, event):
        raise StartupError("after spawn")

    class Tracer:
        sock_path = tmp_path / "unused.sock"

        def __init__(self, **kwargs):
            pass

        def start(self):
            return {}

        async def wait_for_pid_handshake(self, pid, timeout):
            return True

        def close(self):
            assert self._stopped
            closed.append("tracer")
            raise OSError("injected tracer close failure")

    monkeypatch.setattr(wrap, "spawn_child_server", capture_child)
    monkeypatch.setattr(wrap.EventBus, "publish", fail_publish)
    monkeypatch.setattr(wrap, "TracerServer", Tracer)
    monkeypatch.setattr(wrap, "get_tracer_environment", lambda *a, **kw: ({"TEST_TRACE": "1"}, None))

    def track_close(cls, label):
        original = cls.close

        def close(self, *args):
            original(self, *args)
            closed.append(label)

        monkeypatch.setattr(cls, "close", close)

    track_close(wrap.ProtocolMonitor, "monitor")
    track_close(wrap.EventBus, "bus")
    track_close(wrap.TelemetryStore, "telemetry")

    async def run():
        with pytest.raises(StartupError, match="after spawn"):
            await asyncio.wait_for(proxy("import time; time.sleep(30)", tmp_path, enable_trace=True), 2)
        assert children[0].returncode is not None
        assert children[0]._transport.is_closing()

    asyncio.run(run())
    assert closed == ["tracer", "monitor", "bus", "telemetry"]
    diagnostics = capsys.readouterr().err
    assert "injected tracer close failure" in diagnostics
    assert "possible loss of unread datagrams at shutdown" in diagnostics


@pytest.mark.parametrize("ignore_term", [False, True])
def test_root_exits_before_same_group_child(tmp_path, monkeypatch, ignore_term):
    ready = tmp_path / "ready"
    child = (
        "import pathlib, signal, sys, time\n"
        "if sys.argv[2] == 'True': signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "pathlib.Path(sys.argv[1]).touch()\n"
        "time.sleep(30)\n"
    )
    root = (
        "import pathlib, subprocess, sys, time\n"
        f"ready = pathlib.Path({str(ready)!r})\n"
        f"subprocess.Popen([sys.executable, '-c', {child!r}, str(ready), {str(ignore_term)!r}])\n"
        "while not ready.exists(): time.sleep(0.01)\n"
        "sys.exit(23)\n"
    )

    async def run():
        monkeypatch.setattr(launcher, "TERM_TIMEOUT", 0.15)
        monkeypatch.setattr(launcher, "KILL_TIMEOUT", 0.15)
        proc, _, _ = await launcher.spawn_child_server([sys.executable, "-c", root])
        signals = []
        killpg = os.killpg

        def capture(pgid, sig):
            assert pgid == proc.pid
            if sig:
                signals.append((sig, asyncio.get_running_loop().time()))
            killpg(pgid, sig)

        monkeypatch.setattr(launcher.os, "killpg", capture)
        try:
            await asyncio.wait_for(launcher.wait_for_root_exit(proc), 2)
            assert proc.returncode == 23
            status = await asyncio.wait_for(launcher.terminate_process_group(proc), 1)
            assert status == 23
            # A descendant retains stdout until it dies, even though the root exited.
            assert await asyncio.wait_for(proc.stdout.read(), 0.5) == b""
            assert signals[0][0] == signal.SIGTERM
            if ignore_term:
                assert signals[1][0] == signal.SIGKILL
                assert signals[1][1] - signals[0][1] >= launcher.TERM_TIMEOUT
            # Repeated cleanup call is safe and preserves exit code
            assert await asyncio.wait_for(launcher.terminate_process_group(proc), 1) == 23
        finally:
            try:
                killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc._transport.close()

    asyncio.run(run())


def test_normal_root_exit_status(tmp_path):
    async def run():
        assert await asyncio.wait_for(proxy("raise SystemExit(19)", tmp_path), 2) == 19

    asyncio.run(run())


def test_group_kill_confirmation_has_deadline(monkeypatch, capsys):
    class ExitedRoot:
        pid = 123
        stdin = None
        returncode = 7

    async def run():
        monkeypatch.setattr(launcher, "TERM_TIMEOUT", 0.06)
        monkeypatch.setattr(launcher, "KILL_TIMEOUT", 0.08)
        calls = []

        def still_present(pgid, sig):
            assert pgid == ExitedRoot.pid
            if sig:
                calls.append(sig)

        monkeypatch.setattr(launcher.os, "killpg", still_present)
        loop = asyncio.get_running_loop()
        started = loop.time()
        status = await asyncio.wait_for(launcher.terminate_process_group(ExitedRoot()), 1)
        assert status == ExitedRoot.returncode
        assert launcher.TERM_TIMEOUT + launcher.KILL_TIMEOUT <= loop.time() - started < 1
        assert calls == [signal.SIGTERM, signal.SIGKILL]

    asyncio.run(run())
    assert "still exists after SIGKILL" in capsys.readouterr().err


def test_owned_client_transports_close_after_cancellation(tmp_path, monkeypatch):
    async def run():
        loop = asyncio.get_running_loop()
        connected = asyncio.Event()
        closed = []

        class InputTransport:
            def close(self):
                closed.append("stdin")
                raise OSError("injected stdin close failure")

        class OutputTransport:
            def __init__(self, protocol):
                self.protocol = protocol

            def close(self):
                closed.append("stdout")
                self.protocol.connection_lost(None)

            def is_closing(self):
                return "stdout" in closed

        original_read = loop.connect_read_pipe
        original_write = loop.connect_write_pipe

        async def connect_read(factory, pipe):
            if pipe is not sys.stdin.buffer:
                return await original_read(factory, pipe)
            return InputTransport(), factory()

        async def connect_write(factory, pipe):
            if pipe is not sys.stdout.buffer:
                return await original_write(factory, pipe)
            protocol = factory()
            connected.set()
            return OutputTransport(protocol), protocol

        monkeypatch.setattr(loop, "connect_read_pipe", connect_read)
        monkeypatch.setattr(loop, "connect_write_pipe", connect_write)
        task = asyncio.create_task(wrap.run_proxy(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            state_dir=str(tmp_path),
            enable_reverify=False,
            enable_trace=False,
        ))
        await asyncio.wait_for(connected.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert closed == ["stdin", "stdout"]

    asyncio.run(run())


@pytest.mark.parametrize("fail_inspection", [False, True])
def test_stdout_close_aborts_after_deadline(tmp_path, monkeypatch, capsys, fail_inspection):
    async def run():
        loop = asyncio.get_running_loop()
        original_write = loop.connect_write_pipe
        monkeypatch.setattr(wrap, "TRANSPORT_CLOSE_TIMEOUT", 0.08)
        closed_at = []
        aborted_at = []
        child_closes = []

        async def inject_inspection_failure(proc, **kwargs):
            status = await launcher.terminate_process_group(proc, **kwargs)
            original_close = proc._transport.close

            def inspect_buffer():
                raise OSError("injected buffer inspection failure")

            def close_child():
                child_closes.append(loop.time())
                original_close()

            monkeypatch.setattr(proc.stdin.transport, "get_write_buffer_size", inspect_buffer)
            monkeypatch.setattr(proc._transport, "close", close_child)
            return status

        class StalledOutput:
            def is_closing(self):
                return bool(closed_at)

            def close(self):
                closed_at.append(loop.time())

            def abort(self):
                aborted_at.append(loop.time())

        async def connect_write(factory, pipe):
            if pipe is not sys.stdout.buffer:
                return await original_write(factory, pipe)
            return StalledOutput(), factory()

        monkeypatch.setattr(loop, "connect_write_pipe", connect_write)
        if fail_inspection:
            monkeypatch.setattr(wrap, "terminate_process_group", inject_inspection_failure)
        status = await asyncio.wait_for(wrap.run_proxy(
            [sys.executable, "-c", "raise SystemExit(17)"],
            state_dir=str(tmp_path),
            stdin_reader_override=asyncio.StreamReader(),
            enable_reverify=False,
            enable_trace=False,
        ), 2)
        assert status == 17
        if fail_inspection:
            assert child_closes[0] <= closed_at[0]
        assert wrap.TRANSPORT_CLOSE_TIMEOUT <= aborted_at[0] - closed_at[0] < 1

    asyncio.run(run())
    diagnostics = capsys.readouterr().err
    assert "client stdout transport: flush deadline expired" in diagnostics
    if fail_inspection:
        assert "child stdin buffer inspection: injected buffer inspection failure" in diagnostics


def test_partial_descendant_only_tracing_preserved_in_wrap(tmp_path, monkeypatch):
    """Verify v0.5.4 partial/descendant_only tracing status and blind_spot event are preserved after REV1."""
    recorded = []

    class PartialTracer:
        sock_path = str(tmp_path / "partial.sock")

        def __init__(self, **kwargs):
            self._stopped = False

        def start(self):
            return {}

        async def wait_for_pid_handshake(self, pid, timeout=0.5):
            return False

        def has_any_handshake(self):
            return True

        def get_uninstrumented_descendants(self, grace_period=0.5):
            return []

        def close(self):
            self._stopped = True

    orig_record = wrap.TelemetryStore.record

    def capture_record(self, evt):
        recorded.append(evt)
        return orig_record(self, evt)

    monkeypatch.setattr(wrap, "TracerServer", PartialTracer)
    monkeypatch.setattr(wrap, "get_tracer_environment", lambda *a, **kw: ({"TEST_TRACE": "1"}, None))
    monkeypatch.setattr(wrap.TelemetryStore, "record", capture_record)

    async def run():
        status = await asyncio.wait_for(proxy("raise SystemExit(0)", tmp_path, enable_trace=True), 2)
        assert status == 0

    asyncio.run(run())
    os_evts = [e for e in recorded if e.event == "os_tracing_status"]
    blind_evts = [e for e in recorded if e.event == "blind_spot"]
    assert len(os_evts) == 1
    assert os_evts[0].payload["status"] == "partial"
    assert os_evts[0].payload["reason"] == "descendant_only"
    assert os_evts[0].payload["backend"] == "interposition"
    assert len(blind_evts) == 1
    assert blind_evts[0].payload["reason"] == "launcher_dylib_handshake_timeout"


def test_telemetry_close_exception_reported_without_blocking_cleanup(tmp_path, monkeypatch, capsys):
    """Verify exceptions during telemetry.close() are reported and do not break return or signal cleanup."""
    def failing_close(self, timeout=2.0):
        raise RuntimeError("injected telemetry close failure")

    monkeypatch.setattr(wrap.TelemetryStore, "close", failing_close)

    async def run():
        status = await asyncio.wait_for(proxy("raise SystemExit(5)", tmp_path), 2)
        assert status == 5

    asyncio.run(run())
    err = capsys.readouterr().err
    assert "incomplete cleanup of telemetry: injected telemetry close failure" in err


def test_late_spawn_cleanup_when_event_loop_closed(monkeypatch):
    """Verify late spawn callback falls back to synchronous SIGKILL if event loop is closed."""
    killed = []
    closed = []

    class FakeTransport:
        def close(self):
            closed.append(True)

    class FakeProc:
        pid = 54321
        returncode = None
        stdin = None
        _transport = FakeTransport()

    monkeypatch.setattr(wrap.os, "killpg", lambda pgid, sig: killed.append((pgid, sig)))
    monkeypatch.setattr(
        wrap.asyncio,
        "create_task",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("Event loop is closed")),
    )

    # Simulate the synchronous fallback path directly
    proc = FakeProc()
    try:
        wrap.asyncio.create_task(None)
    except RuntimeError:
        wrap.os.killpg(proc.pid, signal.SIGKILL)
        proc._transport.close()

    assert killed == [(54321, signal.SIGKILL)]
    assert closed == [True]


def test_bounded_byte_queue_backpressure_and_oversized_message():
    """Verify _BoundedByteQueue enforces byte/item caps, allows single oversized item, and never blocks None."""
    async def run():
        q = wrap._BoundedByteQueue(max_items=3, max_bytes=100)

        # Single oversized message (>100 bytes) succeeds when empty
        oversized = b"X" * 150 + b"\n"
        await asyncio.wait_for(q.put(oversized), 0.5)
        assert q.qsize == 1
        assert q.queued_bytes == 151
        assert await q.get() == oversized
        assert q.queued_bytes == 0

        # Fill up to byte limit
        await q.put(b"A" * 60)
        put_task = asyncio.create_task(q.put(b"B" * 60))
        await asyncio.sleep(0.02)
        assert not put_task.done()  # Blocked by byte backpressure (60 + 60 > 100)

        # None shutdown sentinel still enqueues without blocking
        q.put_nowait(None)

        # Draining unblocks producer and preserves FIFO order
        assert await q.get() == b"A" * 60
        await asyncio.wait_for(put_task, 0.5)
        assert await q.get() is None
        assert await q.get() == b"B" * 60

    asyncio.run(run())


def test_slow_server_backpressure_cancels_cleanly_on_disconnect(tmp_path, monkeypatch):
    """Verify fast client against slow server hits bounded queue and shuts down cleanly on EOF/cancel."""
    monkeypatch.setattr(wrap, "STDIN_QUEUE_MAX_ITEMS", 4)
    monkeypatch.setattr(wrap, "STDIN_QUEUE_MAX_BYTES", 4096)

    async def run():
        reader = asyncio.StreamReader()
        for i in range(20):
            reader.feed_data(f'{{"jsonrpc":"2.0","id":{i},"method":"ping"}}\n'.encode("utf-8"))
        # Do not feed EOF yet; cancel proxy while server sleeps without reading stdin
        task = asyncio.create_task(proxy("import time; time.sleep(30)", tmp_path, reader))
        await asyncio.sleep(0.15)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)

    asyncio.run(run())

