"""Shared pytest config: skip behavioral tracer tests if no tracer is available."""
import shutil, sys, pytest
from mcp_behave.probe import _macos_tracer_dylib, _linux_tracer_so

def _has_tracer() -> bool:
    if sys.platform == "darwin":
        return _macos_tracer_dylib() is not None
    if sys.platform == "linux":
        return _linux_tracer_so() is not None or shutil.which("strace") is not None
    return False

requires_tracer = pytest.mark.skipif(
    not _has_tracer(),
    reason="No syscall tracer (dylib, LD_PRELOAD, or strace) available on this host",
)
# Backwards compatibility alias
requires_strace = requires_tracer
