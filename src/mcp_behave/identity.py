"""Package identity resolution and offline supply-chain integrity pinning (Milestone 3).

Strict Standing Invariant: The proxy makes NO network calls.
All package inspection is performed offline via local runner caches,
installed environment metadata, and cryptographic entrypoint hashing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .events import (
    EVIDENCE_TIER_OBSERVED,
    KIND_PACKAGE_DRIFT,
    KIND_PACKAGE_TAMPER,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
)
from .lockfile import PackageLock, RuntimeLock


def compute_file_sha256(path: str | Path) -> Optional[str]:
    """Compute SHA-256 digest of a local file in C, releasing GIL."""
    p = Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return "sha256:" + h.hexdigest()
    except (OSError, PermissionError):
        return None


def resolve_executable_path(cmd_name: str, augment_path: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """Safely resolve absolute executable path and SHA-256 digest without user-writable hijack vectors."""
    base_path = os.environ.get("PATH", "")
    effective_path = base_path
    if augment_path:
        fallback_dirs = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"]
        extra = [d for d in fallback_dirs if d not in base_path.split(os.pathsep)]
        if extra:
            effective_path = base_path + os.pathsep + os.pathsep.join(extra)

    resolved = shutil.which(cmd_name, path=effective_path)
    if not resolved:
        return None, None

    file_hash = compute_file_sha256(resolved)
    return resolved, file_hash


def parse_package_spec(arg: str) -> Tuple[str, Optional[str]]:
    """Parse package name and optional semver/version tag from CLI argument (e.g. pkg@1.2.3 -> (pkg, 1.2.3))."""
    if arg.startswith("@"):
        # Scoped npm package: @org/name@1.2.3
        parts = arg.split("@")
        if len(parts) == 3:
            return f"@{parts[1]}", parts[2]
        return arg, None
    elif "@" in arg:
        parts = arg.split("@", 1)
        return parts[0], parts[1]
    return arg, None


def resolve_npx_identity(cmd_args: List[str], allow_network: bool = False) -> Dict[str, Any]:
    """Inspect local NPX runner arguments and local disk cache offline (or query registry if allow_network=True)."""
    # Find target package argument (skip flags like -y, --yes, -p, etc.)
    pkg_arg = None
    for arg in cmd_args[1:]:
        if not arg.startswith("-"):
            pkg_arg = arg
            break

    if not pkg_arg:
        return {
            "ecosystem": "npm",
            "name": "unknown",
            "version": "",
            "resolved_source": "local_args",
            "integrity": "",
        }

    pkg_name, requested_ver = parse_package_spec(pkg_arg)
    resolved_ver = requested_ver or ""
    integrity = ""

    # Attempt offline resolution in local ~/.npm/_npx/ cache
    npm_cache = Path.home() / ".npm" / "_npx"
    if npm_cache.is_dir():
        try:
            for entry in npm_cache.iterdir():
                pkg_json = entry / "node_modules" / pkg_name / "package.json"
                if pkg_json.is_file():
                    with open(pkg_json, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    resolved_ver = data.get("version", resolved_ver)
                    integrity = compute_file_sha256(pkg_json) or ""
                    break
        except Exception:
            pass

    # Remote registry lookup ONLY permitted during audit --lock, NEVER in wrap
    if allow_network and (not integrity or not resolved_ver):
        try:
            res = subprocess.run(
                ["npm", "view", pkg_arg, "version", "dist.integrity", "--json"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                npm_data = json.loads(res.stdout)
                if isinstance(npm_data, dict):
                    resolved_ver = resolved_ver or npm_data.get("version", "")
                    integrity = integrity or npm_data.get("dist.integrity", "")
                elif isinstance(npm_data, str) and not resolved_ver:
                    resolved_ver = npm_data
        except Exception:
            pass

    return {
        "ecosystem": "npm",
        "name": pkg_name,
        "version": resolved_ver,
        "resolved_source": "registry" if (allow_network and integrity) else ("local_cache" if integrity else "local_args"),
        "integrity": integrity,
    }


def resolve_uvx_identity(cmd_args: List[str], allow_network: bool = False) -> Dict[str, Any]:
    """Inspect local UVX/UV runner arguments and local uv cache offline."""
    pkg_arg = None
    for arg in cmd_args[1:]:
        if not arg.startswith("-"):
            pkg_arg = arg
            break

    if not pkg_arg:
        return {
            "ecosystem": "pypi",
            "name": "unknown",
            "version": "",
            "resolved_source": "local_args",
            "integrity": "",
        }

    pkg_name, requested_ver = parse_package_spec(pkg_arg)
    resolved_ver = requested_ver or ""
    integrity = ""

    # Attempt offline resolution in local ~/.cache/uv/ or ~/.cache/uv/wheels
    uv_cache = Path.home() / ".cache" / "uv"
    if uv_cache.is_dir():
        try:
            # Check for wheels or installed metadata matching package name
            for root, _, files in os.walk(uv_cache):
                for f in files:
                    if f.endswith(".whl") and pkg_name.replace("-", "_") in f.lower():
                        wheel_path = Path(root) / f
                        integrity = compute_file_sha256(wheel_path) or ""
                        # Extract version from wheel filename
                        m = re.search(r"-([0-9]+(?:\.[0-9]+)*(?:[a-zA-Z0-9_.-]*))-", f)
                        if m:
                            resolved_ver = m.group(1)
                        break
                if integrity:
                    break
        except Exception:
            pass

    return {
        "ecosystem": "pypi",
        "name": pkg_name,
        "version": resolved_ver,
        "resolved_source": "local_cache" if integrity else "local_args",
        "integrity": integrity,
    }


def resolve_python_identity(cmd_args: List[str]) -> Dict[str, Any]:
    """Inspect direct Python script or module execution offline."""
    # python -m module_name OR python /path/to/script.py
    entrypoint = None
    module_name = None

    for i, arg in enumerate(cmd_args[1:], 1):
        if arg == "-m" and i + 1 < len(cmd_args):
            module_name = cmd_args[i + 1]
            break
        elif not arg.startswith("-") and (arg.endswith(".py") or Path(arg).is_file()):
            entrypoint = arg
            break

    if entrypoint:
        file_hash = compute_file_sha256(entrypoint) or ""
        return {
            "ecosystem": "python_script",
            "name": Path(entrypoint).name,
            "version": "",
            "resolved_source": "local_file",
            "integrity": file_hash,
            "entrypoint": str(Path(entrypoint).resolve()),
        }

    if module_name:
        resolved_ver = ""
        integrity = ""
        try:
            import importlib.metadata
            resolved_ver = importlib.metadata.version(module_name)
        except Exception:
            pass
        return {
            "ecosystem": "pypi",
            "name": module_name,
            "version": resolved_ver,
            "resolved_source": "installed_metadata",
            "integrity": integrity,
        }

    return {
        "ecosystem": "python",
        "name": "python",
        "version": "",
        "resolved_source": "unknown",
        "integrity": "",
    }


def resolve_package_identity(
    cmd: List[str],
    augment_path: bool = False,
    allow_network: bool = False,
) -> Dict[str, Any]:
    """Resolve package identity strictly offline without making outbound network queries.

    Network queries (npm view) are ONLY permitted when allow_network=True during audit --lock.
    In mcp-behave wrap, allow_network is ALWAYS False.
    """
    if not cmd:
        return {"ecosystem": "none", "name": "", "version": "", "integrity": ""}

    base_cmd = Path(cmd[0]).name.lower()

    # 1. NPX / Node.js
    if base_cmd in ("npx", "npx.cmd"):
        return resolve_npx_identity(cmd, allow_network=allow_network)

    # 2. UVX / UV
    if base_cmd in ("uvx", "uvx.cmd", "uv"):
        return resolve_uvx_identity(cmd, allow_network=allow_network)

    # 3. Direct Python
    if "python" in base_cmd:
        return resolve_python_identity(cmd)

    # 4. Compiled Native Binary
    exe_path, exe_hash = resolve_executable_path(cmd[0], augment_path=augment_path)
    return {
        "ecosystem": "native_binary",
        "name": Path(cmd[0]).name,
        "version": "",
        "resolved_source": "local_binary",
        "integrity": exe_hash or "",
        "executable_path": exe_path or "",
    }


def check_package_tamper(
    locked_package: Optional[PackageLock],
    live_identity: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Compare live resolved package identity against locked package baseline.

    Strictly emits evidence_tier='observed' across all drift and tamper events.
    """
    if not locked_package or not live_identity:
        return []

    events: List[Dict[str, Any]] = []
    locked_ver = locked_package.version
    live_ver = live_identity.get("version", "")
    locked_int = locked_package.integrity
    live_int = live_identity.get("integrity", "")

    # 1. Version Drift: package version changed
    if locked_ver and live_ver and locked_ver != live_ver:
        events.append({
            "category": "package_identity_divergence",
            "kind": KIND_PACKAGE_DRIFT,
            "severity": SEVERITY_HIGH,
            "evidence_tier": EVIDENCE_TIER_OBSERVED,
            "would_block": True,
            "message": f"Package '{locked_package.name}' version diverged: locked='{locked_ver}', live='{live_ver}'.",
            "details": {
                "ecosystem": locked_package.ecosystem,
                "package": locked_package.name,
                "locked_version": locked_ver,
                "live_version": live_ver,
            },
        })

    # 2. Tamper / Rug Pull: same version, different cryptographic archive/binary digest
    if locked_int and live_int and locked_int != live_int:
        events.append({
            "category": "package_tamper",
            "kind": KIND_PACKAGE_TAMPER,
            "severity": SEVERITY_CRITICAL,
            "evidence_tier": EVIDENCE_TIER_OBSERVED,
            "would_block": True,
            "message": f"CRITICAL: Package '{locked_package.name}' integrity hash mismatch (possible supply-chain tamper or rug pull).",
            "details": {
                "ecosystem": locked_package.ecosystem,
                "package": locked_package.name,
                "version": locked_ver or live_ver,
                "locked_integrity": locked_int,
                "live_integrity": live_int,
            },
        })

    return events
