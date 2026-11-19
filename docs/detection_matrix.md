# Observation & Evasion Detection Matrix

This document provides a technical, reproducible breakdown of how `mcp-behave` observes server execution across different tracing backends, what evasion techniques each backend detects or misses, and the defense-in-depth mitigations implemented in the engine.

---

## 1. Threat Technique × Observation Backend Matrix

| Threat Vector / Evasion Technique | Native Libc Hooking (`DYLD` / `LD_PRELOAD`) | Linux `strace` (`-f` ptrace) | Ephemeral Container (Docker / Podman) | Kernel eBPF (Roadmap Phase 2) | Primary Mitigation in `mcp-behave` |
|---|:---:|:---:|:---:|:---:|---|
| **Dynamic libc `connect()` / `sendto()`** | ✅ **Detected** | ✅ **Detected** | 🛡️ **Blocked / Detected** | ✅ **Detected** | Network audit findings + Lockfile diff |
| **Direct Raw Syscall** (`libc.syscall` / inline `sysenter` bypassing libc `connect`) | ⚠️ *Missed* | ✅ **Detected** | 🛡️ **Network Blocked** | ✅ **Detected** | Linux `strace` backend or container `--network=none` |
| **Stripped Child Process** (`subprocess.Popen(..., env={})` stripping preload) | ⚠️ *Missed in Child* | ✅ **Detected** (follows `clone`/`fork`) | 🛡️ **Contained** (child inherits cgroup) | ✅ **Detected** (kernel-wide cgroup attach) | `strace -f` / Container isolation |
| **Canary Relative Path Access** (`~/.ssh/id_rsa`, `~/.aws/credentials`) | ✅ **Detected & Neutralized** | ✅ **Detected & Neutralized** | 🛡️ **Neutralized** | ✅ **Detected & Neutralized** | Ephemeral `$HOME` redirection with dummy canary secrets |
| **Hardcoded Absolute Path Access** (`/Users/admin/.ssh` or `/home/user/.ssh`) | ⚠️ *Detected if libc hooked, but host read occurs if permissions allow* | ⚠️ *Detected, host read occurs* | 🛡️ **Blocked (Host root FS not mounted)** | ⚠️ *Detected, host read occurs* | Container sandboxing mounts ephemeral filesystem only |
| **Environment Credential Stealing** (`$AWS_SECRET_ACCESS_KEY`, `$GITHUB_TOKEN`) | 🛡️ **Neutralized** | 🛡️ **Neutralized** | 🛡️ **Neutralized** | 🛡️ **Neutralized** | Automatic scrubbing of host environment variables |
| **Stateful Delayed Beacon** (Benign on rounds 1–2; beacon on round 3+) | ⚠️ *Missed on single round* | ⚠️ *Missed on single round* | ⚠️ *Missed on single round* | ⚠️ *Missed on single round* | Multi-round probing (`--rounds 3`) exercises tools repeatedly |
| **Time Bomb / Sleeping Exfiltration** (Delays action past probe window) | ⚠️ *Missed if sleep > timeout* | ⚠️ *Missed if sleep > timeout* | 🛡️ **Contained** | ⚠️ *Missed if sleep > timeout* | Behavioral lockfile (`mcp-behave check`) in CI |
| **UNIX Domain Socket Hijack** (`/var/run/docker.sock`, `/run/containerd/...`) | ✅ **Detected** | ✅ **Detected** | 🛡️ **Blocked (Socket not bind-mounted)** | ✅ **Detected** | AF_UNIX socket auditing + Docker socket block |
| **Adversarial Manifest Prompt Injection** (System instructions in tool descriptions) | ✅ **Detected** | ✅ **Detected** | ✅ **Detected** | ✅ **Detected** | Static manifest inspection & injection rule heuristics |
| **Arbitrary Command Injection in MCP Serve** (Agent invokes malicious CLI) | 🛡️ **Blocked** | 🛡️ **Blocked** | 🛡️ **Blocked** | 🛡️ **Blocked** | Strict command allowlisting with glob matching |

---

## 2. Tracing Backends Compared

### A. Native Libc Interposition (`macOS dylib` / `Linux .so`)
* **Mechanism**: Intercepts C standard library symbols (`connect`, `open`, `openat`, `creat`, `execve`, `execveat`, `sendto`) via dynamic loader hooks.
* **Advantages**:
  * Zero root or `sudo` requirements.
  * Very low overhead (< 3% CPU).
  * Runs seamlessly on local developer laptops without requiring Docker daemon.
* **Limitations**:
  * Targets with macOS hardened runtime (e.g. system Python) reject `DYLD_INSERT_LIBRARIES` unless run via non-hardened interpreter (Homebrew, uv, pyenv).
  * Statically compiled binaries (Go, Rust with `musl`) do not route through libc dynamic wrappers.
  * Explicit `env={}` in spawned child subprocesses strips environment variables unless intercepted at `execve`.

### B. Linux `strace` Backend
* **Mechanism**: Runs target under `strace -f -e trace=open,openat,creat,connect,sendto,sendmsg,sendmmsg,execve,execveat`.
* **Advantages**:
  * Kernel-level syscall interception; cannot be bypassed by static binaries or raw syscall instructions.
  * `-f` flag tracks all child processes, forks, and threads regardless of environment variable scrubbing.
* **Limitations**:
  * Linux only.
  * Tracing overhead slows down heavy I/O operations.

### C. Container Sandboxing (Docker / Podman)
* **Mechanism**: Executes the MCP server inside an isolated container with drop-all capabilities (`--cap-drop=ALL`), read-only root filesystems, ephemeral scratch space, and restricted network namespaces (`--network=none` or strictly isolated bridge).
* **Advantages**:
  * Even if a binary executes raw syscalls or circumvents userland hooks, it **cannot** access host files or credentials.
  * Absolute paths (`/home/user/.ssh`) resolve to empty/nonexistent paths in the container.
* **Limitations**:
  * Requires a running container engine daemon (`docker` or `podman`).

---

## 3. Reproducing Evasion Tests

The repository bundles standalone adversarial targets under [`targets/evasion/`](../targets/evasion/):

### 1. Delayed Beacon (`targets/evasion/delayed_beacon.py`)
Exercising with a single round misses the beacon:
```bash
mcp-behave audit --rounds 1 python targets/evasion/delayed_beacon.py
# Result: Clean (0 findings)
```
Exercising with multi-round probing catches the delayed behavior:
```bash
mcp-behave audit --rounds 3 python targets/evasion/delayed_beacon.py
# Result: HIGH finding - Undeclared network egress to 93.184.216.34:80
```

### 2. Stripped Subprocess (`targets/evasion/stripped_env.py`)
Demonstrates how child process spawning is captured while preserving host isolation:
```bash
mcp-behave audit python targets/evasion/stripped_env.py
```

Automated verification of the evasion suite runs via pytest:
```bash
pytest tests/test_evasion_suite.py
```
