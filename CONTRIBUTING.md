# Contributing to mcp-behave

Thank you for your interest in contributing to `mcp-behave`! We welcome contributions that improve observation trustworthiness, expand behavioral regression testing, harden sandbox defenses, and reduce false positives.

---

## 1. Development Setup

`mcp-behave` uses [`uv`](https://github.com/astral-sh/uv) for fast, deterministic Python environment management.

### Prerequisites
- Python 3.10, 3.11, or 3.12
- C compiler (`clang` on macOS; `gcc` or `clang` on Linux)
- `uv` (`curl -LsSf https://astral.sh/uv/install.sh | sh` or `brew install uv`)

### Clone and Install
```bash
git clone https://github.com/navid72m/mcp-behave.git
cd mcp-behave

# Install dependencies and sync virtual environment
uv sync
```

---

## 2. Running Tests

Run the full test suite using `pytest`:
```bash
uv run pytest
```

Run tests matching specific keywords or files:
```bash
uv run pytest tests/test_production_hardening.py
uv run pytest -k "lockfile or canary"
```

---

## 3. Architecture & Codebase Map

- `src/mcp_behave/probe.py`: Process spawning, canary `$HOME` isolation, environment scrubbing, argument synthesis, and tracer injection.
- `src/mcp_behave/macos_tracer.c`: macOS `DYLD_INSERT_LIBRARIES` dynamic interposition library.
- `src/mcp_behave/linux_tracer.c`: Linux `LD_PRELOAD` shared library interposer.
- `src/mcp_behave/analyze.py`: Behavioral trace log parser (native binary markers and strace parsing).
- `src/mcp_behave/lockfile.py`: Behavioral lockfile generator (`init`) and CI regression diffing engine (`check`).
- `src/mcp_behave/report.py`: Declared-vs-observed analysis, audit confidence calculation, human CLI and JSON output.
- `src/mcp_behave/scorecard.py`: mcp-behave 0–100 security scoring and category breakdowns.
- `src/mcp_behave/server.py`: FastMCP interface exposing `audit_server`, `inspect_manifest`, and `scan_client_configs`.

---

## 4. Behavioral Lockfiles in Development

When testing server targets:
```bash
# Generate baseline lockfile
uv run mcp-behave init python targets/honest_server.py --lockfile test.lock

# Verify compliance
uv run mcp-behave check python targets/honest_server.py --lockfile test.lock
```

---

## 5. Adding Evasion & Test Targets

When adding new test servers to `targets/`:
1. Keep fixtures minimal and dependency-free.
2. Honest targets must score **100% clean with zero findings**.
3. Malicious/evasive targets must clearly demonstrate a specific behavior (e.g. symlink traversal, delayed network beacon, secret harvesting).
4. Add corresponding assertions to `tests/test_fixture_servers.py` or `tests/test_production_hardening.py`.

---

## 6. Pull Request Guidelines

1. **Tests pass:** Ensure `uv run pytest` runs clean.
2. **Preserve comments & docs:** Maintain existing docstrings and explanatory comments.
3. **No host contamination:** New tests must never access real user credentials or host files. Always rely on canary isolation or `tmp_path`.
4. **Clean commits:** Use conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`).
