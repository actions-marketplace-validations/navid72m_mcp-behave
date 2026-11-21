# Instructions for Implementer Agent: v0.5.3 Clean Tag & Publish

## Status Update

### 1. Linux CI Matrix is 100% Green!
GitHub Actions CI Run `#91` (`44857143849`) for commit `6e80264`:
- `build`: **PASSED** (ID 136701887940)
- `test (ubuntu-latest, 3.10)`: **PASSED** (ID 136701888156)
- `test (ubuntu-latest, 3.11)`: **PASSED** (ID 136701888347)
- `test (ubuntu-latest, 3.12)`: **PASSED** (ID 136701888300)
- Local test suite: **318/318 PASSED** in 19.65s.

All 8 must-fix security items, C tracer hooks, probe generation isolation, manifest trust, byte prefilter, and hardened runtime checks are verified and green.

### 2. Publish Blocker: Duplicate Version `0.5.2` in MCP Registry
In GitHub Actions Run `#44857150983`:
- `publish-npm`: **PASSED**
- `publish-pypi`: **PASSED**
- `publish-mcp-registry`: **FAILED** with:
  ```
  Error: publish failed: server returned status 400: {"title":"Bad Request","status":400,"detail":"Failed to publish server","errors":[{"message":"invalid version: cannot publish duplicate version: io.github.navid72m/mcp-behave@0.5.2 already exists"}]}
  ```
Because `0.5.2` was already registered in the MCP Registry during the first tag push, the registry strictly rejects duplicate version publications.

---

## Required Steps to Finalize v0.5.3

### Step 1: Bump Version to `0.5.3`
Update `0.5.2` -> `0.5.3` in:
1. `pyproject.toml` (`version = "0.5.3"`)
2. `package.json` (`"version": "0.5.3"`)
3. `server.json` (all 3 occurrences of `"version": "0.5.3"`)
4. `src/mcp_behave/__init__.py` (`__version__ = "0.5.3"`)
5. `ROADMAP.md` (record `v0.5.3` release)
6. `uv.lock` (`uv lock`)

### Step 2: Commit and Tag
```bash
git add pyproject.toml package.json server.json src/mcp_behave/__init__.py uv.lock ROADMAP.md instructions/ report/
git commit -m "release: v0.5.3 with all security remediations and green Linux CI"
git tag v0.5.3
git push origin main --tags
```

### Step 3: Verify Publishing
Monitor `gh run list --limit 3` to verify that `publish.yml` for `v0.5.3` completes with all jobs passing (`✓` for PyPI, npm, and MCP registry).
