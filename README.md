<p align="center">
  <img src="assets/logo.png" alt="mcp-behave logo" width="96" />
</p>

# mcp-behave

**Runtime behavioral auditing and monitoring for Model Context Protocol (MCP) servers.**

[![CI](https://github.com/navid72m/mcp-behave/actions/workflows/ci.yml/badge.svg)](https://github.com/navid72m/mcp-behave/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-behave.svg)](https://pypi.org/project/mcp-behave/)
[![npm](https://img.shields.io/npm/v/mcp-behave.svg)](https://www.npmjs.com/package/mcp-behave)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-listed-blue)](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.navid72m/mcp-behave)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/mcp-behave?period=total&units=ABBREVIATION&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/mcp-behave)

[![npm downloads](https://img.shields.io/npm/dw/mcp-behave)](https://www.npmjs.com/package/mcp-behave)


mcp-behave is a **CLI-first security tool** for checking what an MCP server actually does—not only what its tool descriptions say it can do. It actively exercises a server's advertised capabilities, observes selected runtime activity, checks protocol metadata and responses, and compares behavior with saved baselines.

It also provides `mcp-behave wrap`, a stdio proxy for monitoring MCP traffic while an AI client uses a server. mcp-behave is CLI-first: it provides terminal, JSON, and SARIF output and does not ship a built-in graphical dashboard.
<p align="center">
  <a href="demo.gif">
    <img src="demo.gif" alt="mcp-behave demo" width="100%">
  </a>
</p>

## v0.5.6 Performance & Reliability

| **6.8× higher throughput** | **89.5% lower median latency** |
|---|---|
| **101,052 successful endurance-test requests** | **467 passing product tests** |

In a 10-repetition alternating paired comparison (`v0.5.5` vs `v0.5.6`, concurrent `--enforce --redact`, `n=200`, `c=16`, macOS arm64 with native DYLD tracing active), median throughput rose from `185.4` to `1,266.2` RPS while `p50` latency dropped from `95.062` ms to `10.003` ms (`-89.5%`) and `p95` dropped from `167.835` ms to `20.851` ms (`-87.6%`). In a 1-hour bounded-retention soak (`enforce_redact`), `mcp-behave wrap` completed `101,052` requests with `0` failures, `0` timeouts, `0` secret leaks across `2,833` checks, peak RSS of `81.55 MiB`, and `18 -> 19` open FDs (full-run telemetry completeness is `UNVERIFIED` under bounded retention due to intentional pruning). These measurements apply to the tested concurrent stdio proxy workload and environments; see [BENCHMARK.md](BENCHMARK.md) and [v0.5.6 benchmark evidence](benchmarks/results/v0.5.6/README.md) for full details and limitations.

![v0.5.6 vs v0.5.5 concurrent enforcement and redaction throughput](benchmarks/results/v0.5.6/charts/throughput_comparison.svg)

## Why mcp-behave?

An MCP server can advertise a harmless tool while its implementation performs unexpected operations. For example, a tool described as a local document formatter might also read a credential file or attempt an outbound network connection.

mcp-behave compares two views of a server:

- **Declared behavior:** tools, input schemas, annotations, resources, prompts, and metadata exposed over MCP.
- **Observed behavior:** selected file, network, and process activity captured while the server is exercised or monitored.

The goal is to make unexpected behavior visible for review. A clean audit is not proof that a server is safe; it means no covered issue was observed in the tested scenarios.

## What it checks

- **Runtime activity:** selected filesystem operations, network connection attempts, and subprocess launches.
- **MCP metadata:** tool definitions, schemas, descriptions, annotations, resources, prompts, and manifest changes.
- **Content risks:** prompt-injection patterns, invisible or bidirectional Unicode characters, terminal escape sequences, and external Markdown/HTML image references in tool output.
- **Sensitive data:** known secret patterns and configured canary tokens in inspected payloads.
- **Client configuration:** hard-coded credentials, broad filesystem mounts, shell wrappers, and unpinned package commands in supported MCP client configuration files.

Findings describe observed behavior and potential risks; they are not automatic accusations of malicious intent.

## Install

The simplest option is to run with [`uvx`](https://docs.astral.sh/uv/):

```bash
uvx mcp-behave --version
```

Or install the Python package:

```bash
python -m pip install mcp-behave
mcp-behave --version
```

An npm package is also available:

```bash
npm install -g mcp-behave
mcp-behave --version
```

**About the npm package:** it is a Node.js launcher for the Python implementation, not a separate JavaScript auditing engine. It requires Node.js 16+ and a Python 3 environment; it uses `uvx` or `pipx` when available.

## Quick start: audit an MCP server

### Important: audits execute server code

An audit is active testing, not passive package inspection. The probe may call tools and read resources/prompts, and those operations can have side effects. **Do not run an unfamiliar server against your normal host environment without isolation.**

The audit sandbox defaults to `none`. Passing `--sandbox auto` asks `mcp-behave` to use Podman or Docker when available, **but it does not guarantee isolation**: if neither container runtime responds, the audit falls back to unsandboxed local execution. Container runs default to `--network=none` with the default `python:3.12-slim` or `node:20-slim` image and only the working directory mounted read-only at `/workspace`, so commands that download packages (`npx -y`, `uvx`) or reference host paths outside the working directory require pre-populated images or an already isolated disposable environment. When you require container isolation, run from a disposable directory with synthetic inputs and specify an explicit runtime (`--sandbox docker` or `--sandbox podman`) with a command and image that can run offline against `/workspace`.

Pass a stdio server command to run a one-shot audit. The `audit` prefix is optional. Running bare `mcp-behave` starts the tool's MCP service.

```bash
uvx mcp-behave python -m my_mcp_server
mcp-behave audit python -m my_mcp_server
```

Inside an already isolated disposable environment with synthetic fixture files, you can also audit a local server launched with `npx` or `uvx`:

```bash
uvx mcp-behave npx -y @modelcontextprotocol/server-filesystem /tmp/mcpb-fixture
uvx mcp-behave uvx mcp-server-git
```

The probe starts the server, initializes a session, discovers tools, resources, and prompts, and exercises advertised capabilities with synthesized inputs. It can call tools, read resources, and fetch prompts. Even an untraced audit executes server code and can cause side effects. The default audit environment redirects home and configuration paths to a temporary canary home and filters environment variables by name. An unsandboxed target still has the host access of the account that launched it.

With `--transport sse` or `--transport streamable-http`, supply one URL. The audit connects to the running remote server and exercises it for manifest and protocol analysis, without local OS tracing of the server.

## Runtime monitoring with `wrap`

`mcp-behave wrap` runs between an AI client and a stdio MCP server. The client sends MCP messages to the proxy; the proxy forwards them to the target while monitoring protocol traffic and selected operating-system activity.

```text
AI client  <---- stdio / JSON-RPC ---->  mcp-behave wrap  <---- stdio / JSON-RPC ---->  MCP server
                                                 |
                                                 +-- protocol monitoring
                                                 +-- runtime tracing (when available)
                                                 +-- policy checks, scanning, and telemetry
```

Start the inline proxy in monitoring mode with a controlled fixture:

```bash
uvx mcp-behave wrap \
  --server my-server \
  -- python -m my_mcp_server
```

By default, `wrap` monitors protocol traffic and can issue periodic synthetic `tools/list` requests to recheck the manifest. It publishes observed OS policy violations and emits alerts after the activity is observed. Protocol enforcement, response redaction, and OS sandboxing are independently configurable.

With `--enforce`, wrap requires a valid multi-server lockfile entry matching the selected server ID before launching the child, even with `--fail-mode fail-open`. With the default `fail-closed` mode, the inline filter rejects unapproved `tools/call` requests (including Unicode-escaped method names), JSON-RPC batch arrays, malformed JSON, and non-object payloads before forwarding, and replaces covered server responses containing a detected canary, critical secret, batch array, or malformed JSON with a JSON-RPC error. `fail-open` skips those inline blocks. `wrap` also bounds individual JSON-RPC messages and stdin queueing to 16 MiB (256 items max in queue; one oversized message up to 16 MiB is permitted when empty) and applies bounded process-group shutdown. Monitoring can still report findings.

`--redact` replaces detected secret and canary values in inspected server JSON payloads that reach the redaction step. Replacing or redacting a response leaves any OS side effects that already happened in place. Stderr, files, and network traffic are outside this protocol filter.

### Create and use a behavioral lockfile

Generate or update the multi-server lockfile from an audit:

```bash
uvx mcp-behave --lock --server-id my-server python -m my_mcp_server
```

This writes `mcp-behave.lock.json`. Review the generated baseline before treating it as approved. Then run the server through `wrap` with enforcement enabled:

```bash
uvx mcp-behave wrap \
  --server my-server \
  --lockfile mcp-behave.lock.json \
  --enforce \
  -- python -m my_mcp_server
```

To review a manifest change observed by `wrap` and approve it into the lockfile:

```bash
uvx mcp-behave approve --server my-server
```

Useful `wrap` options:

| Option | Purpose |
| --- | --- |
| `--enforce` | Enforce lockfile-based tool policy checks. Requires a valid matching entry in `mcp-behave.lock.json`. |
| `--redact` | Replace detected sensitive values in inspected server responses. |
| `--canary TOKEN` / `--canary-file PATH` | Watch for configured canary values in inspected traffic. |
| `--sandbox auto` | Request the platform-appropriate sandbox backend. |
| `--no-trace` | Disable native runtime tracing and retain protocol-level monitoring. |
| `--no-reverify` | Disable periodic synthetic `tools/list` re-verification. |

`wrap` is an stdio proxy; it does not turn a remote HTTP MCP connection into a locally traced process.

## Other commands

| Command | Use it for |
| --- | --- |
| `mcp-behave lint manifest.json` | Static checks of a manifest or tool-definition JSON without starting a server. |
| `mcp-behave scan-configs` | Find MCP servers in supported local client configuration files and inspect configuration risks. |
| `mcp-behave audit-configs` | Discover configured servers and run audits against them. This actively launches and exercises targets. |
| `mcp-behave inspect <command>` | View a correlated timeline of MCP messages and observed runtime events; can also inspect a prior output directory. |
| `mcp-behave serve` | Expose mcp-behave's audit and inspection tools through an MCP server interface. |
| `mcp-behave install` / `status` / `uninstall` | Add, inspect, or remove wrapper entries in supported local AI client configurations. |

### CI and machine-readable output

Use JSON or SARIF output for automation and code-scanning workflows:

```bash
uvx mcp-behave --json --fail-on high python -m my_mcp_server
uvx mcp-behave --sarif python -m my_mcp_server > mcp-behave.sarif
```

The default output directory is `/tmp/mcp_behave_out`. Set `--out-dir` to choose another location. Exit codes for an audit are `0` for no findings at or above the selected threshold, `3` when the threshold is met, `2` for a tracing/setup failure, and `1` for other errors.

### Legacy single-server baseline workflow

The `init` and `check` commands maintain the earlier single-server `mcp-behave.lock` format:

```bash
uvx mcp-behave init python -m my_mcp_server
uvx mcp-behave check python -m my_mcp_server
```

This is separate from the multi-server `mcp-behave.lock.json` used by `wrap`. Keep the two lockfile formats distinct.

## Runtime tracing and platform notes

- **Audit on macOS:** uses a dynamic interposer via `DYLD_INSERT_LIBRARIES` when available. Hardened or specially signed targets can reject injection, which can cause launch failure.
- **Audit on Linux:** automatic selection tries an `LD_PRELOAD` interposer first, then `strace` if installed. `strace` has its own coverage and permission requirements. With no eligible tracer, the local target is still exercised untraced. `--no-trace` explicitly selects that path when no container is active. Building a native interposer requires a C compiler.
- **Wrap on macOS and Linux:** uses the platform's dynamic interposer and reports tracing status (`active`, `partial`, or `disabled`) in telemetry. It requires a handshake from the launched PID; if the launcher times out while descendants report ready, it emits a `blind_spot` alert and classifies tracing as `partial` (`descendant_only`). With a sandbox command, wrap attempts interposition on the launcher. A handshake or an active container status provides no evidence of tracing coverage inside the container.
- **Native Windows:** ordinary audit tracer selection has no native Windows backend. Wrap tracing reports `unsupported_os` when enabled, and wrap `--sandbox auto` selects no backend. Explicit container use depends on a usable runtime and successful launch. Wrap also relies on asyncio stdio pipe integration, new sessions, and POSIX process-group signaling and cleanup, so the untraced path does not establish native Windows support.

### Explicit tracer selection

`--tracer auto` (the default) selects the best available platform tracer. `--tracer none` or `--no-trace` explicitly requests untraced execution. Requesting an explicit unavailable backend (such as `--tracer ebpf` on macOS or unsupported Linux kernels, `--tracer preload` on macOS, or `--tracer strace` without `strace` installed) fails with exit code `2` before launching a local target. Remote audits (`sse`/`streamable-http`) and active container sandboxes (`--sandbox`) do not use host syscall tracers.

### OS sandbox selection and defaults

Both audit and wrap default to `--sandbox none`.

- **Audit:** `--sandbox auto` checks for responsive Podman first and then Docker. If neither responds, the audit can continue locally without a container. Explicit `--sandbox docker` or `--sandbox podman` uses that runtime name directly, so launch failures can surface. The initial banner labels the requested sandbox before availability is known. An active audit container bypasses host syscall tracing and records `sandbox-<runtime>` as the tracer label.
- **Wrap:** `--sandbox auto` selects Seatbelt on macOS and a container on Linux. Explicit choices are `seatbelt` and `container`. For a selected backend, unavailability or an error preparing the command aborts under the default `fail-closed` mode. Under `fail-open`, those cases can launch the original command with sandbox status disabled. On unsupported platforms, `auto` prepares the original command with disabled sandbox status even under `fail-closed`. These rules govern preparation. A launch error or a failure after the wrapped command starts does not trigger an unsandboxed retry. Active sandbox telemetry describes the prepared command.
- **Container defaults:** no networking, a read-only bind mount of the current working directory at `/workspace`, all capabilities dropped, and no new privileges. Audit can override the network mode. When supplied with an existing canary home directory, the command builder mounts it read-write at `/canary_home` and redirects home and configuration variables there. Audit supplies its temporary canary home by default. Wrap's container preparation does not supply one.

### Seatbelt lockfile hints

Seatbelt starts with an allow-default profile. Wrap passes the selected server's lockfile entry to the profile generator even when protocol enforcement is off. With no matching entry or no tools, the profile adds neither write nor outbound restrictions.

For a nonempty tool set, aggregation considers only tools with nonempty annotation records. It adds write restrictions when every considered tool has `readOnlyHint=true`, with exceptions for `/tmp`, `/private/tmp`, `/dev/null`, `/dev/zero`, and `/dev/tty`. Any considered tool with `openWorldHint=true` leaves outbound networking unrestricted by the profile. When all considered tools are closed-world, the profile restricts outbound networking to loopback.

Generated lockfiles fill in missing hints with `readOnlyHint=false` and `openWorldHint=true`. A tool with both defaults contributes to both permissive outcomes, so an active Seatbelt profile may leave writes and outbound networking unrestricted. Absent or empty legacy annotation records are skipped. If tools exist but all their annotation records are absent or empty, the empty `all` and `any` checks add both restrictions.

### Security and coverage limitations

Native interposers observe selected dynamically linked libc calls. Direct syscalls, statically linked targets, and other uninstrumented operations may escape observation. Behavior tied to a particular input, environment, time, or external condition may be outside the scenarios tested. For a controlled disposable fixture, use multiple probe rounds and adversarial input testing where appropriate:

```bash
uvx mcp-behave --probe-rounds 3 --fuzz python -m my_mcp_server
```

Clean reports, trace and sandbox statuses, redaction, and baselines provide evidence bounded by the configuration and observations. Review baseline changes before approving them. In `wrap`, PID-only tracer tracking is best-effort (`best_effort_pid_only`), parser gaps or queue drops degrade attribution to `correlated` until a trusted lifecycle resync, SQLite row caps bound logical row counts rather than physical disk size without `VACUUM`, bounded-retention runs leave full-run completeness `UNVERIFIED`, Linux validation was executed in ARM64 containers, and post-shutdown orphan checks are point-in-time `ps` snapshots.

## Evaluation

1. Use a disposable environment and a controlled local fixture. Keep real credentials, production data, live client configurations, and sensitive host mounts out of the environment. Wrap starts from the parent environment, so launch the client and wrapper with a synthetic environment too.
2. Audit from a scratch working directory containing only fixture files. For a container trial, confirm a responsive runtime and a fixture command that can run in the image. Use an explicit runtime if the trial requires a container. Keep the default disabled container network and leave `--unsafe-host` off.
3. Use synthetic inputs and canaries. Compare audit findings across selected scenarios, then use a disposable stdio client to exercise wrap monitoring, enforcement with a reviewed fixture lockfile, and optional redaction. Inspect the reported trace and sandbox statuses along with the actual responses and expected fixture effects.

The repository includes benchmark corpora and reports covering paired benign/malicious server fixtures, multi-server authorization scenarios, deterministic runtime-policy tests, and audits of reference MCP servers. The README intentionally keeps detailed tables out of the getting-started path:

- [Benchmark methodology and results](BENCHMARK.md)
- [v0.5.6 performance and endurance validation](benchmarks/results/v0.5.6/README.md) (10-rep paired concurrent enforcement+redaction comparison, macOS and Linux 5-minute lossless/bounded soaks, and 1-hour endurance validation)
- [CrossMCP-Bench report](docs/benchmarks/crossmcp_bench_report.md)
- [MCP-GuardBench report](docs/benchmarks/guardbench_report.md)
- [Pluto MCP Visibility report](docs/benchmarks/pluto_visibility_bench.md)
- [Official reference-server audit](docs/benchmarks/official_servers_audit.md)

These are project-maintained evaluations on specified corpora and fixtures. Results are corpus-specific; they are not independent certification or a guarantee that an arbitrary MCP server is safe.

## Documentation

- [Architecture and data flow](ARCHITECTURE.md)
- [Detection rules and observation matrix](docs/detection_matrix.md)
- [Technical whitepaper](docs/mcp_behave_technical_whitepaper.pdf)
- [Research article: Auditing real-world MCP servers](https://www.navidmirnouri.com/blog/auditing-mcp-servers-with-mcp-behave.html)
- [Roadmap](ROADMAP.md)
- [Security policy](SECURITY.md)
- [Community feedback and issue tracker](https://github.com/navid72m/mcp-behave/issues)

## Development

```bash
git clone https://github.com/navid72m/mcp-behave.git
cd mcp-behave
python -m pip install -e ".[test]"
pytest -v
```

The CI workflow runs tests on Linux and macOS. Contributions, bug reports, false-positive reports, and suggestions are welcome through [GitHub Issues](https://github.com/navid72m/mcp-behave/issues).

## License

MIT. See [LICENSE](LICENSE).

<!-- mcp-name: io.github.navid72m/mcp-behave -->
