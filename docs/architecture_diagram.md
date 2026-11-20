# `mcp-behave` System Architecture

This document illustrates the end-to-end architecture of **`mcp-behave wrap`**, demonstrating how it acts as an inline, zero-overhead, transparent security barrier between an MCP client and an untrusted MCP server.

---

## 1. High-Level System Architecture

```mermaid
flowchart TD
    subgraph ClientLayer["MCP Client Environment"]
        Client["MCP Client\n(Claude Desktop / Cursor / Claude Code)"]
    end

    subgraph ProxyLayer["mcp-behave wrap (Transparent Stdio Proxy)"]
        direction TB

        subgraph StdioPumps["Bidirectional Stdio Pipeline"]
            C2SPump["client_to_server_pump\n(NDJSON Framer)"]
            S2CPump["server_to_client_pump\n(Response Demuxer)"]
            StdinQueue["Single Serialized Writer\n(asyncio.Queue)"]
        end

        subgraph DefenseEngines["Security & Enforcement Engines"]
            Enforcer["PolicyEnforcer (M5)\n- Tool Call Interception\n- Schema Lock Validation\n- Synthetic JSON-RPC Errors"]
            Scanner["Content & Secret Scanner (M2b)\n- CanaryManager\n- Boyer-Moore Fast Pre-Filter\n- Inline Payload Redaction"]
            Manifest["ManifestTracker (M2)\n- TOFU Baseline Pinning\n- Active Synthetic Probes\n- Covert Drift Detection"]
            Attribution["AttributionEngine (M4)\n- In-Flight Tool Context\n- Concurrency Disambiguation\n- Safety Hint Policy Evaluator"]
        end

        subgraph Ingestion["Off-Hot-Path Telemetry Ingestion"]
            TraceServer["TracerServer\n(UNIX Datagram Socket in /tmp)\n(SO_RCVBUF = 256 KB)"]
            EventBus["EventBus\n(Async Decoupled Dispatch)"]
            Telemetry["TelemetryStore\n- SQLite Database (WAL mode)\n- NDJSON Audit Stream\n- Auto-Retention Cleanup"]
            LockfileMgr["Lockfile & Identity Manager (M3)\n- mcp-behave.lock.json\n- Package Identity Pinning"]
        end
    end

    subgraph TargetLayer["Monitored Child Environment (Isolated Process Group)"]
        direction TB
        SandboxWrapper["OS Sandbox Layer\n(Darwin Seatbelt / Linux Container)"]
        ChildProcess["Target MCP Server\n(Node.js / Python / Binary)"]
        Interposer["Native C Interposition Library\n(macos_tracer.dylib / linux_tracer.so)"]
    end

    %% Client Communication
    Client -- "Client Stdio (stdin)" --> C2SPump
    S2CPump -- "Forwarded JSON-RPC (stdout)" --> Client

    %% Inbound Request Path
    C2SPump --> Enforcer
    Enforcer -- "Permitted Request" --> StdinQueue
    Enforcer -. "Policy Violation Block (-32003)" .-> Client
    StdinQueue -- "Serialized NDJSON" --> ChildProcess

    %% Active Re-Verification Probes
    Manifest -. "Synthetic Probe Request" .-> StdinQueue
    ChildProcess -- "Server stdout" --> S2CPump
    S2CPump -. "Intercept Synthetic Probe Response" .-> Manifest

    %% Outbound Response Path
    S2CPump --> Scanner
    Scanner -- "Permitted / Redacted Response" --> Client
    Scanner -. "Canary Exfiltration Block (-32004)" .-> Client

    %% OS Layer Interposition Channel
    ChildProcess -. "Intercepted Syscalls\n(open, connect, spawn)" .-> Interposer
    Interposer -- "Non-blocking Datagrams\nsend(MSG_DONTWAIT)" --> TraceServer

    %% Sandboxing Boundary
    SandboxWrapper --> ChildProcess

    %% Telemetry & Correlation
    TraceServer --> Attribution
    C2SPump -. "Tool Call Start/End" .-> Attribution
    Attribution --> EventBus
    Enforcer --> EventBus
    Scanner --> EventBus
    Manifest --> EventBus
    EventBus --> Telemetry
    LockfileMgr --> Enforcer
    LockfileMgr --> Attribution
```

---

## 2. Request & Response Lifecycle Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Client as MCP Client
    participant Proxy as mcp-behave wrap
    participant Enforcer as PolicyEnforcer
    participant Target as Target MCP Server
    participant Tracer as C Interposer (Dylib)
    participant Kernel as OS Kernel / Telemetry

    %% Tool Call Flow
    Note over Client,Target: Phase 1: Tool Call & Policy Interception
    Client->>Proxy: JSON-RPC tools/call (e.g. read_doc)
    Proxy->>Enforcer: Evaluate tool authorization & arguments

    alt Tool Call Violates Lockfile / Unapproved
        Enforcer-->>Proxy: Blocked (unapproved_tool)
        Proxy-->>Client: Synthetic Error Response (-32003: Policy Violation)
        Note over Proxy,Target: Target server never receives the malicious request
    else Tool Call Approved
        Proxy->>Target: Serialized Line Forwarding via child stdin
        Proxy->>Kernel: AttributionEngine: on_tool_call_start(req_id, read_doc)
    end

    %% OS Execution & Interposition
    Note over Target,Kernel: Phase 2: Execution & Syscall Interposition
    Target->>Kernel: Syscall: open("/Users/.../.ssh/id_rsa", O_RDONLY)
    Kernel->>Tracer: Interposed libc open()
    Tracer-->>Proxy: Datagram "F /Users/.../.ssh/id_rsa" (via /tmp socket)
    Proxy->>Kernel: Attribution: detect sensitive_path_access (CRITICAL)

    %% Response & Redaction Flow
    Note over Target,Client: Phase 3: Response Sanitization & Delivery
    Target->>Proxy: JSON-RPC Result {"content": "AKIAIOSFODNN7EXAMPLE"}
    Proxy->>Enforcer: Scan output (Boyer-Moore + Secret Rules)

    alt Redaction Active (--redact)
        Enforcer->>Proxy: Sanitize payload to [REDACTED: aws_access_key_id]
        Proxy->>Client: Sanitized JSON-RPC Result
    else Canary Exfiltration Detected
        Enforcer-->>Proxy: Block response
        Proxy-->>Client: Synthetic Error Response (-32004: Leak Blocked)
    end
```

---

## 3. Evidence Tier Classification Model

```mermaid
graph TD
    classDef observed fill:#1b5e20,stroke:#4caf50,color:#fff;
    classDef correlated fill:#e65100,stroke:#ff9800,color:#fff;
    classDef structural fill:#0d47a1,stroke:#2196f3,color:#fff;
    classDef heuristic fill:#4a148c,stroke:#ab47bc,color:#fff;

    Root["mcp-behave Evidence Tiers"] --> TierObserved["1. OBSERVED\n(Direct Kernel / Protocol Ground Truth)"]:::observed
    Root --> TierCorrelated["2. CORRELATED\n(Disambiguated Multi-Source Events)"]:::correlated
    Root --> TierStructural["3. STRUCTURAL\n(Static Schema & Package AST Analysis)"]:::structural
    Root --> TierHeuristic["4. HEURISTIC\n(Statistical & Pattern Matching)"]:::heuristic

    TierObserved --> O1["Interposed Syscall (Single In-Flight Tool)"]
    TierObserved --> O2["Cryptographic Package Hash & Signature"]
    TierObserved --> O3["Deterministic Protocol Framing"]

    TierCorrelated --> C1["Syscall during Concurrent Tool Calls"]
    TierCorrelated --> C2["Background Server Thread Activity"]

    TierStructural --> S1["Schema Drift & Type Constraint Relaxation"]
    TierStructural --> S2["Annotation Weakening (readOnly -> false)"]

    TierHeuristic --> H1["Secret Pattern Detection (High Entropy)"]
    TierHeuristic --> H2["Prompt Injection Keyword Scoring"]
```
