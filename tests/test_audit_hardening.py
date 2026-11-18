import os
import tempfile
from pathlib import Path
from mcp_behave.analyze import analyze, interesting_file, is_sensitive_path
from mcp_behave.report import build_findings, _claims_local_operation
from mcp_behave.probe import synth_args


def test_sensitive_path_detection_and_normalization():
    # Noise filter evasion test: /tmp/lib/../../.ssh/id_rsa
    evasion_path = "/tmp/lib/../../home/user/.ssh/id_rsa"
    is_sens, matched = is_sensitive_path(evasion_path)
    assert is_sens is True
    assert "id_rsa" in matched or ".ssh" in matched
    # interesting_file must NEVER drop a sensitive path even with /lib/ in raw string
    assert interesting_file(evasion_path) is True

    # Traversal targeting .env
    env_traversal = "/var/log/../../app/.env"
    is_sens, matched = is_sensitive_path(env_traversal)
    assert is_sens is True
    assert matched == ".env"
    assert interesting_file(env_traversal) is True

    # Standard confidential files
    assert is_sensitive_path("/etc/shadow")[0] is True
    assert is_sensitive_path("/etc/shadow\\0")[0] is True
    assert is_sensitive_path("/home/user/.aws/credentials")[0] is True
    assert is_sensitive_path("/home/user/.kube/config")[0] is True
    assert is_sensitive_path("/home/user/.netrc")[0] is True
    assert is_sensitive_path("/root/.docker/config.json")[0] is True
    assert is_sensitive_path("/var/run/secrets/kubernetes.io/serviceaccount/token")[0] is True
    assert is_sensitive_path("/home/user/.ssh/id_ed25519")[0] is True


def test_false_positive_avoidance():
    # Files containing substrings like 'credentials' or 'environment' as partial names
    assert is_sensitive_path("/app/services/my_credentials_helper.py")[0] is False
    assert is_sensitive_path("/app/environment.py")[0] is False
    assert is_sensitive_path("/usr/lib/python3.12/environment.py")[0] is False
    assert is_sensitive_path("/var/www/static/credentials_banner.png")[0] is False

    # Noise paths that are not sensitive should be filtered
    assert interesting_file("/usr/lib/x86_64-linux-gnu/libc.so") is False
    assert interesting_file("/app/.venv/lib/python3.12/site-packages/urllib3/util.py") is False
    assert interesting_file("/usr/share/zoneinfo/UTC") is False


def test_claims_local_operation():
    # Strict phrases indicate local operation
    assert _claims_local_operation("This tool operates strictly locally without internet access.") is True
    assert _claims_local_operation("Fully offline only mode note editor.") is True
    assert _claims_local_operation("Local-only filesystem manager with zero external telemetry.") is True

    # Casual mention of 'local' (e.g. local cache, local variable, local time) should NOT claim local-only operation
    assert _claims_local_operation("Queries the remote API and caches results in local memory.") is False
    assert _claims_local_operation("Fetch web articles and store in a local sqlite database.") is False
    assert _claims_local_operation("Converts UTC timestamp to local timezone.") is False


def test_scope_evaluation_local_claims_precision():
    manifest = {
        "server_cmd": ["python", "server.py"],
        "tools": [
            {
                "name": "fetch_url",
                "description": "Fetches a URL and caches to local disk for performance.",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
            }
        ],
    }
    profile = {
        "files_opened": [],
        "files_written": [],
        "network_connects": ["93.184.216.34:80"],
        "unix_sockets": [],
        "subprocesses": [],
    }

    findings = build_findings(manifest, profile, resolve_dns=False, persist_rugpull=False)
    net_findings = [f for f in findings if "network egress" in f[1]]
    assert len(net_findings) == 1
    # Should NOT be promoted to HIGH because 'local disk' is not a local-only claim
    assert net_findings[0][0] == "INFO"
    assert "claims local/offline operation" not in net_findings[0][1]


def test_read_vs_write_sensitive_files():
    manifest = {"server_cmd": ["python", "server.py"], "tools": []}
    profile = {
        "files_opened": ["/home/user/.ssh/id_rsa", "/home/user/.ssh/authorized_keys"],
        "files_written": ["/home/user/.ssh/authorized_keys"],
        "network_connects": [],
        "unix_sockets": [],
        "subprocesses": [],
    }

    findings = build_findings(manifest, profile, resolve_dns=False, persist_rugpull=False)
    high_findings = [f[1] for f in findings if f[0] == "HIGH"]

    assert any("read a sensitive path: /home/user/.ssh/id_rsa" in h for h in high_findings)
    assert any("modified or wrote to a sensitive path: /home/user/.ssh/authorized_keys" in h for h in high_findings)


def test_unix_domain_sockets_and_container_escape():
    manifest = {"server_cmd": ["python", "server.py"], "tools": []}
    profile = {
        "files_opened": [],
        "files_written": [],
        "network_connects": [],
        "unix_sockets": ["/var/run/docker.sock", "/tmp/app.sock"],
        "subprocesses": [],
    }

    findings = build_findings(manifest, profile, resolve_dns=False, persist_rugpull=False)
    sock_findings = [f for f in findings if "socket" in f[1]]

    # docker.sock should be HIGH severity
    docker_f = next(f for f in sock_findings if "docker.sock" in f[1])
    assert docker_f[0] == "HIGH"
    assert "container runtime control socket" in docker_f[1]

    # /tmp/app.sock should be INFO severity
    app_f = next(f for f in sock_findings if "/tmp/app.sock" in f[1])
    assert app_f[0] == "INFO"


def test_analyze_native_parser_records():
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        trace_path = tf.name
        tf.write("F /etc/shadow\n")
        tf.write("W /etc/shadow\n")
        tf.write("F /tmp/lib/../../home/user/.ssh/id_rsa\n")
        tf.write("F /usr/lib/libc.so\n")  # noise
        tf.write("N 198.51.100.1 8080\n")
        tf.write("U /var/run/docker.sock\n")
        tf.write("X /usr/bin/python3\n")
        tf.write("M CALL_START test\n")
        tf.flush()

    try:
        prof = analyze(trace_path)
        assert "/etc/shadow" in prof["files_opened"]
        assert "/etc/shadow" in prof["files_written"]
        # Path normalized and sensitive path preserved
        assert "/home/user/.ssh/id_rsa" in prof["files_opened"]
        # Noise dropped
        assert "/usr/lib/libc.so" not in prof["files_opened"]
        assert "198.51.100.1:8080" in prof["network_connects"]
        assert "/var/run/docker.sock" in prof["unix_sockets"]
        assert "/usr/bin/python3" in prof["subprocesses"]
    finally:
        if os.path.exists(trace_path):
            os.remove(trace_path)


def test_synth_args_diversity():
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "endpoint": {"type": "string", "format": "uri"},
            "count": {"type": "integer"},
            "category": {"type": "string", "enum": ["alpha", "beta", "gamma"]},
        },
    }
    r0 = synth_args(schema, round_idx=0)
    r1 = synth_args(schema, round_idx=1)
    r2 = synth_args(schema, round_idx=2)

    # Valid values produced
    assert isinstance(r0["query"], str)
    assert r0["query"] != "probe-canary"  # Non-obvious canary
    assert r0["endpoint"].startswith("http")
    assert r0["category"] == "alpha"

    # Diverse across rounds
    assert r1["category"] == "beta"
    assert r2["category"] == "gamma"
    assert r0["query"] != r1["query"]
    assert r0["count"] != r1["count"]
