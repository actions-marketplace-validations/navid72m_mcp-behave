"""Phase 1 analyzer: parse trace log into a structured behavioral profile.
Supports native dynamic libc interposition (macOS DYLD / Linux LD_PRELOAD) and strace.
Pure observation -- lists what the server touched without allowlists or arbitrary verdicts."""
import json
import os
import re
import sys
from pathlib import Path

# Regexes for strace / dtruss output
STRACE_OPEN = re.compile(r'\b(?:openat|open|creat)\((?:[^,)]+,\s*)?"([^"]+)"(?:,\s*([A-Za-z0-9_|]+))?')
STRACE_NET = re.compile(
    r'(?:connect|sendto)\(\d+,\s*(?:[^,]+,\s*\d+,\s*\d+,\s*)?\{sa_family=AF_INET6?,\s*'
    r'sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet_(?:addr|pton)\((?:[^,]+,\s*)?"([^"]+)"'
)
STRACE_UNIX = re.compile(
    r'(?:connect|sendto)\(\d+,\s*(?:[^,]+,\s*\d+,\s*\d+,\s*)?\{sa_family=AF_UNIX,\s*sun_path=(?:@"([^"]+)"|"([^"]+)")'
)
STRACE_EXEC = re.compile(r'\b(?:execve|execveat)\((?:[^,)]+,\s*)?"([^"]+)"')


def _clean_path(p: str) -> str:
    # dtruss appends a literal `\0` to dereferenced C strings (e.g. "/etc/hosts\0").
    # Strip trailing literal \0 or null byte so both tracers yield clean paths.
    if p.endswith("\\0"):
        p = p[:-2]
    if p.endswith("\0"):
        p = p[:-1]
    return p


def is_sensitive_path(path: str) -> tuple[bool, str]:
    """Determine if a normalized filesystem path targets confidential credentials or system files.
    Returns (is_sensitive, reason_snippet). Matches whole path components and filenames to avoid
    false positives (e.g. 'environment.py' or 'my_credentials_helper.py' will NOT match)."""
    if not path:
        return False, ""

    clean = _clean_path(path.strip())
    norm = os.path.normpath(clean)
    parts = [p.lower() for p in Path(norm).parts]

    # Exact system file targets
    if norm == "/etc/shadow" or norm.endswith("/etc/shadow"):
        return True, "/etc/shadow"
    if norm == "/etc/master.passwd" or norm.endswith("/etc/master.passwd"):
        return True, "/etc/master.passwd"

    # Confidential directory containers
    if ".ssh" in parts:
        return True, ".ssh"
    if ".aws" in parts:
        return True, ".aws"
    if ".kube" in parts:
        return True, ".kube"
    if ".netrc" in parts:
        return True, ".netrc"

    # Docker credentials
    if ".dockercfg" in parts or (".docker" in parts and any(c.startswith("config") for c in parts)):
        return True, ".docker/config"

    # Private keys
    key_needles = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa")
    for part in parts:
        if any(part == k or part.startswith(k + ".") or part.startswith(k + "_") for k in key_needles):
            return True, part

    # Environment secret files: .env, .env.local, .env.production, etc. (exact part or starts with .env.)
    for part in parts:
        if part == ".env" or part.startswith(".env."):
            return True, part

    # Credentials files: credentials, credentials.json, credentials.yaml, credentials.ini
    for part in parts:
        if part in ("credentials", "credentials.json", "credentials.yaml", "credentials.ini", "credentials.xml"):
            return True, part

    # Kubernetes service account secrets
    if "secrets" in parts and "kubernetes.io" in parts:
        return True, "kubernetes.io/token"

    # GPG private keys and keyrings
    if ".gnupg" in parts:
        return True, ".gnupg"
    for part in parts:
        if part in ("secring.gpg", "trustdb.gpg", "pubring.kbx"):
            return True, part

    # Package manager and git credentials
    for part in parts:
        if part in (".npmrc", ".pypirc", ".git-credentials", ".gitconfig"):
            return True, part

    # Cloud provider CLI configurations
    if ".azure" in parts:
        return True, ".azure"
    if "gcloud" in parts:
        for part in parts:
            if part in ("credentials.db", "application_default_credentials.json", "access_tokens.db", "properties"):
                return True, f"gcloud/{part}"
        if any("gcloud" in p for p in parts):
            return True, "gcloud"

    # Browser profile secrets and credential databases
    browser_dirs = ("google/chrome", "chromium", "firefox", "bravesoftware", "brave-browser", "safari")
    browser_secret_files = ("login data", "cookies", "cookies.sqlite", "key4.db", "logins.json", "web data")
    norm_lower = norm.lower()
    if any(b in norm_lower for b in browser_dirs):
        for part in parts:
            if part in browser_secret_files:
                return True, f"browser/{part}"

    # Generic private key file extensions
    base = Path(norm).name.lower()
    if base.endswith((".pem", ".key")) and any(s in base for s in ("private", "id_", "secret", "server", "cert")):
        return True, base

    return False, ""


SYSTEM_NOISE_PREFIXES = (
    "/usr/", "/lib/", "/lib64/", "/proc/", "/sys/", "/dev/",
    "/etc/ld.so", "/opt/homebrew/", "/nix/store/",
)

RUNTIME_DIR_COMPONENTS = {
    "site-packages", "__pycache__", ".venv", "node_modules",
    ".cache", ".nvm", ".npm", ".pyenv", ".cargo", ".rustup", "dist-info",
}

NOISE_SUFFIXES = (".pyc", ".so", ".py._pth", ".node", ".dylib", ".o", ".a")
NET_NOISE = ("127.0.0.1", "::1", "0.0.0.0")

# Allow ad-hoc noise substrings per-run without editing source, for unfamiliar layouts.
_EXTRA = tuple(s for s in os.environ.get("PROBE_NOISE_EXTRA", "").split(":") if s)


def interesting_file(path: str) -> bool:
    if not path or not path.strip():
        return False

    clean = _clean_path(path.strip())
    norm = os.path.normpath(clean)

    # Sensitive targets are ALWAYS interesting -- never filtered as noise, defeating traversal evasions
    is_sens, _ = is_sensitive_path(norm)
    if is_sens:
        return True

    # Drop internal test/probe trace files
    if norm.startswith("/tmp/probe_trace") or norm.endswith("trace.log") or norm.endswith(".write_test"):
        return False

    # Match system noise by path prefixes (not arbitrary substring match)
    if norm.startswith(SYSTEM_NOISE_PREFIXES):
        return False

    # Match runtime/package directories by exact component names
    parts = set(p.lower() for p in Path(norm).parts)
    if parts & RUNTIME_DIR_COMPONENTS:
        return False

    # Noise suffixes
    if norm.endswith(NOISE_SUFFIXES):
        return False

    # Additional custom noise strings
    if any(s in norm for s in _EXTRA):
        return False

    return True


def interesting_net(ip: str) -> bool:
    return not any(ip.startswith(n) for n in NET_NOISE)


def real_port(entry: str) -> bool:
    return not entry.endswith(":0")


def _is_native(sample: list[str]) -> bool:
    """Heuristic: native lines start with 'F ', 'W ', 'U ', 'N ', 'X ', 'M ', or '! '."""
    for line in sample:
        s = line.rstrip("\n")
        if not s:
            continue
        if s.startswith("! "):
            return True
        return len(s) >= 2 and s[0] in "FWUNXM" and s[1] == " "
    return False


def _analyze_native(lines) -> dict:
    files_opened = set()
    files_written = set()
    unix_sockets = set()
    nets = set()
    execs = set()
    truncated_paths = set()
    tool_network_connects = {}
    current_tool = None
    filtered_files = 0

    for line in lines:
        s = line.rstrip("\n")
        if not s:
            continue
        if s.startswith("! TRUNCATED "):
            parts = s[12:].split(" ", 1)
            t_tag = parts[0] if parts else ""
            t_tail = parts[1] if len(parts) > 1 else ""
            if t_tail:
                truncated_paths.add(t_tail)
                norm = os.path.normpath(_clean_path(t_tail))
                if interesting_file(norm):
                    files_opened.add(norm)
                    if t_tag == "W":
                        files_written.add(norm)
            continue

        if len(s) < 2 or s[1] != " ":
            continue
        tag, val = s[0], s[2:]
        if tag == "M":
            if val.startswith("CALL_START "):
                current_tool = val[11:].strip()
            elif val.startswith("CALL_END "):
                current_tool = None
        elif tag == "F":
            norm = os.path.normpath(_clean_path(val))
            if len(norm) > 1024 or len(val) > 1024:
                truncated_paths.add(norm)
            if interesting_file(norm):
                files_opened.add(norm)
            else:
                filtered_files += 1
            # Check symlinks at analysis time
            try:
                if os.path.islink(norm) or (os.path.exists(norm) and os.path.islink(val)):
                    real = os.path.realpath(norm)
                    if real != norm and interesting_file(real):
                        files_opened.add(real)
            except (OSError, ValueError):
                pass
        elif tag == "W":
            norm = os.path.normpath(_clean_path(val))
            if len(norm) > 1024 or len(val) > 1024:
                truncated_paths.add(norm)
            files_written.add(norm)
            if interesting_file(norm):
                files_opened.add(norm)
            try:
                if os.path.islink(norm) or (os.path.exists(norm) and os.path.islink(val)):
                    real = os.path.realpath(norm)
                    if real != norm and interesting_file(real):
                        files_opened.add(real)
                        files_written.add(real)
            except (OSError, ValueError):
                pass
        elif tag == "U":
            norm = os.path.normpath(_clean_path(val))
            unix_sockets.add(norm)
        elif tag == "N":
            ip, _, port = val.rpartition(" ")
            if ip and interesting_net(ip):
                conn = f"{ip}:{port}"
                nets.add(conn)
                if current_tool:
                    tool_network_connects.setdefault(current_tool, []).append(conn)
        elif tag == "X":
            execs.add(os.path.normpath(_clean_path(val)))

    return {
        "files_opened": sorted(files_opened),
        "files_written": sorted(files_written),
        "unix_sockets": sorted(unix_sockets),
        "network_connects": sorted(n for n in nets if real_port(n)),
        "subprocesses": sorted(execs),
        "truncated_paths": sorted(truncated_paths),
        "tool_network_connects": tool_network_connects,
        "_meta": {"files_filtered_as_noise": filtered_files},
    }


def analyze(path: str) -> dict:
    with open(path, errors="replace") as f:
        head = [f.readline() for _ in range(8)]
        if _is_native(head):
            f.seek(0)
            return _analyze_native(f)

    files_opened = set()
    files_written = set()
    unix_sockets = set()
    nets = set()
    execs = set()
    truncated_paths = set()
    filtered_files = 0

    with open(path, errors="replace") as f:
        for line in f:
            if (m := STRACE_OPEN.search(line)):
                p = os.path.normpath(_clean_path(m.group(1)))
                if len(p) > 1024:
                    truncated_paths.add(p)
                flags = m.group(2) or ""
                is_write = "creat(" in line or any(w in flags for w in ("O_WRONLY", "O_RDWR", "O_CREAT"))
                if interesting_file(p):
                    files_opened.add(p)
                    if is_write:
                        files_written.add(p)
                else:
                    filtered_files += 1
            if (m := STRACE_NET.search(line)) and interesting_net(m.group(2)):
                nets.add(f"{m.group(2)}:{m.group(1)}")
            if (m := STRACE_UNIX.search(line)):
                u_path = m.group(1) or m.group(2)
                if u_path:
                    prefix = "@" if m.group(1) else ""
                    unix_sockets.add(f"{prefix}{os.path.normpath(_clean_path(u_path))}")
            if (m := STRACE_EXEC.search(line)):
                execs.add(os.path.normpath(_clean_path(m.group(1))))

    return {
        "files_opened": sorted(files_opened),
        "files_written": sorted(files_written),
        "unix_sockets": sorted(unix_sockets),
        "network_connects": sorted(n for n in nets if real_port(n)),
        "subprocesses": sorted(execs),
        "truncated_paths": sorted(truncated_paths),
        "tool_network_connects": {},
        "_meta": {"files_filtered_as_noise": filtered_files},
    }

if __name__ == "__main__":
    tf = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TRACE_FILE", "/tmp/probe_trace.log")
    print(json.dumps(analyze(tf), indent=2))