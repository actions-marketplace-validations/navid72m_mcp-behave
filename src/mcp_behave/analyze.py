"""Phase 1 analyzer: parse trace log into a structured behavioral profile.
Supports native dynamic libc interposition (macOS DYLD / Linux LD_PRELOAD) and strace.
Pure observation -- lists what the server touched without allowlists or arbitrary verdicts."""
import json
import os
import re
import sys
from pathlib import Path

# Matches strace's `openat(AT_FDCWD, "path"` AND dtruss's `open("path"` /
# `openat(0xff..., "path"`. The fd/dirfd arg before the path is optional.
OPENAT = re.compile(r'\bopen(?:at)?\((?:[^,)]+,\s*)?"([^"]+)"')
# matches both: sin_addr=inet_addr("1.2.3.4")  and  sin6_addr=inet_pton(AF_INET6, "::1", ...)
CONNECT = re.compile(r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*'
                     r'sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet_'
                     r'(?:addr|pton)\((?:[^,]+,\s*)?"([^"]+)"')
EXECVE = re.compile(r'\bexecve\("([^"]+)"')


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
    """Heuristic: native lines start with 'F ', 'W ', 'U ', 'N ', or 'X '.
    strace lines look like 'openat(AT_FDCWD, ...'."""
    for line in sample:
        s = line.rstrip("\n")
        if not s:
            continue
        return len(s) >= 2 and s[0] in "FWUNX" and s[1] == " "
    return False


def _analyze_native(lines) -> dict:
    files_opened = set()
    files_written = set()
    unix_sockets = set()
    nets = set()
    execs = set()
    filtered_files = 0

    for line in lines:
        s = line.rstrip("\n")
        if len(s) < 2 or s[1] != " ":
            continue
        tag, val = s[0], s[2:]
        if tag == "F":
            norm = os.path.normpath(_clean_path(val))
            if interesting_file(norm):
                files_opened.add(norm)
            else:
                filtered_files += 1
        elif tag == "W":
            norm = os.path.normpath(_clean_path(val))
            files_written.add(norm)
            if interesting_file(norm):
                files_opened.add(norm)
        elif tag == "U":
            norm = os.path.normpath(_clean_path(val))
            unix_sockets.add(norm)
        elif tag == "N":
            ip, _, port = val.rpartition(" ")
            if ip and interesting_net(ip):
                nets.add(f"{ip}:{port}")
        elif tag == "X":
            execs.add(os.path.normpath(_clean_path(val)))

    return {
        "files_opened": sorted(files_opened),
        "files_written": sorted(files_written),
        "unix_sockets": sorted(unix_sockets),
        "network_connects": sorted(n for n in nets if real_port(n)),
        "subprocesses": sorted(execs),
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
    filtered_files = 0

    with open(path, errors="replace") as f:
        for line in f:
            if (m := OPENAT.search(line)):
                p = os.path.normpath(_clean_path(m.group(1)))
                if interesting_file(p):
                    files_opened.add(p)
                else:
                    filtered_files += 1
            if (m := CONNECT.search(line)) and interesting_net(m.group(2)):
                nets.add(f"{m.group(2)}:{m.group(1)}")
            if (m := EXECVE.search(line)):
                execs.add(os.path.normpath(_clean_path(m.group(1))))

    return {
        "files_opened": sorted(files_opened),
        "files_written": sorted(files_written),
        "unix_sockets": sorted(unix_sockets),
        "network_connects": sorted(n for n in nets if real_port(n)),
        "subprocesses": sorted(execs),
        "_meta": {"files_filtered_as_noise": filtered_files},
    }

if __name__ == "__main__":
    tf = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TRACE_FILE", "/tmp/probe_trace.log")
    print(json.dumps(analyze(tf), indent=2))