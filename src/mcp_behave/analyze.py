"""Phase 1 analyzer: parse the strace log into a structured behavioral profile.
Pure observation -- lists what the server touched. No allowlist, no verdict yet."""
import re, sys, json, os

# Matches strace's `openat(AT_FDCWD, "path"` AND dtruss's `open("path"` /
# `openat(0xff..., "path"`. The fd/dirfd arg before the path is optional.
OPENAT = re.compile(r'\bopen(?:at)?\((?:[^,)]+,\s*)?"([^"]+)"')
# matches both: sin_addr=inet_addr("1.2.3.4")  and  sin6_addr=inet_pton(AF_INET6, "::1", ...)
# This regex is for strace (Linux) output. macOS now uses the native dylib
# format (see _analyze_native), which DOES carry connect() destinations --
# the dtruss-era "no network on Darwin" limitation is gone.
CONNECT = re.compile(r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*'
                     r'sin6?_port=htons\((\d+)\),\s*sin6?_addr=inet_'
                     r'(?:addr|pton)\((?:[^,]+,\s*)?"([^"]+)"')
EXECVE = re.compile(r'\bexecve\("([^"]+)"')


def _clean_path(p: str) -> str:
    # dtruss appends a literal `\0` to dereferenced C strings (e.g. "/etc/hosts\0").
    # strace does not. Strip it so both tracers yield identical paths.
    return p[:-2] if p.endswith("\\0") else p
# DEFERRED (v2): AF_UNIX egress and alternate sockaddr renderings are not matched.
# A server exfiltrating over a unix domain socket would slip past CONNECT today.

# Substrings that mark a path as runtime/library noise, not behaviorally interesting.
# NOTE: tuned for the spike's Docker+venv layout. Real servers vary (Node, system
# Python, /app, /opt, Nix store), so this is now augmentable via $PROBE_NOISE_EXTRA
# (colon-separated substrings) without editing source. Keep additions conservative:
# over-filtering hides real behavior, under-filtering creates false positives.
NOISE_SUBSTR = ("/site-packages/", "/__pycache__/", "/.venv/", "/usr/", "/lib/",
                "/lib64/", "/proc/", "/sys/", "/dev/", "/etc/ld.so", "dist-info",
                "pyvenv.cfg", "/tmp/probe_trace",
                # common cross-runtime additions:
                "/node_modules/", "/.cache/", "/opt/homebrew/", "/nix/store/",
                "/.nvm/", "/.npm/", "/.pyenv/")
NOISE_SUFFIX = (".pyc", ".so", ".py._pth", ".node", ".dylib")
# Unix sockets / non-routable destinations we don't care about in the spike.
NET_NOISE = ("127.0.0.1", "::1", "0.0.0.0")

# Allow ad-hoc noise substrings per-run without editing source, for unfamiliar layouts.
_EXTRA = tuple(s for s in os.environ.get("PROBE_NOISE_EXTRA", "").split(":") if s)
NOISE_SUBSTR = NOISE_SUBSTR + _EXTRA

def interesting_file(path: str) -> bool:
    if any(s in path for s in NOISE_SUBSTR): return False
    if path.endswith(NOISE_SUFFIX): return False
    return True

def interesting_net(ip: str) -> bool:
    return not any(ip.startswith(n) for n in NET_NOISE)

def real_port(entry: str) -> bool:
    # Drop ":0" pseudo-destinations: connect() calls captured mid-setup or on
    # non-TCP sockets render port 0. They duplicate real "IP:443" findings as
    # noise. Keep only entries with a real (non-zero) port.
    return not entry.endswith(":0")

# The macOS dylib tracer (macos_tracer.c) emits a deliberately trivial format,
# one record per line: "F <path>" / "N <ip> <port>" / "X <path>". We parse it
# natively rather than mimicking strace syntax -- a regex over strace's connect()
# rendering is fragile, and here we own the format end to end. Crucially, unlike
# dtruss, this DOES carry network destinations.
def _is_native(sample: list[str]) -> bool:
    """Heuristic: native lines start with 'F ', 'N ', or 'X '. strace lines
    look like 'openat(AT_FDCWD, ...'. Decide from the first few real lines."""
    for line in sample:
        s = line.rstrip("\n")
        if not s:
            continue
        return len(s) >= 2 and s[0] in "FNX" and s[1] == " "
    return False


def _analyze_native(lines) -> dict:
    files, nets, execs = set(), set(), set()
    filtered_files = 0
    for line in lines:
        s = line.rstrip("\n")
        if len(s) < 2 or s[1] != " ":
            continue
        tag, val = s[0], s[2:]
        if tag == "F":
            if interesting_file(val):
                files.add(val)
            else:
                filtered_files += 1
        elif tag == "N":
            ip, _, port = val.rpartition(" ")
            if ip and interesting_net(ip):
                nets.add(f"{ip}:{port}")
        elif tag == "X":
            execs.add(val)
    return {"files_opened": sorted(files),
            "network_connects": sorted(n for n in nets if real_port(n)),
            "subprocesses": sorted(execs),
            "_meta": {"files_filtered_as_noise": filtered_files}}


def analyze(path: str) -> dict:
    with open(path, errors="replace") as f:
        head = [f.readline() for _ in range(8)]
        if _is_native(head):
            # Re-read from the top: consume the peeked head, then the rest.
            f.seek(0)
            return _analyze_native(f)

    files, nets, execs = set(), set(), set()
    filtered_files = 0  # how many openat hits the noise filter removed
    with open(path, errors="replace") as f:
        for line in f:
            if (m := OPENAT.search(line)):
                path = _clean_path(m.group(1))
                if interesting_file(path):
                    files.add(path)
                else:
                    filtered_files += 1
            if (m := CONNECT.search(line)) and interesting_net(m.group(2)):
                nets.add(f"{m.group(2)}:{m.group(1)}")
            if (m := EXECVE.search(line)):
                execs.add(_clean_path(m.group(1)))
    return {"files_opened": sorted(files),
            "network_connects": sorted(n for n in nets if real_port(n)),
            "subprocesses": sorted(execs),
            # provenance: lets a caller distinguish "genuinely clean" from
            # "noise filter ate everything" when a real server yields 0 findings.
            "_meta": {"files_filtered_as_noise": filtered_files}}

if __name__ == "__main__":
    tf = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TRACE_FILE", "/tmp/probe_trace.log")
    print(json.dumps(analyze(tf), indent=2))