/*
 * mcp-behave macOS behavioral tracer (Apple Silicon / Intel).
 *
 * Interposes libc entry points via DYLD_INSERT_LIBRARIES so we can observe
 * what an MCP server actually does (files opened, network connects, processes
 * spawned) without root, unlike the old dtruss path.
 *
 * DESIGN NOTE / why this file was rewritten:
 *   The first version fetched the real functions with dlsym(RTLD_NEXT, ...).
 *   That is unsafe here: open()/openat() fire during dyld's own early
 *   bootstrap, BEFORE this library's constructor runs, and resolving symbols
 *   via dlsym in that window (or re-entering an interposer whose real-fn
 *   pointer is still NULL) segfaults the host process. The correct DYLD
 *   interpose idiom is to call the real function by its PLAIN NAME inside the
 *   replacement -- dyld binds that call to the original implementation, with
 *   no runtime resolution and no recursion. No dlsym anywhere.
 *
 * OUTPUT FORMAT (parsed by analyze.py's native parser), one record per line:
 *     F <path>          file opened
 *     N <ip> <port>     outbound connect
 *     X <path>          exec / posix_spawn of a subprocess
 *   Written to $MCP_BEHAVE_TRACE_FILE (O_APPEND). NEVER to stdout/stderr: the
 *   MCP stdio transport carries JSON-RPC on stdout, and one stray byte there
 *   corrupts the protocol.
 *
 * Build (done automatically by probe.py; universal2 so it loads on either arch):
 *   cc -arch arm64 -arch x86_64 -dynamiclib -O2 -o libmcpbehave_trace.dylib macos_tracer.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <spawn.h>

/* ---- dyld interpose table macro (Apple-specific) ---------------------- */
typedef struct { const void *replacement; const void *original; } interpose_t;
#define DYLD_INTERPOSE(_new, _old)                                          \
    __attribute__((used)) static const interpose_t                         \
    _interpose_##_old __attribute__((section("__DATA,__interpose"))) =      \
    { (const void *)(unsigned long)&_new, (const void *)(unsigned long)&_old };

/* ---- trace sink ------------------------------------------------------- */
static int g_trace_fd = -1;
/* Reentrancy guard: our logging path must never itself be logged. */
static __thread int g_busy = 0;

__attribute__((constructor))
static void mcpbehave_init(void) {
    const char *path = getenv("MCP_BEHAVE_TRACE_FILE");
    if (!path || !*path) return;
    /* Direct call to open() -> the REAL open (interpose does not redirect this
     * library's own calls). This open is therefore never self-logged. */
    g_trace_fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
}

static void emit(const char *buf, size_t len) {
    if (g_trace_fd < 0) return;
    (void)!write(g_trace_fd, buf, len);   /* single write() ~ atomic per record */
}

static void log_tag(char tag, const char *val) {
    if (g_busy || g_trace_fd < 0 || !val) return;
    g_busy = 1;
    char b[1200];
    int n = snprintf(b, sizeof b, "%c %s\n", tag, val);
    if (n > 0) emit(b, (size_t)(n < (int)sizeof b ? n : (int)sizeof b - 1));
    g_busy = 0;
}

/* ---- open / openat ---------------------------------------------------- *
 * open()/openat() are variadic (mode only present with O_CREAT). We take mode
 * via va_arg and forward it, so we never read a garbage register.           */
int my_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    log_tag('F', path);
    return open(path, flags, mode);
}
DYLD_INTERPOSE(my_open, open)

int my_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    log_tag('F', path);
    return openat(dirfd, path, flags, mode);
}
DYLD_INTERPOSE(my_openat, openat)

/* ---- connect (the network-visibility win over dtruss) ----------------- */
int my_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (!g_busy && addr && g_trace_fd >= 0) {
        g_busy = 1;
        char ip[INET6_ADDRSTRLEN] = {0};
        int port = -1;
        if (addr->sa_family == AF_INET && len >= (socklen_t)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *s = (const struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &s->sin_addr, ip, sizeof ip);
            port = ntohs(s->sin_port);
        } else if (addr->sa_family == AF_INET6 && len >= (socklen_t)sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof ip);
            port = ntohs(s->sin6_port);
        }
        if (port >= 0) {
            char b[128];
            int n = snprintf(b, sizeof b, "N %s %d\n", ip, port);
            if (n > 0) emit(b, (size_t)n);
        }
        g_busy = 0;
    }
    return connect(fd, addr, len);
}
DYLD_INTERPOSE(my_connect, connect)

/* ---- subprocess launch (posix_spawn is what Python's subprocess uses) --- */
int my_execve(const char *path, char *const argv[], char *const envp[]) {
    log_tag('X', path);
    return execve(path, argv, envp);
}
DYLD_INTERPOSE(my_execve, execve)

int my_posix_spawn(pid_t *pid, const char *path,
        const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *at,
        char *const argv[], char *const envp[]) {
    log_tag('X', path);
    return posix_spawn(pid, path, fa, at, argv, envp);
}
DYLD_INTERPOSE(my_posix_spawn, posix_spawn)

int my_posix_spawnp(pid_t *pid, const char *path,
        const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *at,
        char *const argv[], char *const envp[]) {
    log_tag('X', path);
    return posix_spawnp(pid, path, fa, at, argv, envp);
}
DYLD_INTERPOSE(my_posix_spawnp, posix_spawnp)