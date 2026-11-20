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
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/param.h>
#include <spawn.h>

extern char **environ;

/* ---- dyld interpose table macro (Apple-specific) ---------------------- */
typedef struct { const void *replacement; const void *original; } interpose_t;
#define DYLD_INTERPOSE(_new, _old)                                          \
    __attribute__((used)) static const interpose_t                         \
    _interpose_##_old __attribute__((section("__DATA,__interpose"))) =      \
    { (const void *)(unsigned long)&_new, (const void *)(unsigned long)&_old };

/* ---- trace sink ------------------------------------------------------- */
static int g_trace_fd = -1;
static int g_is_socket = 0;
/* Reentrancy guard: our logging path must never itself be logged. */
static __thread int g_busy = 0;
static __thread unsigned long g_dropped_records = 0;

static void mcpbehave_init_sink(void) {
    if (g_trace_fd >= 0) return;

    // 1. Inherited file descriptor (socketpair or non-blocking pipe)
    const char *fd_env = getenv("MCP_BEHAVE_TRACE_FD");
    if (fd_env && *fd_env) {
        int fd = atoi(fd_env);
        if (fd >= 0) {
            int fl = fcntl(fd, F_GETFL, 0);
            if (fl >= 0) {
                fcntl(fd, F_SETFL, fl | O_NONBLOCK);
                g_trace_fd = fd;
                g_is_socket = 1;
                return;
            }
        }
    }

    // 2. UNIX domain datagram socket in /tmp (strict <= 104-byte sun_path)
    const char *sock_path = getenv("MCP_BEHAVE_TRACE_SOCK");
    if (sock_path && *sock_path) {
        int s = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (s >= 0) {
            struct sockaddr_un un;
            memset(&un, 0, sizeof(un));
            un.sun_family = AF_UNIX;
            strncpy(un.sun_path, sock_path, sizeof(un.sun_path) - 1);
            fcntl(s, F_SETFL, O_NONBLOCK);
            if (connect(s, (struct sockaddr *)&un, sizeof(un)) == 0) {
                g_trace_fd = s;
                g_is_socket = 1;
                return;
            }
            close(s);
        }
    }

    // 3. Fallback to file for audit mode
    const char *path = getenv("MCP_BEHAVE_TRACE_FILE");
    if (path && *path) {
        g_trace_fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
        g_is_socket = 0;
    }
}

__attribute__((constructor))
static void mcpbehave_init(void) {
    mcpbehave_init_sink();
}

static void emit(const char *buf, size_t len) {
    if (g_trace_fd < 0) {
        mcpbehave_init_sink();
    }
    if (g_trace_fd < 0 || !buf || len == 0) return;

    ssize_t w;
    if (g_is_socket) {
        w = send(g_trace_fd, buf, len, MSG_DONTWAIT);
    } else {
        w = write(g_trace_fd, buf, len);
    }

    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Buffer full: drop record without blocking child process
            g_dropped_records++;
            return;
        }
        // If file descriptor was closed or invalidated, attempt reopen/reconnect
        g_trace_fd = -1;
        mcpbehave_init_sink();
    } else if (g_dropped_records > 0) {
        // Emit drop alert marker upon buffer recovery
        char drop_msg[128];
        int dn = snprintf(drop_msg, sizeof(drop_msg), "! DROPPED %lu\n", g_dropped_records);
        if (dn > 0) {
            if (g_is_socket) {
                (void)!send(g_trace_fd, drop_msg, (size_t)dn, MSG_DONTWAIT);
            } else {
                (void)!write(g_trace_fd, drop_msg, (size_t)dn);
            }
        }
        g_dropped_records = 0;
    }
}

static void log_tag(char tag, const char *val) {
    if (g_busy || g_trace_fd < 0 || !val) return;
    g_busy = 1;
    char b[4096];
    int n = snprintf(b, sizeof b, "%c %s\n", tag, val);
    if (n >= (int)sizeof(b)) {
        emit(b, sizeof(b) - 1);
        size_t vlen = strlen(val);
        const char *tail = (vlen > 512) ? (val + vlen - 512) : val;
        char alert[1024];
        int an = snprintf(alert, sizeof alert, "! TRUNCATED %c %s\n", tag, tail);
        if (an > 0) emit(alert, (size_t)(an < (int)sizeof alert ? an : (int)sizeof alert - 1));
    } else if (n > 0) {
        emit(b, (size_t)n);
    }
    g_busy = 0;
}

static void check_symlink_and_log(const char *path, int is_write) {
    if (!path || !*path) return;
    char resolved[MAXPATHLEN];
    if (realpath(path, resolved)) {
        if (strcmp(path, resolved) != 0) {
            log_tag('F', resolved);
            if (is_write) log_tag('W', resolved);
        }
    }
}

static void check_fd_and_log(int fd, const char *orig_path, int is_write) {
    if (fd < 0 || !orig_path) return;
    char fd_path[MAXPATHLEN];
    if (fcntl(fd, F_GETPATH, fd_path) >= 0 && fd_path[0]) {
        if (strcmp(orig_path, fd_path) != 0) {
            log_tag('F', fd_path);
            if (is_write) log_tag('W', fd_path);
        }
    }
}

/* ---- open / openat ---------------------------------------------------- *
 * open()/openat() are variadic (mode only present with O_CREAT). We take mode
 * via va_arg and forward it, so we never read a garbage register.           */
int my_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    int is_write = (((flags & O_ACCMODE) == O_WRONLY) || ((flags & O_ACCMODE) == O_RDWR) || (flags & O_CREAT));
    log_tag('F', path);
    if (is_write) {
        log_tag('W', path);
    }
    check_symlink_and_log(path, is_write);
    int fd = open(path, flags, mode);
    check_fd_and_log(fd, path, is_write);
    return fd;
}
DYLD_INTERPOSE(my_open, open)

int my_openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    int is_write = (((flags & O_ACCMODE) == O_WRONLY) || ((flags & O_ACCMODE) == O_RDWR) || (flags & O_CREAT));
    log_tag('F', path);
    if (is_write) {
        log_tag('W', path);
    }
    check_symlink_and_log(path, is_write);
    int fd = openat(dirfd, path, flags, mode);
    check_fd_and_log(fd, path, is_write);
    return fd;
}
DYLD_INTERPOSE(my_openat, openat)

/* ---- socket egress inspection (connect, sendto, sendmsg) -------------- */
static void inspect_sockaddr(const struct sockaddr *addr, socklen_t len) {
    if (!addr || g_trace_fd < 0) return;
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
    } else if (addr->sa_family == AF_UNIX) {
        const struct sockaddr_un *u = (const struct sockaddr_un *)addr;
        if (u->sun_path[0] != '\0') {
            char b[1040];
            int n = snprintf(b, sizeof b, "U %s\n", u->sun_path);
            if (n > 0) emit(b, (size_t)n);
        } else if (len > (socklen_t)sizeof(sa_family_t)) {
            char name[108] = {0};
            size_t max_name = len - sizeof(sa_family_t);
            if (max_name > sizeof(name) - 1) max_name = sizeof(name) - 1;
            memcpy(name, u->sun_path + 1, max_name);
            char b[1040];
            int n = snprintf(b, sizeof b, "U @%s\n", name);
            if (n > 0) emit(b, (size_t)n);
        }
    }
    if (port >= 0) {
        char b[128];
        int n = snprintf(b, sizeof b, "N %s %d\n", ip, port);
        if (n > 0) emit(b, (size_t)n);
    }
}

int my_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (!g_busy && addr && g_trace_fd >= 0) {
        g_busy = 1;
        inspect_sockaddr(addr, len);
        g_busy = 0;
    }
    return connect(fd, addr, len);
}
DYLD_INTERPOSE(my_connect, connect)

ssize_t my_sendto(int fd, const void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (!g_busy && dest_addr && g_trace_fd >= 0) {
        g_busy = 1;
        inspect_sockaddr(dest_addr, addrlen);
        g_busy = 0;
    }
    return sendto(fd, buf, len, flags, dest_addr, addrlen);
}
DYLD_INTERPOSE(my_sendto, sendto)

ssize_t my_sendmsg(int fd, const struct msghdr *msg, int flags) {
    if (!g_busy && msg && msg->msg_name && g_trace_fd >= 0) {
        g_busy = 1;
        inspect_sockaddr((const struct sockaddr *)msg->msg_name, msg->msg_namelen);
        g_busy = 0;
    }
    return sendmsg(fd, msg, flags);
}
DYLD_INTERPOSE(my_sendmsg, sendmsg)

/* ---- subprocess launch (posix_spawn, execve, execv, execvp) --- */
static char **ensure_trace_env(char *const envp[]) {
    if (!envp) return NULL;
    const char *dyld = getenv("DYLD_INSERT_LIBRARIES");
    const char *sock = getenv("MCP_BEHAVE_TRACE_SOCK");
    const char *fd_env = getenv("MCP_BEHAVE_TRACE_FD");
    const char *file_env = getenv("MCP_BEHAVE_TRACE_FILE");

    int has_dyld = 0, has_sock = 0, has_fd = 0, has_file = 0;
    int count = 0;
    for (int i = 0; envp[i] != NULL; i++) {
        count++;
        if (dyld && strncmp(envp[i], "DYLD_INSERT_LIBRARIES=", 22) == 0) has_dyld = 1;
        if (sock && strncmp(envp[i], "MCP_BEHAVE_TRACE_SOCK=", 22) == 0) has_sock = 1;
        if (fd_env && strncmp(envp[i], "MCP_BEHAVE_TRACE_FD=", 20) == 0) has_fd = 1;
        if (file_env && strncmp(envp[i], "MCP_BEHAVE_TRACE_FILE=", 22) == 0) has_file = 1;
    }

    int to_add = (!has_dyld && dyld ? 1 : 0) +
                 (!has_sock && sock ? 1 : 0) +
                 (!has_fd && fd_env ? 1 : 0) +
                 (!has_file && file_env ? 1 : 0);
    if (to_add == 0) return (char **)envp;

    char **new_env = malloc((count + to_add + 1) * sizeof(char *));
    if (!new_env) return (char **)envp;

    int idx = 0;
    for (int i = 0; i < count; i++) {
        new_env[idx++] = envp[i];
    }
    if (!has_dyld && dyld) {
        char *entry = malloc(strlen(dyld) + 24);
        if (entry) {
            snprintf(entry, strlen(dyld) + 24, "DYLD_INSERT_LIBRARIES=%s", dyld);
            new_env[idx++] = entry;
        }
    }
    if (!has_sock && sock) {
        char *entry = malloc(strlen(sock) + 24);
        if (entry) {
            snprintf(entry, strlen(sock) + 24, "MCP_BEHAVE_TRACE_SOCK=%s", sock);
            new_env[idx++] = entry;
        }
    }
    if (!has_fd && fd_env) {
        char *entry = malloc(strlen(fd_env) + 22);
        if (entry) {
            snprintf(entry, strlen(fd_env) + 22, "MCP_BEHAVE_TRACE_FD=%s", fd_env);
            new_env[idx++] = entry;
        }
    }
    if (!has_file && file_env) {
        char *entry = malloc(strlen(file_env) + 24);
        if (entry) {
            snprintf(entry, strlen(file_env) + 24, "MCP_BEHAVE_TRACE_FILE=%s", file_env);
            new_env[idx++] = entry;
        }
    }
    new_env[idx] = NULL;
    return new_env;
}

int my_execve(const char *path, char *const argv[], char *const envp[]) {
    log_tag('X', path);
    char **eff_env = envp ? ensure_trace_env(envp) : (char **)environ;
    return execve(path, argv, eff_env);
}
DYLD_INTERPOSE(my_execve, execve)

int my_execv(const char *path, char *const argv[]) {
    log_tag('X', path);
    return execv(path, argv);
}
DYLD_INTERPOSE(my_execv, execv)

int my_execvp(const char *file, char *const argv[]) {
    log_tag('X', file);
    return execvp(file, argv);
}
DYLD_INTERPOSE(my_execvp, execvp)

int my_posix_spawn(pid_t *pid, const char *path,
        const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *at,
        char *const argv[], char *const envp[]) {
    log_tag('X', path);
    char **eff_env = envp ? ensure_trace_env(envp) : (char **)environ;
    return posix_spawn(pid, path, fa, at, argv, eff_env);
}
DYLD_INTERPOSE(my_posix_spawn, posix_spawn)

int my_posix_spawnp(pid_t *pid, const char *path,
        const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *at,
        char *const argv[], char *const envp[]) {
    log_tag('X', path);
    char **eff_env = envp ? ensure_trace_env(envp) : (char **)environ;
    return posix_spawnp(pid, path, fa, at, argv, eff_env);
}
DYLD_INTERPOSE(my_posix_spawnp, posix_spawnp)