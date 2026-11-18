/*
 * mcp-behave Linux behavioral tracer (x86_64 / arm64 / etc.).
 *
 * Interposes libc entry points via LD_PRELOAD so we can observe
 * what an MCP server actually does (files opened, network connects, processes
 * spawned) without root, without SYS_PTRACE, and without requiring strace.
 *
 * OUTPUT FORMAT (parsed by analyze.py's native parser), one record per line:
 *     F <path>          file opened
 *     N <ip> <port>     outbound connect
 *     X <path>          exec / posix_spawn of a subprocess
 *   Written to $MCP_BEHAVE_TRACE_FILE (O_APPEND). NEVER to stdout/stderr: the
 *   MCP stdio transport carries JSON-RPC on stdout, and one stray byte there
 *   corrupts the protocol.
 *
 * Build (done automatically by probe.py):
 *   cc -shared -fPIC -O2 -o libmcpbehave_trace.so linux_tracer.c -ldl
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <spawn.h>
#include <dlfcn.h>
#include <sys/syscall.h>

extern char **environ;

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#ifndef O_TMPFILE
#define O_TMPFILE 020200000
#endif

/* Function pointer types for intercepted libc symbols */
typedef int (*fn_open_t)(const char *, int, ...);
typedef int (*fn_openat_t)(int, const char *, int, ...);
typedef int (*fn_connect_t)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*fn_sendto_t)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef int (*fn_execve_t)(const char *, char *const [], char *const []);
typedef int (*fn_execv_t)(const char *, char *const []);
typedef int (*fn_execvp_t)(const char *, char *const []);
typedef int (*fn_execvpe_t)(const char *, char *const [], char *const []);
typedef int (*fn_posix_spawn_t)(pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char *const [], char *const []);

static fn_open_t real_open = NULL;
static fn_open_t real_open64 = NULL;
static fn_openat_t real_openat = NULL;
static fn_openat_t real_openat64 = NULL;
static fn_connect_t real_connect = NULL;
static fn_sendto_t real_sendto = NULL;
static fn_execve_t real_execve = NULL;
static fn_execv_t real_execv = NULL;
static fn_execvp_t real_execvp = NULL;
static fn_execvpe_t real_execvpe = NULL;
static fn_posix_spawn_t real_posix_spawn = NULL;
static fn_posix_spawn_t real_posix_spawnp = NULL;

/* ---- trace sink ------------------------------------------------------- */
static int g_trace_fd = -1;
/* Reentrancy guard: our logging path must never itself be logged. */
static __thread int g_busy = 0;

static void emit(const char *buf, size_t len) {
    if (g_trace_fd < 0) {
        const char *path = getenv("MCP_BEHAVE_TRACE_FILE");
        if (path && *path) {
#ifdef SYS_openat
            g_trace_fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_APPEND | O_CREAT, 0600);
#else
            g_trace_fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
#endif
        }
    }
    if (g_trace_fd < 0) return;
#ifdef SYS_write
    ssize_t w = (ssize_t)syscall(SYS_write, g_trace_fd, buf, len);
#else
    ssize_t w = write(g_trace_fd, buf, len);
#endif
    if (w < 0) {
        const char *path = getenv("MCP_BEHAVE_TRACE_FILE");
        if (path && *path) {
#ifdef SYS_openat
            int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_APPEND | O_CREAT, 0600);
#else
            int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
#endif
            if (fd >= 0) {
#ifdef SYS_write
                (void)!syscall(SYS_write, fd, buf, len);
#else
                (void)!write(fd, buf, len);
#endif
                g_trace_fd = fd;
            }
        }
    }
}

static void log_tag(char tag, const char *val) {
    if (g_busy || g_trace_fd < 0 || !val) return;
    g_busy = 1;
    char b[1200];
    int n = snprintf(b, sizeof b, "%c %s\n", tag, val);
    if (n > 0) emit(b, (size_t)(n < (int)sizeof b ? n : (int)sizeof b - 1));
    g_busy = 0;
}

__attribute__((constructor))
static void mcpbehave_init(void) {
    const char *path = getenv("MCP_BEHAVE_TRACE_FILE");
    if (path && *path) {
#ifdef SYS_openat
        g_trace_fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_APPEND | O_CREAT, 0600);
#else
        g_trace_fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
#endif
    }
    real_open = (fn_open_t)dlsym(RTLD_NEXT, "open");
    real_open64 = (fn_open_t)dlsym(RTLD_NEXT, "open64");
    real_openat = (fn_openat_t)dlsym(RTLD_NEXT, "openat");
    real_openat64 = (fn_openat_t)dlsym(RTLD_NEXT, "openat64");
    real_connect = (fn_connect_t)dlsym(RTLD_NEXT, "connect");
    real_sendto = (fn_sendto_t)dlsym(RTLD_NEXT, "sendto");
    real_execve = (fn_execve_t)dlsym(RTLD_NEXT, "execve");
    real_execv = (fn_execv_t)dlsym(RTLD_NEXT, "execv");
    real_execvp = (fn_execvp_t)dlsym(RTLD_NEXT, "execvp");
    real_execvpe = (fn_execvpe_t)dlsym(RTLD_NEXT, "execvpe");
    real_posix_spawn = (fn_posix_spawn_t)dlsym(RTLD_NEXT, "posix_spawn");
    real_posix_spawnp = (fn_posix_spawn_t)dlsym(RTLD_NEXT, "posix_spawnp");
}

static mode_t extract_mode(int flags, va_list ap) {
    if ((flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE)) {
        return (mode_t)va_arg(ap, int);
    }
    return 0;
}

static inline int is_write_flags(int flags) {
    return ((flags & O_ACCMODE) == O_WRONLY) ||
           ((flags & O_ACCMODE) == O_RDWR) ||
           (flags & O_CREAT) ||
           ((flags & O_TMPFILE) == O_TMPFILE);
}

/* ---- open / open64 / openat / openat64 ---------------------------------- */
int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    va_list ap;
    va_start(ap, flags);
    mode = extract_mode(flags, ap);
    va_end(ap);

    log_tag('F', path);
    if (is_write_flags(flags)) {
        log_tag('W', path);
    }
    if (!real_open) {
        real_open = (fn_open_t)dlsym(RTLD_NEXT, "open");
        if (!real_open) {
#ifdef SYS_openat
            return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
#elif defined(SYS_open)
            return (int)syscall(SYS_open, path, flags, mode);
#endif
        }
    }
    return real_open(path, flags, mode);
}

#ifdef open64
#undef open64
#endif

int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    va_list ap;
    va_start(ap, flags);
    mode = extract_mode(flags, ap);
    va_end(ap);

    log_tag('F', path);
    if (is_write_flags(flags)) {
        log_tag('W', path);
    }
    if (!real_open64) {
        real_open64 = (fn_open_t)dlsym(RTLD_NEXT, "open64");
        if (!real_open64) {
            return open(path, flags, mode);
        }
    }
    return real_open64(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    va_list ap;
    va_start(ap, flags);
    mode = extract_mode(flags, ap);
    va_end(ap);

    log_tag('F', path);
    if (is_write_flags(flags)) {
        log_tag('W', path);
    }
    if (!real_openat) {
        real_openat = (fn_openat_t)dlsym(RTLD_NEXT, "openat");
        if (!real_openat) {
#ifdef SYS_openat
            return (int)syscall(SYS_openat, dirfd, path, flags, mode);
#endif
        }
    }
    return real_openat(dirfd, path, flags, mode);
}

#ifdef openat64
#undef openat64
#endif

int openat64(int dirfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    va_list ap;
    va_start(ap, flags);
    mode = extract_mode(flags, ap);
    va_end(ap);

    log_tag('F', path);
    if (is_write_flags(flags)) {
        log_tag('W', path);
    }
    if (!real_openat64) {
        real_openat64 = (fn_openat_t)dlsym(RTLD_NEXT, "openat64");
        if (!real_openat64) {
            return openat(dirfd, path, flags, mode);
        }
    }
    return real_openat64(dirfd, path, flags, mode);
}

/* ---- connect & sendto -------------------------------------------------- */
int connect(int fd, const struct sockaddr *addr, socklen_t len) {
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
        } else if (addr->sa_family == AF_UNIX) {
            const struct sockaddr_un *u = (const struct sockaddr_un *)addr;
            if (u->sun_path[0]) {
                char b[1040];
                int n = snprintf(b, sizeof b, "U %s\n", u->sun_path);
                if (n > 0) emit(b, (size_t)n);
            }
        }
        if (port >= 0) {
            char b[128];
            int n = snprintf(b, sizeof b, "N %s %d\n", ip, port);
            if (n > 0) emit(b, (size_t)n);
        }
        g_busy = 0;
    }
    if (!real_connect) {
        real_connect = (fn_connect_t)dlsym(RTLD_NEXT, "connect");
        if (!real_connect) {
#ifdef SYS_connect
            return (int)syscall(SYS_connect, fd, addr, len);
#else
            return -1;
#endif
        }
    }
    return real_connect(fd, addr, len);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (!g_busy && dest_addr && g_trace_fd >= 0) {
        g_busy = 1;
        if (dest_addr->sa_family == AF_INET && addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
            char ip[INET6_ADDRSTRLEN] = {0};
            const struct sockaddr_in *s = (const struct sockaddr_in *)dest_addr;
            inet_ntop(AF_INET, &s->sin_addr, ip, sizeof ip);
            int port = ntohs(s->sin_port);
            if (port >= 0) {
                char b[128];
                int n = snprintf(b, sizeof b, "N %s %d\n", ip, port);
                if (n > 0) emit(b, (size_t)n);
            }
        } else if (dest_addr->sa_family == AF_INET6 && addrlen >= (socklen_t)sizeof(struct sockaddr_in6)) {
            char ip[INET6_ADDRSTRLEN] = {0};
            const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)dest_addr;
            inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof ip);
            int port = ntohs(s->sin6_port);
            if (port >= 0) {
                char b[128];
                int n = snprintf(b, sizeof b, "N %s %d\n", ip, port);
                if (n > 0) emit(b, (size_t)n);
            }
        } else if (dest_addr->sa_family == AF_UNIX) {
            const struct sockaddr_un *u = (const struct sockaddr_un *)dest_addr;
            if (u->sun_path[0]) {
                char b[1040];
                int n = snprintf(b, sizeof b, "U %s\n", u->sun_path);
                if (n > 0) emit(b, (size_t)n);
            }
        }
        g_busy = 0;
    }
    if (!real_sendto) {
        real_sendto = (fn_sendto_t)dlsym(RTLD_NEXT, "sendto");
        if (!real_sendto) {
#ifdef SYS_sendto
            return (ssize_t)syscall(SYS_sendto, fd, buf, len, flags, dest_addr, addrlen);
#else
            return -1;
#endif
        }
    }
    return real_sendto(fd, buf, len, flags, dest_addr, addrlen);
}

/* ---- subprocess launch ------------------------------------------------- */
int execve(const char *path, char *const argv[], char *const envp[]) {
    log_tag('X', path);
    if (!real_execve) {
        real_execve = (fn_execve_t)dlsym(RTLD_NEXT, "execve");
        if (!real_execve) {
#ifdef SYS_execve
            return (int)syscall(SYS_execve, path, argv, envp);
#else
            return -1;
#endif
        }
    }
    return real_execve(path, argv, envp);
}

int execv(const char *path, char *const argv[]) {
    log_tag('X', path);
    if (!real_execv) {
        real_execv = (fn_execv_t)dlsym(RTLD_NEXT, "execv");
    }
    if (real_execv) {
        return real_execv(path, argv);
    }
    return execve(path, argv, environ);
}

int execvp(const char *file, char *const argv[]) {
    log_tag('X', file);
    if (!real_execvp) {
        real_execvp = (fn_execvp_t)dlsym(RTLD_NEXT, "execvp");
    }
    if (real_execvp) {
        return real_execvp(file, argv);
    }
    return -1;
}

int execvpe(const char *file, char *const argv[], char *const envp[]) {
    log_tag('X', file);
    if (!real_execvpe) {
        real_execvpe = (fn_execvpe_t)dlsym(RTLD_NEXT, "execvpe");
    }
    if (real_execvpe) {
        return real_execvpe(file, argv, envp);
    }
    return -1;
}

int posix_spawn(pid_t *pid, const char *path,
        const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *at,
        char *const argv[], char *const envp[]) {
    log_tag('X', path);
    if (!real_posix_spawn) {
        real_posix_spawn = (fn_posix_spawn_t)dlsym(RTLD_NEXT, "posix_spawn");
    }
    if (real_posix_spawn) {
        return real_posix_spawn(pid, path, fa, at, argv, envp);
    }
    return -1;
}

int posix_spawnp(pid_t *pid, const char *path,
        const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *at,
        char *const argv[], char *const envp[]) {
    log_tag('X', path);
    if (!real_posix_spawnp) {
        real_posix_spawnp = (fn_posix_spawn_t)dlsym(RTLD_NEXT, "posix_spawnp");
    }
    if (real_posix_spawnp) {
        return real_posix_spawnp(pid, path, fa, at, argv, envp);
    }
    return -1;
}
