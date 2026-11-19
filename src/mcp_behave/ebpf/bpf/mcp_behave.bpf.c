// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 mcp-behave contributors
 *
 * mcp_behave.bpf.c - Linux eBPF kernel program for auditing MCP servers.
 *
 * Captures process execution, network connections, and filesystem access
 * directly at the Linux kernel boundary using tracepoints and ringbuffer,
 * completely independent of userspace dynamic library loading or libc.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mcp_behave.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Hash map tracking the target MCP server PID and all its child processes */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} target_pids SEC(".maps");

/* Ring buffer for streaming normalized events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB ring buffer */
} events SEC(".maps");

/* Helper to check if a PID is part of the monitored MCP process tree */
static __always_inline bool is_target_process(__u32 pid) {
    __u8 *tracked = bpf_map_lookup_elem(&target_pids, &pid);
    return tracked != NULL;
}

/* 1. Track process tree propagation across forks */
SEC("tracepoint/sched/sched_process_fork")
int handle_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;

    if (!is_target_process(parent_pid)) {
        return 0;
    }

    /* Add child PID to tracked hierarchy */
    __u8 one = 1;
    bpf_map_update_elem(&target_pids, &child_pid, &one, BPF_ANY);

    /* Submit fork event */
    struct mcp_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->type = MCP_EVENT_FORK;
    evt->pid = child_pid;
    evt->ppid = parent_pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* 2. Track executable launches (P0: execve / sched_process_exec) */
SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!is_target_process(pid)) {
        return 0;
    }

    struct mcp_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->type = MCP_EVENT_EXEC;
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* Read binary path from filename */
    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    const char *filename = (const char *)ctx + fname_off;
    bpf_probe_read_kernel_str(&evt->path, sizeof(evt->path), filename);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* 3. Track filesystem access (P0: openat) */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!is_target_process(pid)) {
        return 0;
    }

    struct mcp_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->type = MCP_EVENT_OPEN;
    evt->pid = pid;
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* args[1] is filename, args[2] is flags */
    const char *pathname = (const char *)ctx->args[1];
    evt->flags = (__u32)ctx->args[2];
    bpf_probe_read_user_str(&evt->path, sizeof(evt->path), pathname);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* 4. Track network socket connections (P0: connect) */
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!is_target_process(pid)) {
        return 0;
    }

    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (!addr) return 0;

    unsigned short family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    if (family == AF_INET) {
        struct sockaddr_in in4 = {};
        bpf_probe_read_user(&in4, sizeof(in4), addr);

        struct mcp_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) return 0;

        evt->type = MCP_EVENT_CONNECT;
        evt->pid = pid;
        evt->timestamp_ns = bpf_ktime_get_ns();
        evt->af_family = AF_INET;
        evt->port = __builtin_bswap16(in4.sin_port);
        evt->daddr_ipv4 = in4.sin_addr.s_addr;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

        bpf_ringbuf_submit(evt, 0);
    } else if (family == AF_UNIX) {
        struct sockaddr_un un = {};
        bpf_probe_read_user(&un, sizeof(un), addr);

        struct mcp_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (!evt) return 0;

        evt->type = MCP_EVENT_UNIX;
        evt->pid = pid;
        evt->timestamp_ns = bpf_ktime_get_ns();
        evt->af_family = AF_UNIX;
        bpf_probe_read_user_str(&evt->path, sizeof(evt->path), un.sun_path);
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

        bpf_ringbuf_submit(evt, 0);
    }

    return 0;
}
