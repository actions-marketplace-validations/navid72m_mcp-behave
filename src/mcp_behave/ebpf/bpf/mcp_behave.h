/* SPDX-License-Identifier: MIT
 * Header definitions for mcp-behave Linux eBPF runtime tracer.
 */
#ifndef __MCP_BEHAVE_BPF_H__
#define __MCP_BEHAVE_BPF_H__

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN  256

/* Event types */
enum mcp_event_type {
    MCP_EVENT_EXEC    = 1,
    MCP_EVENT_FORK    = 2,
    MCP_EVENT_OPEN    = 3,
    MCP_EVENT_CONNECT = 4,
    MCP_EVENT_UNIX    = 5,
};

/* Unified event record emitted through BPF ring buffer */
struct mcp_event {
    unsigned int  type;                 /* enum mcp_event_type */
    unsigned int  pid;                  /* Process ID */
    unsigned int  tgid;                 /* Thread Group ID */
    unsigned int  ppid;                 /* Parent Process ID */
    unsigned int  uid;                  /* User ID */
    unsigned long long timestamp_ns;    /* Kernel monotonic time */
    char          comm[TASK_COMM_LEN];  /* Process command name */
    char          path[MAX_PATH_LEN];   /* Path or binary name */
    unsigned int  flags;                /* Open flags or status */
    unsigned short af_family;           /* AF_INET, AF_INET6, AF_UNIX */
    unsigned short port;                /* Destination port (host byte order) */
    unsigned int  daddr_ipv4;           /* Destination IPv4 address */
    unsigned char daddr_ipv6[16];       /* Destination IPv6 address */
};

#endif /* __MCP_BEHAVE_BPF_H__ */
