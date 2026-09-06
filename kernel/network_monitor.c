// SPDX-License-Identifier: GPL-2.0
// SpectreShield eBPF Network Monitor
// Hooks: sys_enter_connect, sys_enter_bind, sys_enter_socket
// Detects: C2 callbacks, reverse shells, port scanning, data exfiltration

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 16
#define EVENT_TYPE_CONNECT 1
#define EVENT_TYPE_BIND 2
#define EVENT_TYPE_SOCKET 3
#define EVENT_TYPE_ACCEPT 4

struct network_event {
    __u32 event_type;
    __u32 pid;
    __u32 tgid;
    __u64 timestamp_ns;
    __u32 uid;
    __u32 sa_family;
    __u32 sport;
    __u32 dport;
    __u32 addr[4];       // IPv6-compatible (v4 maps to addr[0])
    __s32 sock_type;
    __s32 protocol;
    char comm[MAX_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
    __uint(key_size, 0);
    __uint(value_size, 0);
} network_events SEC(".maps");

// Track socket-to-process mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // socket cookie
    __type(value, __u32); // pid
} socket_pid_map SEC(".maps");

// Suspicious port watchlist (hash set)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   // port number
    __type(value, __u8);  // 1 = suspicious
} suspicious_ports SEC(".maps");

static __always_inline void parse_sockaddr(struct network_event *event, void *uaddr) {
    struct sockaddr sa;
    bpf_probe_read_user(&sa, sizeof(sa), uaddr);
    event->sa_family = sa.sa_family;

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in sin;
        bpf_probe_read_user(&sin, sizeof(sin), uaddr);
        event->dport = __builtin_bswap32(sin.sin_port) >> 16;
        event->addr[0] = sin.sin_addr.s_addr;
    } else if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6 sin6;
        bpf_probe_read_user(&sin6, sizeof(sin6), uaddr);
        event->dport = __builtin_bswap32(sin6.sin6_port) >> 16;
        bpf_probe_read_user(event->addr, sizeof(event->addr), &sin6.sin6_addr);
    }
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_TYPE_CONNECT;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Parse sockaddr
    void *uaddr = (void *)ctx->args[1];
    parse_sockaddr(event, uaddr);

    // Check if destination port is suspicious
    __u8 *flag = bpf_map_lookup_elem(&suspicious_ports, &event->dport);
    if (flag) {
        event->sock_type = -1; // Mark as suspicious
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_TYPE_BIND;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    void *uaddr = (void *)ctx->args[1];
    parse_sockaddr(event, uaddr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx) {
    struct network_event *event;
    event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_TYPE_SOCKET;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    event->sa_family = (__u32)ctx->args[0];
    event->sock_type = (__s32)ctx->args[1];
    event->protocol = (__s32)ctx->args[2];

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
