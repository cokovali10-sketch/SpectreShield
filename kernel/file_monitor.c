// SPDX-License-Identifier: GPL-2.0
// SpectreShield eBPF File Monitor
// Hooks: sys_enter_openat, sys_enter_chmod, sys_enter_fchmodat
// Detects: sensitive file access, permission changes, tampering

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define EVENT_TYPE_OPEN 1
#define EVENT_TYPE_CHMOD 2
#define EVENT_TYPE_UNLINK 3
#define EVENT_TYPE_RENAME 4
#define EVENT_TYPE_SETXATTR 5

struct file_event {
    __u32 event_type;
    __u32 pid;
    __u32 tgid;
    __u64 timestamp_ns;
    __u32 uid;
    __u32 mode;
    __u32 flags;
    char comm[MAX_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char target_filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
    __uint(key_size, 0);
    __uint(value_size, 0);
} file_events SEC(".maps");

// Watched paths (sensitive files)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);   // hash of path prefix
    __type(value, __u8);  // severity level
} watched_paths SEC(".maps");

// Simple djb2 hash for path matching
static __always_inline __u32 hash_str(const char *str, int max_len) {
    __u32 hash = 5381;
    char c;
    #pragma unroll
    for (int i = 0; i < max_len; i++) {
        if (bpf_probe_read_user(&c, 1, str + i) < 0) break;
        if (c == 0) break;
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_TYPE_OPEN;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->flags = (__u32)ctx->args[2];

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);

    // Check against watched paths
    __u32 path_hash = hash_str(event->filename, 64);
    __u8 *severity = bpf_map_lookup_elem(&watched_paths, &path_hash);
    if (severity) {
        event->mode = *severity; // Use mode field to pass severity
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_chmod(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_TYPE_CHMOD;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->mode = (__u32)ctx->args[1];

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlink(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *event;
    event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_TYPE_UNLINK;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
