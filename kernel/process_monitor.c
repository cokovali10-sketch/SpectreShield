// SPDX-License-Identifier: GPL-2.0
// SpectreShield eBPF Process Monitor
// Hooks: sys_enter_execve, sys_enter_clone, sched_process_exit
// Streams process lifecycle events to userspace via BPF ring buffer

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define EVENT_TYPE_EXEC 1
#define EVENT_TYPE_CLONE 2
#define EVENT_TYPE_EXIT 3
#define EVENT_TYPE_PTRACE 4

struct process_event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 tgid;
    __u64 timestamp_ns;
    __u32 uid;
    __u32 flags;
    char comm[MAX_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    __s32 exit_code;
    __u32 clone_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
    __uint(key_size, 0);
    __uint(value_size, 0);
} process_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} parent_cache SEC(".maps");

// Track process tree for anomaly detection
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   // child pid
    __type(value, __u32); // parent pid
} process_tree SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct process_event *event;
    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_TYPE_EXEC;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Read comm
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Read filename from syscall args
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename_ptr);

    // Read parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = 0;
    BPF_CORE_READ_INTO(&ppid, task, real_parent, tgid);
    event->ppid = ppid;

    // Store in process tree
    bpf_map_update_elem(&process_tree, &event->pid, &ppid, BPF_ANY);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx) {
    struct process_event *event;
    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_TYPE_CLONE;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->clone_flags = (__u32)ctx->args[0];

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = 0;
    BPF_CORE_READ_INTO(&ppid, task, real_parent, tgid);
    event->ppid = ppid;

    bpf_map_update_elem(&process_tree, &event->pid, &ppid, BPF_ANY);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct process_event *event;
    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_TYPE_EXIT;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    BPF_CORE_READ_INTO(&event->exit_code, task, exit_code);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Clean up process tree entry
    bpf_map_delete_elem(&process_tree, &event->pid);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Detect ptrace attach (anti-debugging / injection detection)
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    __u32 request = (__u32)ctx->args[0];

    // Only trace PTRACE_ATTACH (16) and PTRACE_SEIZE (0x4206)
    if (request != 16 && request != 0x4206) return 0;

    struct process_event *event;
    event = bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event) return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = EVENT_TYPE_PTRACE;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->flags = request;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    __u32 target_pid = (__u32)ctx->args[1];
    event->ppid = target_pid; // reuse ppid field for target

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
