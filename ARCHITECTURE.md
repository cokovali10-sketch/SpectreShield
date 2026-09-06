# SpectreShield Architecture

Enterprise-grade eBPF-based EDR & Behavioral Threat Intelligence daemon for Linux.

---

## System Overview

SpectreShield is a zero-dependency, single-binary Linux EDR daemon that combines kernel-level eBPF telemetry with AI-driven threat analysis via the Hermes v5.0 local agent framework.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         SPECTRESHIELD ARCHITECTURE                        │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │                     LINUX KERNEL SPACE                           │     │
│  │                                                                  │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │     │
│  │  │process_monitor│  │network_monitor│  │ file_monitor │          │     │
│  │  │  (eBPF C)    │  │  (eBPF C)    │  │  (eBPF C)    │          │     │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │     │
│  │         │                 │                  │                   │     │
│  │         └─────────────────┼──────────────────┘                  │     │
│  │                           │                                     │     │
│  │                    ┌──────▼──────┐                              │     │
│  │                    │ BPF Ring    │  16MB lock-free ring buffer   │     │
│  │                    │ Buffers     │  per event type              │     │
│  │                    └──────┬──────┘                              │     │
│  └───────────────────────────┼────────────────────────────────────┘     │
│                              │                                           │
│  ┌───────────────────────────┼────────────────────────────────────┐     │
│  │                     USER SPACE                                   │     │
│  │                      │                                           │     │
│  │         ┌────────────┼────────────┐                             │     │
│  │         │            │            │                              │     │
│  │    ┌────▼────┐  ┌────▼────┐  ┌────▼────┐                       │     │
│  │    │ Process │  │ Network │  │  File   │                        │     │
│  │    │ Events  │  │ Events  │  │ Events  │                        │     │
│  │    └────┬────┘  └────┬────┘  └────┬────┘                        │     │
│  │         │            │            │                              │     │
│  │         └────────────┼────────────┘                             │     │
│  │                      │                                           │     │
│  │              ┌───────▼────────┐                                  │     │
│  │              │   BEHAVIORAL   │                                  │     │
│  │              │   ENGINE       │                                  │     │
│  │              │  • Baseline    │                                  │     │
│  │              │  • Anomaly     │                                  │     │
│  │              │  • Heuristics  │                                  │     │
│  │              └───────┬────────┘                                  │     │
│  │                      │                                           │     │
│  │         ┌────────────┼────────────┐                             │     │
│  │         │            │            │                              │     │
│  │    ┌────▼────┐  ┌────▼────┐  ┌────▼────┐                       │     │
│  │    │Forensic │  │Sandbox  │  │ Hermes  │                       │     │
│  │    │ Engine  │  │Detonate │  │ Bridge  │                       │     │
│  │    │• Dump   │  │• Namespc│  │• Analyze│                       │     │
│  │    │• Freeze │  │• Timeout│  │• Remed  │                       │     │
│  │    │• Report │  │• Capture│  │• PostMo │                       │     │
│  │    └─────────┘  └─────────┘  └────┬────┘                       │     │
│  │                                    │                            │     │
│  │                              ┌─────▼─────┐                      │     │
│  │                              │  Hermes   │                      │     │
│  │                              │  v5.0     │                      │     │
│  │                              │  (Local   │                      │     │
│  │                              │   LLM)    │                      │     │
│  │                              └───────────┘                      │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │  CLI (spectreshield start|stop|status|audit|logs)              │     │
│  │  REST API (:9090) — /api/threats, /api/processes, /api/dumps   │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## eBPF Hook Lifecycle

### Process Monitor

```
sys_enter_execve tracepoint
    │
    ├─ Read filename from ctx->args[0]
    ├─ Get current PID/TGID/UID
    ├─ Read parent PID from task_struct->real_parent->tgid
    ├─ Store in process_tree hash map
    └─ Submit to process_events ring buffer

sys_enter_clone tracepoint
    │
    ├─ Read clone_flags from ctx->args[0]
    ├─ Detect CLONE_NEWUSER (privilege escalation)
    ├─ Count clones per parent (fork bomb detection)
    └─ Submit to process_events ring buffer

sched_process_exit tracepoint
    │
    ├─ Read exit_code from task_struct
    ├─ Clean up process_tree entry
    └─ Submit to process_events ring buffer

sys_enter_ptrace tracepoint
    │
    ├─ Filter: only PTRACE_ATTACH (16) and PTRACE_SEIZE (0x4206)
    └─ Submit anti-debugging event
```

### Network Monitor

```
sys_enter_connect tracepoint
    │
    ├─ Parse sockaddr (IPv4/IPv6)
    ├─ Check against suspicious_ports hash map
    └─ Submit to network_events ring buffer

sys_enter_bind tracepoint
    │
    ├─ Parse sockaddr for bind address
    └─ Submit to network_events ring buffer

sys_enter_socket tracepoint
    │
    ├─ Record family, type, protocol
    └─ Submit to network_events ring buffer
```

### File Monitor

```
sys_enter_openat tracepoint
    │
    ├─ Read filename from ctx->args[1]
    ├─ Compute djb2 hash
    ├─ Check against watched_paths hash map
    └─ Submit to file_events ring buffer

sys_enter_chmod tracepoint
    │
    ├─ Read mode from ctx->args[1]
    ├─ Detect setuid/setgid bits (0o4000/0o2000)
    └─ Submit to file_events ring buffer

sys_enter_unlinkat tracepoint
    │
    ├─ Read filename from ctx->args[1]
    └─ Submit to file_events ring buffer
```

---

## Ring Buffer Mechanics

```
Kernel Space                         User Space
┌──────────────────┐                ┌──────────────────┐
│  eBPF Program    │   ringbuf      │  Go Reader       │
│                  │   submit()     │                  │
│  ┌────────────┐  │ ──────────▶   │  ┌────────────┐  │
│  │ Event Data │  │               │  │ Decode     │  │
│  │ (struct)   │  │               │  │ Analyze    │  │
│  └────────────┘  │               │  │ Respond    │  │
│                  │               │  └────────────┘  │
│  Consumer: 0     │   ◀────────   │  Producer: 1     │
│  (kernel)        │   poll()      │  (userspace)     │
└──────────────────┘                └──────────────────┘

- Lock-free SPSC (single producer, single consumer)
- 16MB default size per buffer
- Zero-copy from kernel to userspace
- Backpressure: reserve() fails if buffer full → event dropped
```

---

## Behavioral Analysis Pipeline

```
Raw eBPF Events
       │
       ▼
┌─────────────────┐
│  Event Parser   │  Decode ring buffer entries
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Process Tree   │  Build parent-child relationships
│  Tracker        │  Track UID, exec path, start time
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Baseline       │  Compare against normal behavior
│  Comparator     │  Flag deviations from baseline
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐ ┌────────┐
│ Anomaly│ │ Normal │
│ Found  │ │ Flow   │
└───┬────┘ └────────┘
    │
    ▼
┌─────────────────┐
│  Threat         │  Classify: privilege escalation,
│  Classifier     │  malware, C2, reverse shell, etc.
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Severity       │  Assign: Info/Low/Medium/High/Critical
│  Assessor       │
└────────┬────────┘
         │
    ┌────┴────────────┐
    │                 │
    ▼                 ▼
┌────────┐     ┌────────────┐
│ Alert  │     │ Auto-      │
│ Log    │     │ Contain    │
└────────┘     │ (cgroup    │
               │  freeze)   │
               └─────┬──────┘
                     │
                     ▼
               ┌────────────┐
               │ Hermes     │
               │ AI Analysis│
               └────────────┘
```

---

## Hermes Integration Pathways

### 1. Threat Correlation (Real-time)

```
eBPF Event → Engine Anomaly → Hermes /api/chat
    │                              │
    │  Prompt: "Analyze this       │  Response: Confidence,
    │  threat: {JSON threat}"      │  attack path, impact,
    │                              │  remediation
    ▼                              ▼
  Threat ID ◀──────────── ThreatAnalysis
```

### 2. Autonomous Remediation (On-demand)

```
Threat Detected
    │
    ▼
Hermes /api/chat
    │  Prompt: "Generate remediation
    │  for threat: {JSON}"
    │
    ▼
RemediationScript
    ├─ Actions: ["kill -9 1234", "iptables -A INPUT -s ... -j DROP"]
    ├─ SeccompJSON: {...}
    └─ AutoApprove: false (always require human)
```

### 3. Post-Mortem Generation (Async)

```
Incident Complete
    │
    ▼
Hermes /api/chat
    │  Prompt: "Write incident post-mortem
    │  for: {JSON incident report}"
    │
    ▼
Human-readable post-mortem report
```

### 4. State Sync (Periodic)

```
Baseline Updated
    │
    ▼
Hermes /api/chat (agent mode)
    │  Prompt: "Store this baseline in
    │  your memory: {JSON baseline}"
    │
    ▼
Cross-reboot persistence via Hermes memory
```

---

## Containment Methods

| Method | Mechanism | Speed | Reversible |
|--------|-----------|-------|------------|
| **cgroup freeze** | Write "1" to cgroup.freeze | ~1ms | Yes |
| **SIGSTOP** | Signal 19 | ~0.1ms | Yes |
| **SIGKILL** | Signal 9 | ~0.1ms | No |
| **Seccomp** | Apply SECCOMP_MODE_FILTER | ~1ms | No |
| **Network block** | iptables DROP rule | ~5ms | Yes |
| **Namespace isolate** | Clone new namespaces | ~2ms | No |

---

## Filesystem Layout

```
/var/lib/spectreshield/
├── baseline.json              # Behavioral baseline
├── spectreshield.pid          # Daemon PID file
├── dumps/                     # Memory dumps
│   ├── dump-<pid>-<timestamp>.dump
│   ├── dump-<pid>-<timestamp>.dump.meta.json
│   ├── binary-<pid>-<timestamp>  # Extracted binaries
│   └── incident-<timestamp>.json # Incident reports
├── sandbox/                   # Detonation sandbox
│   └── <binary copies>
└── config.json                # Runtime config

/var/log/spectreshield/
├── spectreshield.log          # JSON structured logs
└── audit.log                  # Audit trail

/usr/lib/spectreshield/bpf/
├── process_monitor.o          # Compiled eBPF object
├── network_monitor.o
└── file_monitor.o
```

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check + Hermes status |
| GET | `/api/stats` | Daemon statistics |
| GET | `/api/threats` | List detected threats |
| GET | `/api/processes` | Process tree |
| GET | `/api/dumps` | Memory dump records |
| GET | `/api/sandbox` | Sandbox instances |
| POST | `/api/baseline` | Rebuild baseline |
| POST | `/api/hermes/analyze` | AI threat analysis |
| GET | `/api/config` | Current configuration |

---

## Syscall Reference

| Tracepoint | Syscall | eBPF Hook Point | Data Captured |
|------------|---------|-----------------|---------------|
| `sys_enter_execve` | `execve(2)` | filename, args | Binary path, comm |
| `sys_enter_clone` | `clone(2)` | clone_flags | CLONE_NEWUSER detection |
| `sched_process_exit` | `exit(2)` | exit_code | Process termination |
| `sys_enter_ptrace` | `ptrace(2)` | request | PTRACE_ATTACH detection |
| `sys_enter_connect` | `connect(2)` | sockaddr | Remote IP/port |
| `sys_enter_bind` | `bind(2)` | sockaddr | Bind address |
| `sys_enter_socket` | `socket(2)` | family, type, proto | Socket creation |
| `sys_enter_openat` | `openat(2)` | filename, flags | File access |
| `sys_enter_chmod` | `chmod(2)` | mode | Permission changes |
| `sys_enter_unlinkat` | `unlinkat(2)` | filename | File deletion |

---

## Build Instructions

```bash
# Prerequisites (on Linux)
apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Build eBPF programs
clang -target bpf -I/usr/include/$(uname -m)-linux-gnu \
    -c kernel/process_monitor.c -o kernel/process_monitor.o
clang -target bpf -I/usr/include/$(uname -m)-linux-gnu \
    -c kernel/network_monitor.c -o kernel/network_monitor.o
clang -target bpf -I/usr/include/$(uname -m)-linux-gnu \
    -c kernel/file_monitor.c -o kernel/file_monitor.o

# Build Go daemon
GOOS=linux GOARCH=amd64 go build -o spectreshield ./cmd/spectreshield/

# Install
cp spectreshield /usr/local/bin/
cp kernel/*.o /usr/lib/spectreshield/bpf/
```

---

## Performance Characteristics

| Metric | Value |
|--------|-------|
| eBPF program load | ~5ms per program |
| Ring buffer latency | ~0.1ms (kernel→userspace) |
| Event processing | ~100K events/sec |
| Memory overhead | ~10MB base + 16MB per ring buffer |
| CPU overhead | <1% at 10K events/sec |
| Containment latency | ~1ms (cgroup freeze) |
| Binary size | ~10MB (statically linked) |
