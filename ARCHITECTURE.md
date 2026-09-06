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

---

## New Modules (v1.1.0)

### Seccomp Profile Generator (`hermes-bridge/seccomp.go`)

Dynamic generation of seccomp BPF profiles based on threat type:

| Threat Type | Seccomp Action |
|-------------|----------------|
| `reverse_shell` | Block connect/sendto/sendmsg |
| `privilege_escalation` | Block setuid/setgid/mount/chroot |
| `data_exfiltration` | Block sendto/sendmsg/sendmmsg |
| `file_tampering` | Block unlink/rename/chmod/chown |
| `fork_bomb` | Block clone/fork/vfork/clone3 |
| `kernel_module` | Block init_module/finit_module/delete_module |
| `anti_debugging` | Block ptrace |

Profiles include 130+ always-allowed syscalls for basic process operation.

### Firewall Rule Generator (`hermes-bridge/firewall.go`)

Dynamic iptables rule generation:

```go
fg := NewFirewallGenerator(cfg)

// Block IP
rules := fg.GenerateBlockIPRules("1.2.3.4", "C2 server")

// Block port
rules = fg.GenerateBlockPortRules(4444, "tcp", "reverse shell")

// Block process network
rules = fg.GenerateBlockProcessRules(pid, "malware")

// Isolate host
rules = fg.GenerateIsolationRules("active attack")

// Apply
fg.ApplyRules(rules)
```

Rules are inserted into a dedicated `SPECTRESHIELD` chain in INPUT/OUTPUT.

### WebSocket/SSE Streaming (`internal/api/websocket.go`)

Real-time event streaming via Server-Sent Events:

```
GET /api/events/stream
Content-Type: text/event-stream

event: stats
data: {"active_pids":123,"uptime":"5m30s"}

event: threat
data: {"id":"threat-123","category":"c2_callback","severity":3}
```

### Test Suite (`tests/engine_test.go`)

10 test cases covering:
- Engine initialization
- Sliding window frequency analysis
- Process exec/clone/ptrace analysis
- Network threat detection
- File permission analysis
- Baseline save/load
- Attack pattern matching
- Statistical functions (variance, stddev)

---

## Module Inventory

| Module | File | Lines | Purpose |
|--------|------|-------|---------|
| eBPF Process Monitor | `kernel/process_monitor.c` | 270 | execve/clone/exit/ptrace hooks |
| eBPF Network Monitor | `kernel/network_monitor.c` | 270 | connect/bind/socket hooks |
| eBPF File Monitor | `kernel/file_monitor.c` | 321 | openat/chmod/unlink/mount hooks |
| Types | `internal/types/types.go` | 178 | Shared type definitions |
| Config | `internal/config/config.go` | 178 | Configuration management |
| Logger | `internal/logging/logger.go` | 50 | Structured logging (slog) |
| Engine | `engine/engine.go` | 522 | Behavioral analysis engine |
| Forensics | `forensics/forensics.go` | 278 | Memory forensics & cgroup freeze |
| Hermes Bridge | `hermes-bridge/bridge.go` | 297 | Hermes v5.0 AI integration |
| Seccomp Generator | `hermes-bridge/seccomp.go` | 350 | Dynamic seccomp profile generation |
| Firewall Generator | `hermes-bridge/firewall.go` | 300 | iptables rule generation |
| Sandbox | `sandbox/sandbox.go` | 205 | Binary detonation sandbox |
| CLI | `cli/cli.go` | 136 | CLI formatting & output |
| API Server | `internal/api/server.go` | 170 | REST API endpoints |
| WebSocket | `internal/api/websocket.go` | 130 | SSE real-time streaming |
| Main | `cmd/spectreshield/main.go` | 500 | Daemon lifecycle & CLI |
| Tests | `tests/engine_test.go` | 180 | Unit tests |
| **Total** | **21 files** | **~4,835** | |
