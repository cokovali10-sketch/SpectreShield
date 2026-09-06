<div align="center">

# 🛡️ SpectreShield

### **eBPF-powered EDR & Behavioral Threat Intelligence Platform**

[![CI/CD](https://github.com/cokovali10-sketch/SpectreShield/actions/workflows/ci.yml/badge.svg)](https://github.com/cokovali10-sketch/SpectreShield/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![eBPF](https://img.shields.io/badge/eBPF-powered-brightgreen.svg)](https://ebpf.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-orange.svg)](https://attack.mitre.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://linux.org)

**The most comprehensive open-source endpoint detection and response platform.**
Real-time threat detection, behavioral analysis, automated incident response — all powered by eBPF.

[Features](#-features) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [Modules](#-security-modules) • [API](#-api-reference) • [Contributing](#-contributing)

---

</div>

## 📊 Stats

| Metric | Value |
|--------|-------|
| **Go Source Files** | 28 |
| **Go Source Lines** | 327,000+ bytes |
| **C Kernel Programs** | 3 eBPF programs |
| **Security Modules** | 23 |
| **Detection Rules** | 16 YARA + 30 Sigma + 50 MITRE |
| **API Endpoints** | 30+ |
| **CLI Commands** | 20+ |
| **Binary Size** | ~13MB |

## 🚀 Features

### Core Engine
- **eBPF Process Monitor** — Real-time process execution tracking via kernel hooks
- **eBPF Network Monitor** — Socket connect/bind/sendto/recvfrom monitoring
- **eBPF File Monitor** — File open/chmod/unlink tracking with audit trail
- **Behavioral Analysis** — Sliding window anomaly detection, process tree analysis
- **Automatic Baseline** — Learns normal system behavior, alerts on deviations

### Detection Engines
- **YARA Engine** — 16 built-in rules, custom rule support, regex/hex/text/wide patterns
- **Sigma Rules** — 30 built-in detection rules, JSON format, severity filtering
- **MITRE ATT&CK** — 50+ techniques mapped, 14 tactics, threat classification
- **Rootkit Detection** — 14 detection checks: hidden processes, syscall hooks, LD_PRELOAD, kernel modules, hidden ports, process hollowing

### Network Security
- **Deep Packet Inspection** — Ethernet/IP/TCP/UDP parsing, TLS/HTTP/DNS/SSH detection
- **SNI Extraction** — Server Name Indication from TLS ClientHello
- **DNS Tunneling Detection** — High-entropy DNS query analysis
- **SYN Flood Detection** — SYN packet rate monitoring
- **Flow Analysis** — PCAP parsing, beaconing detection, anomaly detection

### Threat Intelligence
- **IOC Database** — IP, domain, hash, URL, email tracking
- **IOC Enrichment** — Correlation, confidence scoring, expiry management
- **Feed Management** — Multiple threat intelligence feed support
- **Bulk Operations** — Batch IOC import/export

### Forensics
- **Memory Forensics** — Process memory analysis, string extraction, shellcode detection
- **Process Hollowing Detection** — Deleted executable mapping detection
- **Binary Analysis** — Entropy calculation, packing detection, pattern scanning
- **Network Forensics** — PCAP analysis, flow correlation, top talkers

### Compliance
- **CIS Benchmark** — 30+ controls
- **PCI DSS** — 12 controls
- **HIPAA** — 5 controls
- **NIST 800-53** — 14 controls
- **CIS Docker Benchmark** — 20 controls
- **Kubernetes CIS** — 22 controls

### Container Security
- **Docker Monitoring** — Privileged container detection, sensitive mount detection
- **Kubernetes Monitoring** — Pod security context analysis, hostPath detection
- **Escape Detection** — Container escape technique identification

### Automated Response
- **5 Playbooks** — Reverse shell, C2, ransomware, privilege escalation, data exfiltration
- **Auto-Response** — Automatic playbook selection by trigger
- **Step Execution** — Command, kill, freeze, block, alert actions

### Integration
- **Hermes AI Bridge** — Connect to Hermes v5.0 for AI-powered analysis
- **REST API** — 30+ endpoints for all modules
- **TUI Dashboard** — Interactive terminal UI (Bubble Tea)
- **Web Dashboard** — Real-time HTML dashboard with auto-refresh

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SpectreShield                            │
├─────────────────────────────────────────────────────────────────┤
│  CLI (20+ commands)  │  REST API (30+ endpoints)  │  Dashboard  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │  YARA    │ │  Sigma   │ │  MITRE   │ │  Rootkit         │   │
│  │  Engine  │ │  Rules   │ │  ATT&CK  │ │  Detector        │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │  DPI     │ │  TI      │ │  Memory  │ │  Compliance      │   │
│  │  Engine  │ │  Database│ │  Forensic│ │  Engine          │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │Container │ │  Network │ │  IR      │ │  Hermes Bridge   │   │
│  │ Security │ │Forensic │ │  Engine  │ │  (AI Analysis)   │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                    Behavioral Analysis Engine                    │
│              (Sliding Window, Process Tree, Anomaly)            │
├─────────────────────────────────────────────────────────────────┤
│     eBPF Kernel Layer (Process/Network/File Monitors)           │
│          cilium/ebpf • Ring Buffer • Tracepoints               │
├─────────────────────────────────────────────────────────────────┤
│                    SQLite Persistence Layer                      │
└─────────────────────────────────────────────────────────────────┘
```

## ⚡ Quick Start

### Prerequisites
- Linux kernel 5.4+ (eBPF support)
- Go 1.21+
- clang/llvm (for eBPF compilation)
- Root privileges (for eBPF)

### Installation

```bash
# Clone the repository
git clone https://github.com/cokovali10-sketch/SpectreShield.git
cd SpectreShield

# Build everything
make all

# Or just the Go binary
make build
```

### From Binary

```bash
# Download latest release
wget https://github.com/cokovali10-sketch/SpectreShield/releases/latest/download/spectreshield-linux-amd64
chmod +x spectreshield-linux-amd64
sudo ./spectreshield-linux-amd64 start --foreground
```

### Docker

```bash
docker build -t spectreshield .
docker run --privileged -p 8080:8080 spectreshield
```

### Usage

```bash
# Start daemon
sudo spectreshield start --foreground --log-level debug

# Launch TUI dashboard
spectreshield dashboard

# Launch web dashboard
spectreshield web --port 8080

# Scan for rootkits
spectreshield rootkit

# YARA scan
spectreshield yara /path/to/binary

# Run compliance check
spectreshield compliance

# View incident response playbooks
spectreshield response

# Check threat intelligence
spectreshield ti

# Analyze network traffic
spectreshield dpi

# Check container security
spectreshield container

# Memory forensics
spectreshield memory /proc/<pid>/mem

# Show version
spectreshield version
```

## 📦 Security Modules

| Module | Description | Lines |
|--------|-------------|-------|
| `yara/` | YARA rule engine with 16 built-in rules | 787 |
| `sigma/` | Sigma detection rules (30 built-in) | 450+ |
| `mitre/` | MITRE ATT&CK mapping (50+ techniques) | 560 |
| `rootkit/` | Rootkit detector (14 checks) | 777 |
| `dpi/` | Deep Packet Inspection engine | 444 |
| `compliance/` | CIS/PCI/HIPAA/NIST compliance | 559 |
| `ti/` | Threat Intelligence IOC database | 350+ |
| `memory/` | Memory forensics engine | 350+ |
| `network/` | Network forensics | 300+ |
| `response/` | Automated Incident Response | 350+ |
| `container/` | Container security monitor | 456 |
| `web/` | Web dashboard with embedded HTML | 200+ |
| `engine/` | Behavioral analysis engine | 600+ |
| `forensics/` | Forensics & cgroup freeze | 400+ |
| `hermes-bridge/` | AI integration bridge | 500+ |
| `analyzer/` | Static binary analyzer | 500+ |
| `sandbox/` | Namespace isolation sandbox | 300+ |
| `tui/` | Terminal UI dashboard | 300+ |
| `kernel/` | eBPF C programs (3 files) | 500+ |
| `internal/` | Config, logging, API, types, eBPF | 1500+ |
| `cli/` | CLI formatting & output | 300+ |
| `cmd/` | Main entry point | 540+ |

## 🔌 API Reference

```
GET  /api/health              - Health check
GET  /api/stats               - System statistics
GET  /api/threats             - Detected threats
GET  /api/processes           - Process tree
GET  /api/dumps               - Memory dumps
GET  /api/sandbox             - Sandbox instances
POST /api/baseline            - Rebuild baseline
POST /api/hermes/analyze      - AI analysis
GET  /api/config              - Configuration
GET  /api/yara/rules          - YARA rules
GET  /api/yara/scan           - YARA scan
GET  /api/rootkit/scan        - Rootkit scan
GET  /api/sigma/rules         - Sigma rules
GET  /api/mitre/techniques    - MITRE techniques
GET  /api/mitre/tactics       - MITRE tactics
GET  /api/compliance/frameworks - Compliance frameworks
POST /api/compliance/run      - Run compliance check
GET  /api/response/playbooks  - IR playbooks
POST /api/response/execute    - Execute playbook
GET  /api/ti/iocs             - Threat IOCs
GET  /api/ti/stats            - TI statistics
POST /api/dpi/analyze         - Analyze packet
GET  /api/container/scan      - Container scan
POST /api/memory/analyze      - Memory analysis
GET  /api/web/data            - Dashboard data (JSON)
```

## 🧪 Testing

```bash
# Run all tests
make test

# Run with coverage
make test-cover

# Run specific package
go test -v ./engine/...

# Run linting
make lint
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Fork the repository
git clone https://github.com/YOUR_USERNAME/SpectreShield.git
cd SpectreShield
git checkout -b feature/amazing-feature
git commit -m 'Add amazing feature'
git push origin feature/amazing-feature
# Open a Pull Request
```

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [cilium/ebpf](https://github.com/cilium/ebpf) - eBPF library for Go
- [charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea) - TUI framework
- [MITRE ATT&CK](https://attack.mitre.org) - Threat intelligence framework
- [YARA](https://virustotal.github.io/yara/) - Pattern matching for malware
- [Sigma](https://github.com/SigmaHQ/sigma) - Generic signature format

---

<div align="center">

**Built with ❤️ for the security community**

⭐ Star this repo if you find it useful!

</div>
