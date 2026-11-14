//go:build linux

package types

import (
	"net"
	"time"
)

// EventType represents the type of kernel event
type EventType int

const (
	EventExec     EventType = 1
	EventClone    EventType = 2
	EventExit     EventType = 3
	EventPtrace   EventType = 4
	EventConnect  EventType = 10
	EventBind     EventType = 11
	EventSocket   EventType = 12
	EventOpen     EventType = 20
	EventChmod    EventType = 21
	EventUnlink   EventType = 22
	EventRename   EventType = 23
	EventSetXattr EventType = 24
)

// Severity levels for threats
type Severity int

const (
	SeverityInfo     Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

// String returns the lowercase name of the severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ThreatCategory classifies the type of threat
type ThreatCategory string

const (
	ThreatPrivilegeEscalation ThreatCategory = "privilege_escalation"
	ThreatMalware             ThreatCategory = "malware"
	ThreatC2Callback          ThreatCategory = "c2_callback"
	ThreatReverseShell        ThreatCategory = "reverse_shell"
	ThreatDataExfiltration    ThreatCategory = "data_exfiltration"
	ThreatLateralMovement     ThreatCategory = "lateral_movement"
	ThreatAntiDebugging       ThreatCategory = "anti_debugging"
	ThreatFileTampering       ThreatCategory = "file_tampering"
	ThreatSuspiciousProcess   ThreatCategory = "suspicious_process"
	ThreatPortScan            ThreatCategory = "port_scan"
	ThreatForkBomb            ThreatCategory = "fork_bomb"
)

// ProcessEvent represents a process lifecycle event from eBPF
type ProcessEvent struct {
	EventType   EventType `json:"event_type"`
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	TGID        uint32    `json:"tgid"`
	TimestampNS uint64    `json:"timestamp_ns"`
	UID         uint32    `json:"uid"`
	Flags       uint32    `json:"flags"`
	Comm        string    `json:"comm"`
	Filename    string    `json:"filename"`
	ExitCode    int32     `json:"exit_code"`
	CloneFlags  uint32    `json:"clone_flags"`
}

// NetworkEvent represents a network operation from eBPF
type NetworkEvent struct {
	EventType   EventType `json:"event_type"`
	PID         uint32    `json:"pid"`
	TGID        uint32    `json:"tgid"`
	TimestampNS uint64    `json:"timestamp_ns"`
	UID         uint32    `json:"uid"`
	SAFamily    uint32    `json:"sa_family"`
	Sport       uint32    `json:"sport"`
	Dport       uint32    `json:"dport"`
	Addr        [4]uint32 `json:"addr"`
	SockType    int32     `json:"sock_type"`
	Protocol    int32     `json:"protocol"`
	Comm        string    `json:"comm"`
	RemoteAddr  net.IP    `json:"remote_addr,omitempty"`
}

// FileEvent represents a file operation from eBPF
type FileEvent struct {
	EventType      EventType `json:"event_type"`
	PID            uint32    `json:"pid"`
	TGID           uint32    `json:"tgid"`
	TimestampNS    uint64    `json:"timestamp_ns"`
	UID            uint32    `json:"uid"`
	Mode           uint32    `json:"mode"`
	Flags          uint32    `json:"flags"`
	Comm           string    `json:"comm"`
	Filename       string    `json:"filename"`
	TargetFilename string    `json:"target_filename"`
}

// Threat represents a detected threat
type Threat struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Category    ThreatCategory `json:"category"`
	Severity    Severity       `json:"severity"`
	PID         uint32         `json:"pid"`
	PPID        uint32         `json:"ppid"`
	TGID        uint32         `json:"tgid"`
	UID         uint32         `json:"uid"`
	Comm        string         `json:"comm"`
	Description string         `json:"description"`
	Evidence    string         `json:"evidence"`
	RawEvent    string         `json:"raw_event"`
	Remediation string         `json:"remediation,omitempty"`
	Contained   bool           `json:"contained"`
}

// ProcessInfo holds process tree state
type ProcessInfo struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Comm      string    `json:"comm"`
	UID       uint32    `json:"uid"`
	StartTime time.Time `json:"start_time"`
	ExecPath  string    `json:"exec_path,omitempty"`
}

// BaselineProfile stores normal behavior patterns
type BaselineProfile struct {
	Hostname        string              `json:"hostname"`
	NormalProcesses map[string][]string `json:"normal_processes"` // comm -> []filenames
	NormalPorts     map[uint32]string   `json:"normal_ports"`     // port -> comm
	NormalPaths     map[string]uint32   `json:"normal_paths"`     // path -> mode
	ProcessTree     map[uint32][]uint32 `json:"process_tree"`     // ppid -> [children]
	FirstSeen       time.Time           `json:"first_seen"`
	LastUpdated     time.Time           `json:"last_updated"`
	SampleCount     int64               `json:"sample_count"`
}

// IncidentReport is the full incident report for Hermes
type IncidentReport struct {
	ID                string     `json:"id"`
	Timestamp         time.Time  `json:"timestamp"`
	Hostname          string     `json:"hostname"`
	Threats           []Threat   `json:"threats"`
	AffectedPIDs      []uint32   `json:"affected_pids"`
	ContainmentAction string     `json:"containment_action"`
	ContainmentTime   *time.Time `json:"containment_time,omitempty"`
	Analysis          string     `json:"analysis"`
	RemediationPlan   string     `json:"remediation_plan"`
	Status            string     `json:"status"` // "detected", "contained", "remediated", "false_positive"
}

// DaemonStats holds runtime statistics
type DaemonStats struct {
	Uptime             time.Duration `json:"uptime"`
	EventsProcessed    uint64        `json:"events_processed"`
	ThreatsDetected    uint64        `json:"threats_detected"`
	ProcessesContained uint64        `json:"processes_contained"`
	HermesQueries      uint64        `json:"hermes_queries"`
	ActivePIDs         int           `json:"active_pids"`
	RingBufferUsage    float64       `json:"ring_buffer_usage_pct"`
	MemoryUsageMB      float64       `json:"memory_usage_mb"`
	CPUUsagePercent    float64       `json:"cpu_usage_percent"`
}

// ContainmentMethod describes how a threat was contained
type ContainmentMethod string

const (
	ContainmentFreeze  ContainmentMethod = "cgroup_freeze"
	ContainmentKill    ContainmentMethod = "process_kill"
	ContainmentSeccomp ContainmentMethod = "seccomp_apply"
	ContainmentNetwork ContainmentMethod = "network_block"
	ContainmentIsolate ContainmentMethod = "namespace_isolate"
)
