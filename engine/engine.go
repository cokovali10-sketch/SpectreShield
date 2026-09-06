//go:build linux

package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/logging"
	"github.com/cokovali10-sketch/SpectreShield/internal/types"
)

// Engine is the behavioral analysis and anomaly detection core
type Engine struct {
	cfg            *config.Config
	log            *logging.Logger
	baseline       *types.BaselineProfile
	processTree    map[uint32]*types.ProcessInfo // pid -> info
	processParents map[uint32]uint32             // child -> parent
	anomalies      []types.Threat
	eventCounts    map[string]*SlidingWindow
	mu             sync.RWMutex
}

// SlidingWindow tracks event frequency over time
type SlidingWindow struct {
	window     []time.Time
	windowSize time.Duration
	threshold  int
}

func NewSlidingWindow(windowSize time.Duration, threshold int) *SlidingWindow {
	return &SlidingWindow{
		window:     make([]time.Time, 0, threshold*2),
		windowSize: windowSize,
		threshold:  threshold,
	}
}

func (sw *SlidingWindow) Record() int {
	now := time.Now()
	sw.window = append(sw.window, now)
	sw.prune(now)
	return len(sw.window)
}

func (sw *SlidingWindow) prune(now time.Time) {
	cutoff := now.Add(-sw.windowSize)
	i := 0
	for i < len(sw.window) && sw.window[i].Before(cutoff) {
		i++
	}
	sw.window = sw.window[i:]
}

func (sw *SlidingWindow) ExceedsThreshold() bool {
	return len(sw.window) >= sw.threshold
}

// NewEngine creates a new analysis engine
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{
		cfg:            cfg,
		processTree:    make(map[uint32]*types.ProcessInfo),
		processParents: make(map[uint32]uint32),
		eventCounts:    make(map[string]*SlidingWindow),
	}
}

// LoadBaseline loads the behavioral baseline from disk
func (e *Engine) LoadBaseline() error {
	data, err := os.ReadFile(e.cfg.Engine.BaselinePath)
	if err != nil {
		if os.IsNotExist(err) {
			e.baseline = &types.BaselineProfile{
				NormalProcesses: make(map[string][]string),
				NormalPorts:     make(map[uint32]string),
				NormalPaths:     make(map[string]uint32),
				ProcessTree:     make(map[uint32][]uint32),
				FirstSeen:       time.Now(),
			}
			return e.SaveBaseline()
		}
		return fmt.Errorf("load baseline: %w", err)
	}

	var profile types.BaselineProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("parse baseline: %w", err)
	}
	e.baseline = &profile
	return nil
}

// SaveBaseline persists the baseline to disk
func (e *Engine) SaveBaseline() error {
	e.baseline.LastUpdated = time.Now()
	data, err := json.MarshalIndent(e.baseline, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(e.cfg.Engine.BaselinePath, data, 0o644)
}

// AnalyzeProcessEvent analyzes a process lifecycle event
func (e *Engine) AnalyzeProcessEvent(event *types.ProcessEvent) *types.Threat {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.eventCounts["process"].Record()

	switch event.EventType {
	case types.EventExec:
		return e.analyzeExec(event)
	case types.EventClone:
		return e.analyzeClone(event)
	case types.EventExit:
		e.handleExit(event)
		return nil
	case types.EventPtrace:
		return e.analyzePtrace(event)
	}
	return nil
}

func (e *Engine) analyzeExec(event *types.ProcessEvent) *types.Threat {
	e.processTree[event.PID] = &types.ProcessInfo{
		PID:       event.PID,
		PPID:      event.PPID,
		Comm:      event.Comm,
		UID:       event.UID,
		StartTime: time.Now(),
		ExecPath:  event.Filename,
	}
	e.processParents[event.PID] = event.PPID

	if e.baseline != nil {
		normalPaths, exists := e.baseline.NormalProcesses[event.Comm]
		if exists && !contains(normalPaths, event.Filename) {
			return &types.Threat{
				ID:          fmt.Sprintf("exec-anomaly-%d-%d", event.PID, time.Now().UnixNano()),
				Timestamp:   time.Now(),
				Category:    types.ThreatSuspiciousProcess,
				Severity:    types.SeverityMedium,
				PID:         event.PID,
				PPID:        event.PPID,
				TGID:        event.TGID,
				UID:         event.UID,
				Comm:        event.Comm,
				Description: fmt.Sprintf("Process '%s' executing from unusual path: %s", event.Comm, event.Filename),
				Evidence:    fmt.Sprintf("Expected paths: %v", normalPaths),
			}
		}
	}

	shellProcesses := []string{"/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/python", "/usr/bin/python3", "/usr/bin/perl"}
	for _, shell := range shellProcesses {
		if event.Filename == shell || strings.HasPrefix(event.Filename, shell) {
			dangerousParents := []string{"nginx", "apache2", "httpd", "php-fpm", "node", "java"}
			parentInfo := e.processTree[event.PPID]
			if parentInfo != nil {
				for _, dp := range dangerousParents {
					if parentInfo.Comm == dp {
						return &types.Threat{
							ID:          fmt.Sprintf("shell-parent-%d-%d", event.PID, time.Now().UnixNano()),
							Timestamp:   time.Now(),
							Category:    types.ThreatPrivilegeEscalation,
							Severity:    types.SeverityCritical,
							PID:         event.PID,
							PPID:        event.PPID,
							TGID:        event.TGID,
							UID:         event.UID,
							Comm:        event.Comm,
							Description: fmt.Sprintf("Web server '%s' spawned shell '%s' — possible RCE", parentInfo.Comm, event.Filename),
							Evidence:    fmt.Sprintf("Parent PID %d (%s) -> Child PID %d (%s)", event.PPID, parentInfo.Comm, event.PID, event.Filename),
						}
					}
				}
			}
		}
	}

	dangerousCmds := []string{
		"rm -rf /", "dd if=/dev/zero", "mkfs", ":(){ :|:& };:",
		"curl | sh", "wget | sh", "chmod 777 /", "chown root",
		"/dev/tcp/", "nc -e", "ncat -e", "python -c 'import socket",
	}
	for _, cmd := range dangerousCmds {
		if strings.Contains(event.Filename, cmd) {
			return &types.Threat{
				ID:          fmt.Sprintf("dangerous-cmd-%d-%d", event.PID, time.Now().UnixNano()),
				Timestamp:   time.Now(),
				Category:    types.ThreatMalware,
				Severity:    types.SeverityCritical,
				PID:         event.PID,
				PPID:        event.PPID,
				TGID:        event.TGID,
				UID:         event.UID,
				Comm:        event.Comm,
				Description: fmt.Sprintf("Dangerous command detected: %s", cmd),
				Evidence:    event.Filename,
			}
		}
	}

	return nil
}

func (e *Engine) analyzeClone(event *types.ProcessEvent) *types.Threat {
	e.processTree[event.PID] = &types.ProcessInfo{
		PID:       event.PID,
		PPID:      event.PPID,
		Comm:      event.Comm,
		UID:       event.UID,
		StartTime: time.Now(),
	}
	e.processParents[event.PID] = event.PPID

	key := fmt.Sprintf("clone-%d", event.PPID)
	sw, exists := e.eventCounts[key]
	if !exists {
		sw = NewSlidingWindow(3*time.Second, 15)
		e.eventCounts[key] = sw
	}
	count := sw.Record()
	if count >= 15 {
		return &types.Threat{
			ID:          fmt.Sprintf("fork-bomb-%d-%d", event.PPID, time.Now().UnixNano()),
			Timestamp:   time.Now(),
			Category:    types.ThreatForkBomb,
			Severity:    types.SeverityCritical,
			PID:         event.PPID,
			PPID:        event.PPID,
			TGID:        event.TGID,
			UID:         event.UID,
			Comm:        event.Comm,
			Description: fmt.Sprintf("Fork bomb detected: PID %d spawned %d children in 3s", event.PPID, count),
			Evidence:    fmt.Sprintf("Clone flags: 0x%x", event.CloneFlags),
		}
	}

	if event.CloneFlags&0x10000000 != 0 {
		return &types.Threat{
			ID:          fmt.Sprintf("user-ns-%d-%d", event.PID, time.Now().UnixNano()),
			Timestamp:   time.Now(),
			Category:    types.ThreatPrivilegeEscalation,
			Severity:    types.SeverityHigh,
			PID:         event.PID,
			PPID:        event.PPID,
			TGID:        event.TGID,
			UID:         event.UID,
			Comm:        event.Comm,
			Description: "User namespace creation detected — possible privilege escalation",
			Evidence:    fmt.Sprintf("CLONE_NEWUSER flag in clone() by UID %d", event.UID),
		}
	}

	return nil
}

func (e *Engine) analyzePtrace(event *types.ProcessEvent) *types.Threat {
	targetPID := event.PPID
	return &types.Threat{
		ID:          fmt.Sprintf("ptrace-%d-%d-%d", event.PID, targetPID, time.Now().UnixNano()),
		Timestamp:   time.Now(),
		Category:    types.ThreatAntiDebugging,
		Severity:    types.SeverityHigh,
		PID:         event.PID,
		PPID:        event.PPID,
		TGID:        event.TGID,
		UID:         event.UID,
		Comm:        event.Comm,
		Description: fmt.Sprintf("Process '%s' (PID %d) attached to PID %d via ptrace", event.Comm, event.PID, targetPID),
		Evidence:    fmt.Sprintf("ptrace request: %d", event.Flags),
	}
}

func (e *Engine) handleExit(event *types.ProcessEvent) {
	delete(e.processTree, event.PID)
	delete(e.processParents, event.PID)
}

// AnalyzeNetworkEvent analyzes a network event
func (e *Engine) AnalyzeNetworkEvent(event *types.NetworkEvent) *types.Threat {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, port := range e.cfg.Engine.SuspiciousPorts {
		if event.Dport == port {
			return &types.Threat{
				ID:          fmt.Sprintf("suspicious-port-%d-%d", event.PID, time.Now().UnixNano()),
				Timestamp:   time.Now(),
				Category:    types.ThreatC2Callback,
				Severity:    types.SeverityHigh,
				PID:         event.PID,
				TGID:        event.TGID,
				UID:         event.UID,
				Comm:        event.Comm,
				Description: fmt.Sprintf("Connection to suspicious port %d detected", event.Dport),
				Evidence:    fmt.Sprintf("Family: %d, Proto: %d", event.SAFamily, event.Protocol),
			}
		}
	}

	if event.SockType == -1 {
		return &types.Threat{
			ID:          fmt.Sprintf("net-suspicious-%d-%d", event.PID, time.Now().UnixNano()),
			Timestamp:   time.Now(),
			Category:    types.ThreatReverseShell,
			Severity:    types.SeverityCritical,
			PID:         event.PID,
			TGID:        event.TGID,
			UID:         event.UID,
			Comm:        event.Comm,
			Description: "Suspicious network activity from process",
			Evidence:    fmt.Sprintf("Port: %d, Family: %d", event.Dport, event.SAFamily),
		}
	}

	key := fmt.Sprintf("connect-%d", event.PID)
	sw, exists := e.eventCounts[key]
	if !exists {
		sw = NewSlidingWindow(10*time.Second, 20)
		e.eventCounts[key] = sw
	}
	count := sw.Record()
	if count >= 20 {
		return &types.Threat{
			ID:          fmt.Sprintf("port-scan-%d-%d", event.PID, time.Now().UnixNano()),
			Timestamp:   time.Now(),
			Category:    types.ThreatPortScan,
			Severity:    types.SeverityMedium,
			PID:         event.PID,
			TGID:        event.TGID,
			UID:         event.UID,
			Comm:        event.Comm,
			Description: fmt.Sprintf("Port scan detected: %d connections in 10s", count),
		}
	}

	return nil
}

// AnalyzeFileEvent analyzes a file event
func (e *Engine) AnalyzeFileEvent(event *types.FileEvent) *types.Threat {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, wp := range e.cfg.Engine.WatchedPaths {
		if event.Filename == wp || strings.HasPrefix(event.Filename, wp) {
			return &types.Threat{
				ID:          fmt.Sprintf("file-watch-%d-%d", event.PID, time.Now().UnixNano()),
				Timestamp:   time.Now(),
				Category:    types.ThreatFileTampering,
				Severity:    types.SeverityHigh,
				PID:         event.PID,
				TGID:        event.TGID,
				UID:         event.UID,
				Comm:        event.Comm,
				Description: fmt.Sprintf("Sensitive file access: %s", event.Filename),
				Evidence:    fmt.Sprintf("Event type: %d, Mode: 0%o", event.EventType, event.Mode),
			}
		}
	}

	if event.EventType == types.EventChmod && (event.Mode&0o4000 != 0 || event.Mode&0o2000 != 0) {
		return &types.Threat{
			ID:          fmt.Sprintf("setuid-chmod-%d-%d", event.PID, time.Now().UnixNano()),
			Timestamp:   time.Now(),
			Category:    types.ThreatPrivilegeEscalation,
			Severity:    types.SeverityCritical,
			PID:         event.PID,
			TGID:        event.TGID,
			UID:         event.UID,
			Comm:        event.Comm,
			Description: fmt.Sprintf("Setuid/setgid bit set on %s (mode 0%o)", event.Filename, event.Mode),
			Evidence:    fmt.Sprintf("Mode: 0%o", event.Mode),
		}
	}

	return nil
}

// GetProcessTree returns the current process tree
func (e *Engine) GetProcessTree() map[uint32]*types.ProcessInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[uint32]*types.ProcessInfo, len(e.processTree))
	for k, v := range e.processTree {
		copy := *v
		result[k] = &copy
	}
	return result
}

// GetAnomalies returns detected anomalies
func (e *Engine) GetAnomalies() []types.Threat {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]types.Threat, len(e.anomalies))
	copy(result, e.anomalies)
	return result
}

// BuildBaseline builds baseline from current system state
func (e *Engine) BuildBaseline() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("read /proc: %w", err)
	}

	for _, entry := range entries {
		var pid uint32
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}

		statusPath := filepath.Join("/proc", entry.Name(), "status")
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		info := &types.ProcessInfo{PID: pid}

		for _, line := range lines {
			if strings.HasPrefix(line, "Name:") {
				info.Comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
			if strings.HasPrefix(line, "PPid:") {
				fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), "%d", &info.PPID)
			}
			if strings.HasPrefix(line, "Uid:") {
				fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "Uid:")), "%d", &info.UID)
			}
		}

		exePath := filepath.Join("/proc", entry.Name(), "exe")
		if link, err := os.Readlink(exePath); err == nil {
			info.ExecPath = link
		}

		e.processTree[pid] = info
		e.processParents[pid] = info.PPID

		if e.baseline.NormalProcesses[info.Comm] == nil {
			e.baseline.NormalProcesses[info.Comm] = make([]string, 0)
		}
		if info.ExecPath != "" && !contains(e.baseline.NormalProcesses[info.Comm], info.ExecPath) {
			e.baseline.NormalProcesses[info.Comm] = append(e.baseline.NormalProcesses[info.Comm], info.ExecPath)
		}
	}

	e.baseline.SampleCount++
	return e.SaveBaseline()
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

var attackPatterns = []*regexp.Regexp{
	regexp.MustCompile(`curl\s+.*\|\s*(ba)?sh`),
	regexp.MustCompile(`wget\s+.*\|\s*(ba)?sh`),
	regexp.MustCompile(`python[23]?\s+-c\s+['"].*socket`),
	regexp.MustCompile(`nc\s+-e`),
	regexp.MustCompile(`ncat\s+-e`),
	regexp.MustCompile(`\/bin\/(ba)?sh\s+-i`),
	regexp.MustCompile(`mkfs\.\w+`),
	regexp.MustCompile(`:\(\)\s*\{`),
	regexp.MustCompile(`dd\s+if=\/dev\/(zero|random)`),
	regexp.MustCompile(`chmod\s+[0-7]*777`),
	regexp.MustCompile(`chown\s+root`),
}

func MatchAttackPattern(s string) (bool, string) {
	for _, re := range attackPatterns {
		if re.MatchString(s) {
			return true, re.String()
		}
	}
	return false, ""
}

func Variance(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	mean := 0.0
	for _, v := range data {
		mean += v
	}
	mean /= float64(len(data))

	variance := 0.0
	for _, v := range data {
		diff := v - mean
		variance += diff * diff
	}
	return variance / float64(len(data))
}

func StdDev(data []float64) float64 {
	return math.Sqrt(Variance(data))
}
