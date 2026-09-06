//go:build linux

package forensics

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/logging"
	"github.com/cokovali10-sketch/SpectreShield/internal/types"
)

type ForensicsEngine struct {
	cfg   *config.Config
	log   *logging.Logger
	dumps map[string]*DumpRecord
	mu    sync.RWMutex
}

type DumpRecord struct {
	ID          string    `json:"id"`
	PID         uint32    `json:"pid"`
	ProcessName string    `json:"process_name"`
	DumpPath    string    `json:"dump_path"`
	SizeBytes   int64     `json:"size_bytes"`
	Timestamp   time.Time `json:"timestamp"`
	Reason      string    `json:"reason"`
	Verified    bool      `json:"verified"`
}

func NewForensicsEngine(cfg *config.Config) *ForensicsEngine {
	os.MkdirAll(cfg.Forensics.DumpDir, 0o755)
	return &ForensicsEngine{
		cfg:   cfg,
		dumps: make(map[string]*DumpRecord),
	}
}

func (fe *ForensicsEngine) FreezeProcess(pid uint32) error {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return fmt.Errorf("read cgroup for pid %d: %w", pid, err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[1] == "" {
			cgroupDir := parts[2]
			freezerPath := filepath.Join("/sys/fs/cgroup", cgroupDir, "cgroup.freeze")
			if err := os.WriteFile(freezerPath, []byte("1"), 0o644); err == nil {
				fe.log.Info("process frozen", "pid", pid, "cgroup", cgroupDir)
				return nil
			}
		}
	}

	return fe.signalProcess(pid, 19)
}

func (fe *ForensicsEngine) UnfreezeProcess(pid uint32) error {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return fmt.Errorf("read cgroup for pid %d: %w", pid, err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[1] == "" {
			cgroupDir := parts[2]
			freezerPath := filepath.Join("/sys/fs/cgroup", cgroupDir, "cgroup.freeze")
			if err := os.WriteFile(freezerPath, []byte("0"), 0o644); err == nil {
				return nil
			}
		}
	}

	return fe.signalProcess(pid, 18)
}

func (fe *ForensicsEngine) DumpMemory(pid uint32, reason string) (*DumpRecord, error) {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	commData, _ := os.ReadFile(commPath)
	comm := strings.TrimSpace(string(commData))

	dumpID := fmt.Sprintf("dump-%d-%d", pid, time.Now().UnixNano())
	dumpPath := filepath.Join(fe.cfg.Forensics.DumpDir, dumpID+".dump")

	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsData, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("read maps for pid %d: %w", pid, err)
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return nil, fmt.Errorf("open mem for pid %d: %w", pid, err)
	}
	defer memFile.Close()

	dumpFile, err := os.Create(dumpPath)
	if err != nil {
		return nil, fmt.Errorf("create dump file: %w", err)
	}
	defer dumpFile.Close()

	var totalSize int64
	lines := strings.Split(string(mapsData), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		addrRange := strings.Split(parts[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		start, _ := strconv.ParseUint(addrRange[0], 16, 64)
		end, _ := strconv.ParseUint(addrRange[1], 16, 64)

		if len(parts) > 1 && strings.Contains(parts[1], "r") {
			regionSize := int64(end - start)
			if regionSize > 0 && regionSize < int64(fe.cfg.Forensics.MaxDumpSizeMB*1024*1024) {
				totalSize += regionSize
				if totalSize > int64(fe.cfg.Forensics.MaxDumpSizeMB*1024*1024) {
					break
				}
			}
		}
	}

	header := fmt.Sprintf("SPECTRESHIELD_DUMP\nPID: %d\nComm: %s\nReason: %s\nTime: %s\nRegions: %d\n",
		pid, comm, reason, time.Now().Format(time.RFC3339), len(lines))
	dumpFile.WriteString(header)
	dumpFile.WriteString(string(mapsData))

	record := &DumpRecord{
		ID:          dumpID,
		PID:         pid,
		ProcessName: comm,
		DumpPath:    dumpPath,
		SizeBytes:   totalSize,
		Timestamp:   time.Now(),
		Reason:      reason,
	}

	fe.dumps[dumpID] = record

	metaPath := dumpPath + ".meta.json"
	metaData, _ := json.MarshalIndent(record, "", "  ")
	os.WriteFile(metaPath, metaData, 0o644)

	fe.log.Info("memory dump created", "id", dumpID, "pid", pid, "size", totalSize)
	return record, nil
}

func (fe *ForensicsEngine) KillProcess(pid uint32) error {
	return fe.signalProcess(pid, 9)
}

func (fe *ForensicsEngine) ExtractBinary(pid uint32) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	binary, err := os.Readlink(exePath)
	if err != nil {
		return "", fmt.Errorf("readlink /proc/%d/exe: %w", pid, err)
	}

	if !fe.cfg.Forensics.AutoExtractBinary {
		return binary, nil
	}

	dumpID := fmt.Sprintf("binary-%d-%d", pid, time.Now().UnixNano())
	destPath := filepath.Join(fe.cfg.Forensics.DumpDir, dumpID)

	srcData, err := os.ReadFile(binary)
	if err != nil {
		return "", fmt.Errorf("read binary: %w", err)
	}

	if err := os.WriteFile(destPath, srcData, 0o755); err != nil {
		return "", fmt.Errorf("write binary: %w", err)
	}

	fe.log.Info("binary extracted", "pid", pid, "path", destPath)
	return destPath, nil
}

func (fe *ForensicsEngine) GenerateIncidentReport(threats []types.Threat, containment types.ContainmentMethod) *types.IncidentReport {
	hostname, _ := os.Hostname()

	report := &types.IncidentReport{
		ID:                fmt.Sprintf("incident-%d", time.Now().UnixNano()),
		Timestamp:         time.Now(),
		Hostname:          hostname,
		Threats:           threats,
		ContainmentAction: string(containment),
		Status:            "detected",
	}

	pidSet := make(map[uint32]bool)
	for _, t := range threats {
		pidSet[t.PID] = true
		report.AffectedPIDs = append(report.AffectedPIDs, t.PID)
	}

	var analysisParts []string
	for _, t := range threats {
		analysisParts = append(analysisParts, fmt.Sprintf("[%s] %s (PID %d): %s",
			t.Severity, t.Category, t.PID, t.Description))
	}
	report.Analysis = strings.Join(analysisParts, "\n")

	reportPath := filepath.Join(fe.cfg.Forensics.DumpDir, report.ID+".json")
	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(reportPath, data, 0o644)

	return report
}

func (fe *ForensicsEngine) ListDumps() []*DumpRecord {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	result := make([]*DumpRecord, 0, len(fe.dumps))
	for _, d := range fe.dumps {
		result = append(result, d)
	}
	return result
}

func (fe *ForensicsEngine) CleanupDumps(maxAge time.Duration) int {
	fe.mu.Lock()
	defer fe.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for id, dump := range fe.dumps {
		if dump.Timestamp.Before(cutoff) {
			os.Remove(dump.DumpPath)
			os.Remove(dump.DumpPath + ".meta.json")
			delete(fe.dumps, id)
			removed++
		}
	}
	return removed
}

func (fe *ForensicsEngine) signalProcess(pid uint32, sig int) error {
	pidFile := fmt.Sprintf("/proc/%d", pid)
	if _, err := os.Stat(pidFile); err != nil {
		return fmt.Errorf("process %d not found", pid)
	}

	sigStr := strconv.Itoa(sig)
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	if _, err := os.Stat(statusPath); err != nil {
		return fmt.Errorf("cannot signal pid %d: %w", pid, err)
	}

	signalPath := fmt.Sprintf("/proc/%d/signal", pid)
	return os.WriteFile(signalPath, []byte(sigStr), 0o644)
}
