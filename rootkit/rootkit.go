//go:build linux

package rootkit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Detector detects rootkits and kernel-level threats
type Detector struct {
	baseline   *SystemBaseline
	findings   []*Finding
	mu         sync.RWMutex
}

// SystemBaseline holds a snapshot of the system state
type SystemBaseline struct {
	ProcessList   map[string]string `json:"process_list"`   // pid -> comm
	KernelModules map[string]string `json:"kernel_modules"` // name -> hash
	SyscallTable  []string          `json:"syscall_table"`
	HiddenPorts   []uint16          `json:"hidden_ports"`
	Timestamp     time.Time         `json:"timestamp"`
}

// Finding represents a rootkit detection finding
type Finding struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // "hidden_process", "syscall_hook", "kernel_tamper", etc.
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// ProcessInfo contains information about a process
type ProcessInfo struct {
	PID    uint32
	PPID   uint32
	Comm   string
	ExePath string
	UID    uint32
}

// NewDetector creates a new rootkit detector
func NewDetector() *Detector {
	return &Detector{}
}

// CreateBaseline creates a system baseline
func (d *Detector) CreateBaseline() (*SystemBaseline, error) {
	baseline := &SystemBaseline{
		ProcessList:   make(map[string]string),
		KernelModules: make(map[string]string),
		Timestamp:     time.Now(),
	}

	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		var pid uint32
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if comm != nil {
			baseline.ProcessList[entry.Name()] = strings.TrimSpace(string(comm))
		}
	}

	modules, _ := os.ReadFile("/proc/modules")
	if modules != nil {
		for _, line := range strings.Split(string(modules), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				data, _ := os.ReadFile(fmt.Sprintf("/sys/module/%s", parts[0]))
				hash := sha256.Sum256(data)
				baseline.KernelModules[parts[0]] = hex.EncodeToString(hash[:])
			}
		}
	}

	d.baseline = baseline
	return baseline, nil
}

// Scan performs a full rootkit scan
func (d *Detector) Scan() []*Finding {
	d.mu.Lock()
	d.findings = nil
	d.mu.Unlock()

	d.checkHiddenProcesses()
	d.checkSyscallHooks()
	d.checkKernelModules()
	d.checkLD_PRELOAD()
	d.checkDevFiles()
	d.checkHiddenPorts()
	d.checkProcessHiding()
	d.checkMemoryAnomalies()
	d.checkNetworkHooks()
	d.checkFilesystemHooks()
	d.checkInterruptHooks()
	d.checkModuleVerification()
	d.checkProcessInjection()
	d.checkFileDescriptors()

	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.findings
}

func (d *Detector) checkHiddenProcesses() {
	procPids := make(map[string]bool)
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		if _, err := fmt.Sscanf(entry.Name(), "%d", nil); err == nil {
			procPids[entry.Name()] = true
		}
	}

	out, err := exec.Command("ps", "-eo", "pid,comm").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines[1:] {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if !procPids[parts[0]] {
					d.addFinding(&Finding{
						ID:          fmt.Sprintf("hidden-proc-%d", time.Now().UnixNano()),
						Type:        "hidden_process",
						Severity:    "critical",
						Title:       "Hidden process detected",
						Description: fmt.Sprintf("Process %s (PID %s) is hidden from /proc", parts[1], parts[0]),
						Evidence:    fmt.Sprintf("ps shows PID %s but /proc/%s does not exist", parts[0], parts[0]),
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}
}

func (d *Detector) checkSyscallHooks() {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return
	}

	syscallAddrs := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 3 && strings.Contains(parts[2], "sys_") {
			syscallAddrs[parts[2]] = parts[0]
		}
	}

	for name, addr := range syscallAddrs {
		if len(addr) > 0 {
			d.addFinding(&Finding{
				ID:          fmt.Sprintf("syscall-hook-%s", name),
				Type:        "syscall_hook",
				Severity:    "medium",
				Title:       fmt.Sprintf("Syscall hook detected: %s", name),
				Description: fmt.Sprintf("Syscall %s hooked at address %s", name, addr),
				MitreID:     "T1014",
			})
		}
	}
}

func (d *Detector) checkKernelModules() {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			modPath := filepath.Join("/sys/module", parts[0])
			if _, err := os.Stat(modPath); err == nil {
				sigPath := filepath.Join(modPath, "sig")
				if _, err := os.Stat(sigPath); os.IsNotExist(err) {
					d.addFinding(&Finding{
						ID:          fmt.Sprintf("unsigned-mod-%s", parts[0]),
						Type:        "kernel_module",
						Severity:    "high",
						Title:       "Unsigned kernel module loaded",
						Description: fmt.Sprintf("Module '%s' is not signed", parts[0]),
						Evidence:    fmt.Sprintf("No signature found at %s", sigPath),
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}
}

func (d *Detector) checkLD_PRELOAD() {
	preload := os.Getenv("LD_PRELOAD")
	if preload != "" {
		d.addFinding(&Finding{
			ID:          "ld-preload-set",
			Type:        "library_hooking",
			Severity:    "critical",
			Title:       "LD_PRELOAD environment variable set",
			Description: "LD_PRELOAD is set, which can indicate library injection",
			Evidence:    fmt.Sprintf("LD_PRELOAD=%s", preload),
			Timestamp:   time.Now(),
		})
	}

	if data, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		content := strings.TrimSpace(string(data))
		if content != "" {
			d.addFinding(&Finding{
				ID:          "ld-so-preload",
				Type:        "library_hooking",
				Severity:    "critical",
				Title:       "/etc/ld.so.preload contains entries",
				Description: "System-wide library preloading is configured",
				Evidence:    content,
				Timestamp:   time.Now(),
			})
		}
	}
}

func (d *Detector) checkDevFiles() {
	suspiciousDevs := []string{"/dev/mem", "/dev/kmem", "/dev/port"}
	for _, dev := range suspiciousDevs {
		if _, err := os.Stat(dev); err == nil {
			d.addFinding(&Finding{
				ID:          fmt.Sprintf("dev-access-%s", filepath.Base(dev)),
				Type:        "kernel_access",
				Severity:    "critical",
				Title:       fmt.Sprintf("Direct device access: %s", dev),
				Description: fmt.Sprintf("Direct access to %s is suspicious", dev),
				Evidence:    fmt.Sprintf("%s exists and is accessible", dev),
				Timestamp:   time.Now(),
			})
		}
	}
}

func (d *Detector) checkHiddenPorts() {
	tcpData, _ := os.ReadFile("/proc/net/tcp")
	if tcpData == nil {
		return
	}

	listeningPorts := make(map[uint16]bool)
	for _, line := range strings.Split(string(tcpData), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 4 && parts[3] == "0A" {
			if colonIdx := strings.Index(parts[1], ":"); colonIdx >= 0 {
				portHex := parts[1][colonIdx+1:]
				var port uint16
				fmt.Sscanf(portHex, "%X", &port)
				listeningPorts[port] = true
			}
		}
	}

	out, err := exec.Command("ss", "-tlnp").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines[1:] {
			parts := strings.Fields(line)
			for _, part := range parts {
				if colonIdx := strings.LastIndex(part, ":"); colonIdx >= 0 {
					var port uint16
					if _, err := fmt.Sscanf(part[colonIdx+1:], "%d", &port); err == nil {
						if listeningPorts[port] {
							delete(listeningPorts, port)
						}
					}
				}
			}
		}
	}

	for port := range listeningPorts {
		d.addFinding(&Finding{
			ID:          fmt.Sprintf("hidden-port-%d", port),
			Type:        "hidden_port",
			Severity:    "high",
			Title:       fmt.Sprintf("Hidden listening port: %d", port),
			Description: fmt.Sprintf("Port %d is listening but hidden from userspace tools", port),
			Evidence:    fmt.Sprintf("Port %d found in /proc/net/tcp but not in ss output", port),
			Timestamp:   time.Now(),
		})
	}
}

func (d *Detector) checkProcessHiding() {
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		var pid uint32
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}

		exePath := fmt.Sprintf("/proc/%d/exe", pid)
		if link, err := os.Readlink(exePath); err == nil {
			if strings.Contains(link, "(deleted)") {
				d.addFinding(&Finding{
					ID:          fmt.Sprintf("deleted-exe-%d", pid),
					Type:        "process_hollowing",
					Severity:    "critical",
					Title:       fmt.Sprintf("Process with deleted executable: PID %d", pid),
					Description: "Process is running from a deleted executable file",
					Evidence:    fmt.Sprintf("exe -> %s", link),
					Timestamp:   time.Now(),
				})
			}
		}

		commData, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if commData != nil {
			comm := strings.TrimSpace(string(commData))
			if link, err := os.Readlink(exePath); err == nil {
				exeName := filepath.Base(link)
				if comm != exeName && comm != "" && exeName != "" {
					d.addFinding(&Finding{
						ID:          fmt.Sprintf("masquerade-%d", pid),
						Type:        "process_masquerading",
						Severity:    "medium",
						Title:       fmt.Sprintf("Process name mismatch: PID %d", pid),
						Description: fmt.Sprintf("comm='%s' but exe='%s'", comm, exeName),
						Evidence:    fmt.Sprintf("/proc/%d/comm != /proc/%d/exe", pid, pid),
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}
}

func (d *Detector) checkMemoryAnomalies() {
	smapsPath := "/proc/self/smaps"
	data, err := os.ReadFile(smapsPath)
	if err != nil {
		return
	}

	suspiciousPatterns := []string{"rwxp", "00000000 00:00 0"}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(string(data), pattern) {
			d.addFinding(&Finding{
				ID:          fmt.Sprintf("mem-anomaly-%d", time.Now().UnixNano()),
				Type:        "memory_anomaly",
				Severity:    "high",
				Title:       "Suspicious memory mapping detected",
				Description: "Found suspicious memory region with executable permissions",
				Evidence:    fmt.Sprintf("Pattern '%s' found in /proc/self/smaps", pattern),
				Timestamp:   time.Now(),
			})
			break
		}
	}
}

func (d *Detector) checkNetworkHooks() {
	netdev, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}

	lines := strings.Split(string(netdev), "\n")
	for _, line := range lines[1:] {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) >= 2 {
			iface := strings.TrimSpace(parts[0])
			if iface != "" && iface != "lo" {
				stats := strings.Fields(parts[1])
				if len(stats) >= 10 {
					rxBytes := stats[0]
					txBytes := stats[8]
					if rxBytes != "0" || txBytes != "0" {
						continue
					}
				}
			}
		}
	}
}

func (d *Detector) checkFilesystemHooks() {
	procMounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return
	}

	suspiciousMounts := []string{"/dev/shm", "/tmp", "/var/tmp"}
	for _, mount := range suspiciousMounts {
		if strings.Contains(string(procMounts), mount) {
			mountInfo := fmt.Sprintf("Found suspicious mount: %s", mount)
			d.addFinding(&Finding{
				ID:          fmt.Sprintf("fs-hook-%s-%d", filepath.Base(mount), time.Now().UnixNano()),
				Type:        "filesystem_hook",
				Severity:    "medium",
				Title:       fmt.Sprintf("Suspicious mount point: %s", mount),
				Description: "Filesystem mounted in suspicious location",
				Evidence:    mountInfo,
				Timestamp:   time.Now(),
			})
		}
	}
}

func (d *Detector) checkInterruptHooks() {
	interrupts, err := os.ReadFile("/proc/interrupts")
	if err != nil {
		return
	}

	lines := strings.Split(string(interrupts), "\n")
	for _, line := range lines[1:] {
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			irqNum := parts[0]
			if _, err := fmt.Sscanf(irqNum, "%d", &irqNum); err == nil {
				handler := parts[2]
				if handler != "" && handler != "IO-APIC-edge" {
					continue
				}
			}
		}
	}
}

func (d *Detector) checkModuleVerification() {
	procModules, err := os.ReadFile("/proc/modules")
	if err != nil {
		return
	}

	lines := strings.Split(string(procModules), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			modName := parts[0]
			modRef := parts[2]

			if modRef == "0" {
				continue
			}

			verPath := filepath.Join("/sys/module", modName, "version")
			if _, err := os.Stat(verPath); os.IsNotExist(err) {
				d.addFinding(&Finding{
					ID:          fmt.Sprintf("unverified-mod-%s", modName),
					Type:        "module_verification",
					Severity:    "high",
					Title:       fmt.Sprintf("Unverified kernel module: %s", modName),
					Description: "Kernel module has no version information",
					Evidence:    fmt.Sprintf("Module %s has no version file", modName),
					Timestamp:   time.Now(),
				})
			}
		}
	}
}

func (d *Detector) checkProcessInjection() {
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		var pid uint32
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}

		mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
		mapsData, err := os.ReadFile(mapsPath)
		if err != nil {
			continue
		}

		lines := strings.Split(string(mapsData), "\n")
		rwxRegions := 0
		for _, line := range lines {
			if strings.Contains(line, "rwxp") {
				rwxRegions++
			}
		}

		if rwxRegions > 5 {
			d.addFinding(&Finding{
				ID:          fmt.Sprintf("process-injection-%d", pid),
				Type:        "process_injection",
				Severity:    "critical",
				Title:       fmt.Sprintf("Process injection detected: PID %d", pid),
				Description: fmt.Sprintf("Process has %d executable memory regions", rwxRegions),
				Evidence:    fmt.Sprintf("Process %d has excessive RWX memory regions", pid),
				Timestamp:   time.Now(),
			})
		}
	}
}

func (d *Detector) checkFileDescriptors() {
	entries, _ := os.ReadDir("/proc")
	suspiciousFds := []string{"/dev/mem", "/dev/kmem", "/dev/sda", "/dev/sdb"}

	for _, entry := range entries {
		var pid uint32
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}

		fdsPath := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdsPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			fdPath := filepath.Join(fdsPath, fd.Name())
			link, err := os.Readlink(fdPath)
			if err != nil {
				continue
			}

			for _, suspicious := range suspiciousFds {
				if strings.Contains(link, suspicious) {
					d.addFinding(&Finding{
						ID:          fmt.Sprintf("suspicious-fd-%d-%s", pid, fd.Name()),
						Type:        "suspicious_file_descriptor",
						Severity:    "critical",
						Title:       fmt.Sprintf("Suspicious file descriptor in PID %d", pid),
						Description: fmt.Sprintf("Process has open file descriptor to %s", suspicious),
						Evidence:    fmt.Sprintf("FD %s -> %s", fd.Name(), link),
						Timestamp:   time.Now(),
					})
				}
			}
		}
	}
}

func (d *Detector) addFinding(f *Finding) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.findings = append(d.findings, f)
}

// GetFindings returns all findings
func (d *Detector) GetFindings() []*Finding {
	d.mu.RLock()
	defer d.mu.RUnlock()
	result := make([]*Finding, len(d.findings))
	copy(result, d.findings)
	return result
}

// GetFindingsByType returns findings of a specific type
func (d *Detector) GetFindingsByType(findingType string) []*Finding {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var result []*Finding
	for _, f := range d.findings {
		if f.Type == findingType {
			result = append(result, f)
		}
	}
	return result
}

// GetFindingsBySeverity returns findings of a specific severity
func (d *Detector) GetFindingsBySeverity(severity string) []*Finding {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var result []*Finding
	for _, f := range d.findings {
		if f.Severity == severity {
			result = append(result, f)
		}
	}
	return result
}

// ClearFindings clears all findings
func (d *Detector) ClearFindings() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.findings = nil
}

// CompareWithBaseline compares current state with baseline
func (d *Detector) CompareWithBaseline(current *SystemBaseline) []*Finding {
	if d.baseline == nil {
		return nil
	}

	var findings []*Finding

	for pid, comm := range current.ProcessList {
		if _, exists := d.baseline.ProcessList[pid]; !exists {
			findings = append(findings, &Finding{
				ID:          fmt.Sprintf("new-proc-%s", pid),
				Type:        "new_process",
				Severity:    "medium",
				Title:       fmt.Sprintf("New process detected: PID %s", pid),
				Description: fmt.Sprintf("Process %s (PID %s) was not in baseline", comm, pid),
				Evidence:    fmt.Sprintf("PID %s not in baseline from %s", pid, d.baseline.Timestamp.Format(time.RFC3339)),
				Timestamp:   time.Now(),
			})
		}
	}

	for name, hash := range current.KernelModules {
		if baselineHash, exists := d.baseline.KernelModules[name]; !exists {
			findings = append(findings, &Finding{
				ID:          fmt.Sprintf("new-module-%s", name),
				Type:        "new_kernel_module",
				Severity:    "critical",
				Title:       fmt.Sprintf("New kernel module loaded: %s", name),
				Description: fmt.Sprintf("Module '%s' was not in baseline", name),
				Evidence:    fmt.Sprintf("Module hash: %s", hash),
				Timestamp:   time.Now(),
			})
		} else if baselineHash != hash {
			findings = append(findings, &Finding{
				ID:          fmt.Sprintf("module-changed-%s", name),
				Type:        "kernel_module_tamper",
				Severity:    "critical",
				Title:       fmt.Sprintf("Kernel module modified: %s", name),
				Description: fmt.Sprintf("Module '%s' has been modified since baseline", name),
				Evidence:    fmt.Sprintf("Baseline hash: %s, Current hash: %s", baselineHash, hash),
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

// ScanKnownRootkits scans for known rootkit signatures
func (d *Detector) ScanKnownRootkits() []*Finding {
	var findings []*Finding

	rootkitSignatures := map[string]string{
		"adore":    "/lib/modules/.adore",
		"knark":    "/dev/knark",
		"riphant":  "/usr/lib/libatriph.so",
		"hideLKM":  "/lib/modules/.hide",
		"modhide":  "/dev/.udev/rules.d",
		"enzym":    "/usr/bin/.enzym",
		"phalanx":  "/usr/share/.phalanx",
		" suckit":  "/usr/share/.suckit",
		" reuters": "/usr/share/.reuters",
	}

	for rootkit, path := range rootkitSignatures {
		re := regexp.MustCompile(regexp.QuoteMeta(rootkit))
		data, err := os.ReadFile(path)
		if err == nil {
			if re.Match(data) {
				findings = append(findings, &Finding{
					ID:          fmt.Sprintf("rootkit-%s", rootkit),
					Type:        "known_rootkit",
					Severity:    "critical",
					Title:       fmt.Sprintf("Known rootkit detected: %s", rootkit),
					Description: fmt.Sprintf("Signature of %s rootkit found", rootkit),
					Evidence:    fmt.Sprintf("File %s matches %s signature", path, rootkit),
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return findings
}

// GenerateReport generates a rootkit scan report
func (d *Detector) GenerateReport() string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	report := "# Rootkit Detection Report\n\n"
	report += fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339))
	report += fmt.Sprintf("Total Findings: %d\n\n", len(d.findings))

	severityCount := make(map[string]int)
	for _, f := range d.findings {
		severityCount[f.Severity]++
	}

	report += "## Summary\n"
	for severity, count := range severityCount {
		report += fmt.Sprintf("- %s: %d\n", severity, count)
	}
	report += "\n"

	report += "## Findings\n"
	for _, f := range d.findings {
		report += fmt.Sprintf("### [%s] %s\n", strings.ToUpper(f.Severity), f.Title)
		report += fmt.Sprintf("- Type: %s\n", f.Type)
		report += fmt.Sprintf("- ID: %s\n", f.ID)
		report += fmt.Sprintf("- Description: %s\n", f.Description)
		report += fmt.Sprintf("- Evidence: %s\n", f.Evidence)
		report += fmt.Sprintf("- Timestamp: %s\n\n", f.Timestamp.Format(time.RFC3339))
	}

	return report
}

// GetSeverityScore returns a numeric severity score
func (d *Detector) GetSeverityScore() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	score := 0
	for _, f := range d.findings {
		switch f.Severity {
		case "critical":
			score += 10
		case "high":
			score += 7
		case "medium":
			score += 4
		case "low":
			score += 1
		}
	}
	return score
}

// IsCompromised returns true if critical findings exist
func (d *Detector) IsCompromised() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, f := range d.findings {
		if f.Severity == "critical" {
			return true
		}
	}
	return false
}

// GetProcessList returns current process list
func (d *Detector) GetProcessList() map[string]string {
	processList := make(map[string]string)
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		var pid uint32
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if comm != nil {
			processList[entry.Name()] = strings.TrimSpace(string(comm))
		}
	}
	return processList
}

// GetKernelModules returns current kernel modules
func (d *Detector) GetKernelModules() map[string]string {
	modules := make(map[string]string)
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return modules
	}

	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			modules[parts[0]] = parts[1]
		}
	}
	return modules
}
