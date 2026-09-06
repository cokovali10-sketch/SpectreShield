//go:build linux

package container

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Container represents a running container
type Container struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	Status    string            `json:"status"`
	PID       uint32            `json:"pid"`
	Labels    map[string]string `json:"labels"`
	Networks  []string          `json:"networks"`
	Ports     []string          `json:"ports"`
	StartedAt time.Time         `json:"started_at"`
}

// Finding represents a container security finding
type Finding struct {
	ID          string    `json:"id"`
	ContainerID string    `json:"container_id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	MITRE       string    `json:"mitre"`
	Timestamp   time.Time `json:"timestamp"`
}

// Monitor monitors container security
type Monitor struct {
	containers map[string]*Container
	findings   []*Finding
	mu         sync.RWMutex
}

// NewMonitor creates a new container monitor
func NewMonitor() *Monitor {
	return &Monitor{
		containers: make(map[string]*Container),
	}
}

// ScanDocker scans Docker containers
func (m *Monitor) ScanDocker() []*Finding {
	m.mu.Lock()
	m.findings = nil
	m.mu.Unlock()

	containers := m.listDockerContainers()
	for _, c := range containers {
		m.analyzeContainer(c)
	}

	return m.GetFindings()
}

func (m *Monitor) listDockerContainers() []*Container {
	var containers []*Container

	containerDir := "/var/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby"
	if _, err := os.Stat(containerDir); err == nil {
		entries, _ := os.ReadDir(containerDir)
		for _, entry := range entries {
			containers = append(containers, &Container{
				ID:   entry.Name(),
				Name: entry.Name(),
			})
		}
	}

	stateFile := "/var/run/docker/containerd/containerd.sock"
	if _, err := os.Stat(stateFile); err == nil {
		f, err := os.Open(stateFile)
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				if line != "" {
					containers = append(containers, &Container{
						ID:   line,
						Name: line,
					})
				}
			}
		}
	}

	return containers
}

func (m *Monitor) analyzeContainer(c *Container) {
	m.checkPrivileged(c)
	m.checkHostPID(c)
	m.checkHostNetwork(c)
	m.checkSensitiveMounts(c)
	m.checkRootUser(c)
	m.checkCapabilities(c)
	m.checkSeccomp(c)
	m.checkAppArmor(c)
	m.checkReadonlyRootFS(c)
	m.checkResourceLimits(c)
}

func (m *Monitor) checkPrivileged(c *Container) {
	if c.Labels["privileged"] == "true" {
		m.addFinding(c.ID, "privileged_container", "critical",
			"Privileged container detected",
			"Container is running in privileged mode with full host access",
			"Set privileged=false or use specific capabilities",
			"T1611")
	}
}

func (m *Monitor) checkHostPID(c *Container) {
	if c.Labels["pid"] == "host" {
		m.addFinding(c.ID, "host_pid", "high",
			"Host PID namespace sharing",
			"Container can see all host processes",
			"Remove pid=host from container configuration",
			"T1611")
	}
}

func (m *Monitor) checkHostNetwork(c *Container) {
	if c.Labels["network"] == "host" {
		m.addFinding(c.ID, "host_network", "medium",
			"Host network namespace",
			"Container shares host network stack",
			"Use bridge or overlay network instead",
			"T1611")
	}
}

func (m *Monitor) checkSensitiveMounts(c *Container) {
	sensitiveMounts := []string{"/", "/etc", "/var/run/docker.sock", "/proc", "/sys"}
	for _, mount := range sensitiveMounts {
		if c.Labels["bind"] == mount || strings.Contains(c.Labels["volume"], mount) {
			m.addFinding(c.ID, "sensitive_mount", "critical",
				fmt.Sprintf("Sensitive path mounted: %s", mount),
				fmt.Sprintf("Container has access to host %s", mount),
				"Remove sensitive volume mounts",
				"T1611")
		}
	}
}

func (m *Monitor) checkRootUser(c *Container) {
	if c.Labels["user"] == "root" || c.Labels["user"] == "0" {
		m.addFinding(c.ID, "root_user", "high",
			"Container running as root",
			"Container process runs as root user",
			"Use non-root user in Dockerfile",
			"T1611")
	}
}

func (m *Monitor) checkCapabilities(c *Container) {
	capAdd := c.Labels["cap-add"]
	dangerousCaps := []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "NET_RAW", "SYS_MODULE"}
	for _, cap := range dangerousCaps {
		if strings.Contains(capAdd, cap) {
			m.addFinding(c.ID, "dangerous_capabilities", "high",
				fmt.Sprintf("Dangerous capability granted: %s", cap),
				fmt.Sprintf("Container has extra capability: %s", cap),
				"Remove unnecessary capabilities",
				"T1611")
		}
	}
}

func (m *Monitor) checkSeccomp(c *Container) {
	if c.Labels["seccomp"] == "unconfined" {
		m.addFinding(c.ID, "seccomp_disabled", "high",
			"Seccomp profile disabled",
			"Container has no seccomp filtering",
			"Enable seccomp with default or custom profile",
			"T1611")
	}
}

func (m *Monitor) checkAppArmor(c *Container) {
	if c.Labels["apparmor"] == "unconfined" {
		m.addFinding(c.ID, "apparmor_disabled", "medium",
			"AppArmor profile disabled",
			"Container has no AppArmor confinement",
			"Enable AppArmor with default or custom profile",
			"T1611")
	}
}

func (m *Monitor) checkReadonlyRootFS(c *Container) {
	if c.Labels["read_only"] != "true" {
		m.addFinding(c.ID, "writable_rootfs", "medium",
			"Writable root filesystem",
			"Container root filesystem is writable",
			"Set read_only=true and use tmpfs for writable paths",
			"T1611")
	}
}

func (m *Monitor) checkResourceLimits(c *Container) {
	if c.Labels["memory"] == "" {
		m.addFinding(c.ID, "no_memory_limit", "medium",
			"No memory limit set",
			"Container has no memory limit",
			"Set memory limit with --memory flag",
			"T1611")
	}
	if c.Labels["cpus"] == "" {
		m.addFinding(c.ID, "no_cpu_limit", "low",
			"No CPU limit set",
			"Container has no CPU limit",
			"Set CPU limit with --cpus flag",
			"T1611")
	}
}

func (m *Monitor) addFinding(containerID, fType, severity, title, desc, evidence, mitre string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings = append(m.findings, &Finding{
		ID:          fmt.Sprintf("container-%s-%d", containerID, time.Now().UnixNano()),
		ContainerID: containerID,
		Type:        fType,
		Severity:    severity,
		Title:       title,
		Description: desc,
		Evidence:    evidence,
		MITRE:       mitre,
		Timestamp:   time.Now(),
	})
}

// GetFindings returns all findings
func (m *Monitor) GetFindings() []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Finding, len(m.findings))
	copy(result, m.findings)
	return result
}

// ScanKubernetes scans Kubernetes pods
func (m *Monitor) ScanKubernetes() []*Finding {
	podDir := "/var/lib/kubelet/pods"
	if _, err := os.Stat(podDir); os.IsNotExist(err) {
		return nil
	}

	entries, _ := os.ReadDir(podDir)
	for _, entry := range entries {
		if entry.IsDir() {
			m.analyzeKubePod(entry.Name(), filepath.Join(podDir, entry.Name()))
		}
	}

	return m.GetFindings()
}

func (m *Monitor) analyzeKubePod(podID, podDir string) {
	specFile := filepath.Join(podDir, "spec")
	if _, err := os.Stat(specFile); os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(specFile)
	if err != nil {
		return
	}

	content := string(data)

	if strings.Contains(content, "hostPID: true") {
		m.addFinding(podID, "kube_host_pid", "high",
			"Kubernetes pod with hostPID",
			"Pod shares host PID namespace",
			"Remove hostPID from pod security context",
			"T1611")
	}

	if strings.Contains(content, "hostNetwork: true") {
		m.addFinding(podID, "kube_host_network", "medium",
			"Kubernetes pod with hostNetwork",
			"Pod shares host network namespace",
			"Remove hostNetwork from pod security context",
			"T1611")
	}

	if strings.Contains(content, "privileged: true") {
		m.addFinding(podID, "kube_privileged", "critical",
			"Kubernetes privileged pod",
			"Pod runs in privileged mode",
			"Set privileged=false in security context",
			"T1611")
	}

	if strings.Contains(content, "hostPath") {
		m.addFinding(podID, "kube_host_path", "high",
			"Kubernetes pod with hostPath mount",
			"Pod mounts host filesystem path",
			"Use emptyDir or PersistentVolume instead",
			"T1611")
	}

	if !strings.Contains(content, "runAsNonRoot: true") {
		m.addFinding(podID, "kube_root_user", "high",
			"Kubernetes pod may run as root",
			"Pod does not enforce non-root execution",
			"Add runAsNonRoot: true to security context",
			"T1611")
	}

	if strings.Contains(content, "readOnlyRootFilesystem: false") || !strings.Contains(content, "readOnlyRootFilesystem") {
		m.addFinding(podID, "kube_writable_rootfs", "medium",
			"Kubernetes writable root filesystem",
			"Pod root filesystem is writable",
			"Set readOnlyRootFilesystem: true",
			"T1611")
	}

	capsToAdd := []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"}
	for _, cap := range capsToAdd {
		if strings.Contains(content, cap) {
			m.addFinding(podID, "kube_extra_cap", "high",
				fmt.Sprintf("Kubernetes pod with extra capability: %s", cap),
				"Pod has dangerous Linux capability",
				"Remove unnecessary capabilities",
				"T1611")
		}
	}
}

// GetContainerByPID finds a container by its PID
func (m *Monitor) GetContainerByPID(pid uint32) *Container {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.containers {
		if c.PID == pid {
			return c
		}
	}
	return nil
}

// GetContainerByID finds a container by its ID
func (m *Monitor) GetContainerByID(id string) *Container {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.containers[id]
}

// ListContainers returns all known containers
func (m *Monitor) ListContainers() []*Container {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Container, 0, len(m.containers))
	for _, c := range m.containers {
		result = append(result, c)
	}
	return result
}

// ExportJSON exports findings to JSON
func (m *Monitor) ExportJSON(path string) error {
	data, err := json.MarshalIndent(m.GetFindings(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ExportContainers exports container list to JSON
func (m *Monitor) ExportContainers(path string) error {
	data, err := json.MarshalIndent(m.ListContainers(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Summary returns a summary of findings by severity
func (m *Monitor) Summary() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	summary := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	for _, f := range m.findings {
		summary[f.Severity]++
	}
	return summary
}

// FilterBySeverity returns findings matching the given severity
func (m *Monitor) FilterBySeverity(severity string) []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*Finding
	for _, f := range m.findings {
		if f.Severity == severity {
			result = append(result, f)
		}
	}
	return result
}

// FilterByType returns findings matching the given type
func (m *Monitor) FilterByType(fType string) []*Finding {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*Finding
	for _, f := range m.findings {
		if f.Type == fType {
			result = append(result, f)
		}
	}
	return result
}

// ClearFindings clears all findings
func (m *Monitor) ClearFindings() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings = nil
}

// ContainerCount returns the number of known containers
func (m *Monitor) ContainerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.containers)
}

// FindingCount returns the number of findings
func (m *Monitor) FindingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.findings)
}
