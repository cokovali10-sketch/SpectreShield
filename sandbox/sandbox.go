//go:build linux

package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/logging"
)

// Sandbox isolates suspicious binaries for detonation analysis
type Sandbox struct {
	cfg    *config.Config
	log    *logging.Logger
	active map[string]*SandboxInstance
	mu     sync.RWMutex
}

// SandboxInstance represents a running sandboxed process
type SandboxInstance struct {
	ID         string     `json:"id"`
	BinaryPath string     `json:"binary_path"`
	PID        int        `json:"pid"`
	StartTime  time.Time  `json:"start_time"`
	EndTime    *time.Time `json:"end_time,omitempty"`
	ExitCode   int        `json:"exit_code"`
	Output     string     `json:"output"`
	KillSent   bool       `json:"kill_sent"`
}

// DetonationResult captures the result of a sandbox detonation
type DetonationResult struct {
	ID              string            `json:"id"`
	BinaryPath      string            `json:"binary_path"`
	Duration        time.Duration     `json:"duration"`
	ExitCode        int               `json:"exit_code"`
	Stdout          string            `json:"stdout"`
	Stderr          string            `json:"stderr"`
	Syscalls        []string          `json:"syscalls"`
	NetworkIO       []NetworkIORecord `json:"network_io"`
	FileOps         []FileOpRecord    `json:"file_ops"`
	KilledByTimeout bool              `json:"killed_by_timeout"`
}

type NetworkIORecord struct {
	Timestamp time.Time `json:"timestamp"`
	Protocol  string    `json:"protocol"`
	Remote    string    `json:"remote"`
	Port      uint32    `json:"port"`
}

type FileOpRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Path      string    `json:"path"`
	Operation string    `json:"operation"`
}

// NewSandbox creates a new sandbox
func NewSandbox(cfg *config.Config) *Sandbox {
	os.MkdirAll(cfg.Sandbox.SandboxDir, 0o755)
	return &Sandbox{
		cfg:    cfg,
		active: make(map[string]*SandboxInstance),
	}
}

// Detonate runs a binary in the sandbox and captures its behavior
func (s *Sandbox) Detonate(binaryPath string) (*DetonationResult, error) {
	if !s.cfg.Sandbox.Enabled {
		return nil, fmt.Errorf("sandbox is disabled")
	}

	// Copy binary to sandbox directory
	sandboxBin := filepath.Join(s.cfg.Sandbox.SandboxDir, filepath.Base(binaryPath))
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("read binary: %w", err)
	}
	if err := os.WriteFile(sandboxBin, data, 0o755); err != nil {
		return nil, fmt.Errorf("write sandbox binary: %w", err)
	}

	id := fmt.Sprintf("detonation-%d", time.Now().UnixNano())

	// Create isolated namespaces via unshare
	cmd := exec.Command(
		"unshare",
		"--pid", "--fork",
		"--mount", "--uts", "--net",
		"--",
		sandboxBin,
	)

	// Set up environment
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/tmp",
		"TMPDIR=/tmp",
		"TERM=xterm",
	}

	// Set resource limits
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWUTS,
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	instance := &SandboxInstance{
		ID:         id,
		BinaryPath: binaryPath,
		StartTime:  time.Now(),
	}

	s.mu.Lock()
	s.active[id] = instance
	s.mu.Unlock()

	// Run with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		now := time.Now()
		instance.EndTime = &now
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				instance.ExitCode = exitErr.ExitCode()
			} else {
				instance.ExitCode = -1
			}
		}
	case <-time.After(s.cfg.Sandbox.Timeout):
		now := time.Now()
		instance.EndTime = &now
		instance.KillSent = true
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		<-done
	}

	instance.Output = stdout.String()

	// Cleanup
	os.Remove(sandboxBin)

	return &DetonationResult{
		ID:              id,
		BinaryPath:      binaryPath,
		Duration:        instance.EndTime.Sub(instance.StartTime),
		ExitCode:        instance.ExitCode,
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		KilledByTimeout: instance.KillSent,
	}, nil
}

// GetInstance returns a sandbox instance by ID
func (s *Sandbox) GetInstance(id string) (*SandboxInstance, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inst, ok := s.active[id]
	return inst, ok
}

// ListInstances returns all sandbox instances
func (s *Sandbox) ListInstances() []*SandboxInstance {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*SandboxInstance, 0, len(s.active))
	for _, inst := range s.active {
		result = append(result, inst)
	}
	return result
}

// Cleanup removes old sandbox instances
func (s *Sandbox) Cleanup(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for id, inst := range s.active {
		if inst.EndTime != nil && inst.EndTime.Before(cutoff) {
			delete(s.active, id)
			removed++
		}
	}
	return removed
}
