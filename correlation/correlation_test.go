//go:build linux

package correlation

import (
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(e.events) != 0 {
		t.Errorf("expected 0 events, got %d", len(e.events))
	}
}

func TestAddEvent(t *testing.T) {
	e := NewEngine()
	event := Event{
		ID:        "test-1",
		Timestamp: time.Now(),
		Type:      "process_execution",
		PID:       1234,
		PPID:      1,
		Name:      "test.exe",
		Severity:  "medium",
	}
	e.AddEvent(event)

	if len(e.events) != 1 {
		t.Errorf("expected 1 event, got %d", len(e.events))
	}
}

func TestGetTimeline(t *testing.T) {
	e := NewEngine()

	for i := 0; i < 5; i++ {
		e.AddEvent(Event{
			ID:        time.Now().Format("20060102150405.000"),
			Timestamp: time.Now(),
			Type:      "process_execution",
			PID:       uint32(1000 + i),
			Severity:  "low",
		})
	}

	timeline := e.GetTimeline(5 * time.Minute)
	if timeline == nil {
		t.Fatal("expected non-nil timeline")
	}
	if len(timeline.Events) != 5 {
		t.Errorf("expected 5 events in timeline, got %d", len(timeline.Events))
	}
}

func TestGetChains(t *testing.T) {
	e := NewEngine()

	e.AddEvent(Event{
		ID:        "chain-test-1",
		Timestamp: time.Now(),
		Type:      "process_execution",
		PID:       100,
		PPID:      1,
		Name:      "parent.exe",
		Severity:  "low",
	})

	e.AddEvent(Event{
		ID:        "chain-test-2",
		Timestamp: time.Now(),
		Type:      "process_execution",
		PID:       101,
		PPID:      100,
		Name:      "child.exe",
		Severity:  "high",
	})

	chains := e.GetChains()
	if len(chains) == 0 {
		t.Error("expected at least one chain")
	}
}

func TestGetProcessTree(t *testing.T) {
	e := NewEngine()

	e.processTree[2] = 1
	e.processTree[3] = 2
	e.processTree[4] = 2
	e.processTree[5] = 3

	tree := e.GetProcessTree(1, 5)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	if len(tree[1]) != 1 {
		t.Errorf("expected 1 child of PID 1, got %d", len(tree[1]))
	}
}

func TestEviction(t *testing.T) {
	e := NewEngine()
	e.maxEvents = 10

	for i := 0; i < 15; i++ {
		e.AddEvent(Event{
			ID:        time.Now().Format("20060102150405.000"),
			Timestamp: time.Now(),
			Type:      "process_execution",
			PID:       uint32(i),
			Severity:  "info",
		})
	}

	if len(e.events) > 10 {
		t.Errorf("expected max 10 events after eviction, got %d", len(e.events))
	}
}

func TestStats(t *testing.T) {
	e := NewEngine()
	e.AddEvent(Event{
		ID:        "stat-test",
		Timestamp: time.Now(),
		Type:      "process_execution",
		PID:       1,
		Severity:  "info",
	})

	stats := e.GetStats()
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
	if stats["total_events"] != 1 {
		t.Errorf("expected 1 event in stats, got %v", stats["total_events"])
	}
}
