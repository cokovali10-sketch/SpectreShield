//go:build linux

package mitre

import (
	"testing"
)

func TestNewDatabase(t *testing.T) {
	db := NewDatabase()
	if db == nil {
		t.Fatal("expected non-nil database")
	}
}

func TestGetTechniqueCount(t *testing.T) {
	db := NewDatabase()
	count := db.GetTechniqueCount()
	if count == 0 {
		t.Error("expected at least one technique")
	}
	t.Logf("found %d MITRE ATT&CK techniques", count)
}

func TestGetTacticCount(t *testing.T) {
	db := NewDatabase()
	count := db.GetTacticCount()
	if count == 0 {
		t.Error("expected at least one tactic")
	}
	t.Logf("found %d MITRE ATT&CK tactics", count)
}

func TestGetTactics(t *testing.T) {
	db := NewDatabase()
	tactics := db.GetTactics()
	if tactics == nil {
		t.Fatal("expected non-nil tactics")
	}
	if len(tactics) == 0 {
		t.Error("expected at least one tactic")
	}
}
