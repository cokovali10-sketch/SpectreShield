//go:build linux

package sigma

import (
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if e.GetRuleCount() != 0 {
		t.Errorf("expected 0 rules before loading, got %d", e.GetRuleCount())
	}
}

func TestLoadBuiltinRules(t *testing.T) {
	e := NewEngine()
	e.LoadBuiltinRules()
	count := e.GetRuleCount()
	if count == 0 {
		t.Error("expected at least one rule after loading defaults")
	}
	t.Logf("loaded %d builtin Sigma rules", count)
}

func TestRuleCount(t *testing.T) {
	e := NewEngine()
	e.LoadBuiltinRules()
	count := e.GetRuleCount()
	if count < 20 {
		t.Errorf("expected at least 20 rules, got %d", count)
	}
}
