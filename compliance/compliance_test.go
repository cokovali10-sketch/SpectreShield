//go:build linux

package compliance

import (
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestGetFrameworks(t *testing.T) {
	e := NewEngine()
	frameworks := e.GetFrameworks()
	if frameworks == nil {
		t.Fatal("expected non-nil frameworks")
	}
	if len(frameworks) == 0 {
		t.Error("expected at least one framework")
	}
	t.Logf("found %d compliance frameworks", len(frameworks))
}

func TestRunFrameworks(t *testing.T) {
	e := NewEngine()
	reports := e.RunFrameworks()
	if reports == nil {
		t.Fatal("expected non-nil reports")
	}
	if len(reports) == 0 {
		t.Error("expected at least one report")
	}
	for _, report := range reports {
		if report.Framework == "" {
			t.Error("report has empty framework")
		}
		if len(report.Results) == 0 {
			t.Errorf("framework %s has no controls", report.Framework)
		}
		t.Logf("framework: %s, controls: %d, passed: %d, failed: %d",
			report.Framework, len(report.Results), report.Passed, report.Failed)
	}
}
