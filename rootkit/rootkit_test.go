//go:build linux

package rootkit

import (
	"testing"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
}

func TestScanReturnsFindings(t *testing.T) {
	d := NewDetector()
	findings := d.Scan()
	if findings == nil {
		t.Fatal("expected non-nil findings slice")
	}
	t.Logf("rootkit scan found %d findings", len(findings))
}

func TestScanIsIdempotent(t *testing.T) {
	d := NewDetector()
	findings1 := d.Scan()
	findings2 := d.Scan()
	if len(findings1) != len(findings2) {
		t.Errorf("expected consistent results: %d vs %d", len(findings1), len(findings2))
	}
}

func TestBaselineCreation(t *testing.T) {
	d := NewDetector()
	baseline, err := d.CreateBaseline()
	if err != nil {
		t.Fatalf("failed to create baseline: %v", err)
	}
	if baseline == nil {
		t.Fatal("expected non-nil baseline")
	}
	if baseline.ProcessList == nil {
		t.Error("expected non-nil process list")
	}
	if baseline.KernelModules == nil {
		t.Error("expected non-nil kernel modules")
	}
}
