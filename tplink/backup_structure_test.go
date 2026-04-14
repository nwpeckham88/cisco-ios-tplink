package tplink

import (
	"strings"
	"testing"
)

func TestInferBackupStructureDetectsUndocumentedRuns(t *testing.T) {
	baseline := buildSyntheticBackup()
	knownChanged := buildSyntheticBackup()
	copy(knownChanged[5:9], []byte{10, 0, 0, 42})

	undocumentedChanged := buildSyntheticBackup()
	undocumentedChanged[100] ^= 0xFF
	undocumentedChanged[101] ^= 0xFF

	report, err := InferBackupStructure("baseline", baseline, map[string][]byte{
		"known":        knownChanged,
		"undocumented": undocumentedChanged,
	})
	if err != nil {
		t.Fatalf("InferBackupStructure() error = %v", err)
	}

	if report.SampleCount != 2 {
		t.Fatalf("SampleCount = %d, want 2", report.SampleCount)
	}
	if len(report.UnionChangedRuns) == 0 {
		t.Fatal("expected union changed runs")
	}
	if len(report.UndocumentedChangedRuns) == 0 {
		t.Fatal("expected undocumented changed runs")
	}

	found := false
	for _, run := range report.UndocumentedChangedRuns {
		if run.Offset <= 100 && (run.Offset+run.Length-1) >= 101 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected undocumented run covering offsets 100..101, got %+v", report.UndocumentedChangedRuns)
	}
}

func TestFormatBackupStructureReportIncludesSections(t *testing.T) {
	baseline := buildSyntheticBackup()
	candidate := buildSyntheticBackup()
	candidate[200] ^= 0xAA

	report, err := InferBackupStructure("baseline", baseline, map[string][]byte{
		"candidate": candidate,
	})
	if err != nil {
		t.Fatalf("InferBackupStructure() error = %v", err)
	}

	output := FormatBackupStructureReport(report)
	checks := []string{
		"Backup Structure Inference",
		"Known ranges",
		"Union changed ranges",
		"Undocumented changed ranges",
		"Unknown static ranges",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("expected output to contain %q\n%s", check, output)
		}
	}
}

func TestInferBackupStructureRequiresSamples(t *testing.T) {
	_, err := InferBackupStructure("baseline", buildSyntheticBackup(), map[string][]byte{})
	if err == nil {
		t.Fatal("expected error for empty sample set")
	}
}
