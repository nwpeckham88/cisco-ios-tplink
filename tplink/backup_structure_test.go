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
		if run.Offset <= 100 && (run.Offset+run.Length-1) >= 100 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected undocumented run covering offset 100, got %+v", report.UndocumentedChangedRuns)
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

func TestKnownBackupStructureRangesIncludeControlFlags(t *testing.T) {
	ranges := knownBackupStructureRanges()
	labelsByOffset := map[int]string{}
	for _, r := range ranges {
		labelsByOffset[r.Offset] = r.Label
	}

	want := map[int]string{
		offsetMirrorDestination:                             "mirror destination port",
		offsetPortVLANMatrixBase + (0 * portVLANMatrixStride): "port-vlan matrix gi1",
		offsetPortVLANMatrixBase + (7 * portVLANMatrixStride): "port-vlan matrix gi8",
		offsetPortVLANPortIDs + 0:                             "port-vlan id gi1",
		offsetPortVLANPortIDs + 7:                             "port-vlan id gi8",
		offsetPortVLANModeA:                                   "port-vlan mode signature a",
		offsetPortVLANModeB:                                   "port-vlan mode signature b",
		offsetQoSPort1Priority:                                "qos gi1 priority",
		offsetQoSPort2Priority:                                "qos gi2 priority",
		offsetQoSPort3Priority:                                "qos gi3 priority",
		offsetQoSPort4Priority:                                "qos gi4 priority",
		offsetQoSPort5Priority:                                "qos gi5 priority",
		offsetQoSPort6Priority:                                "qos gi6 priority",
		offsetQoSPort7Priority:                                "qos gi7 priority",
		offsetQoSPort8Priority:                                "qos gi8 priority",
		offsetLoopPreventionFlag:                              "loop prevention flag",
		offsetLoopPreventionMode:                              "loop prevention mode",
		offsetIGMPFlag:                                        "igmp snooping flag",
		offsetIGMPReportSuppFlag:                              "igmp report-suppression flag",
		offsetQoSModeSigA:                                     "qos mode signature a",
		offsetQoSModeSigB:                                     "qos mode signature b",
		offsetQoSModeSigC:                                     "qos mode signature c",
		offsetLEDFlag:                                         "led flag",
	}
	for offset, label := range want {
		got, ok := labelsByOffset[offset]
		if !ok {
			t.Fatalf("missing known range at offset 0x%04x", offset)
		}
		if got != label {
			t.Fatalf("range label at 0x%04x = %q want %q", offset, got, label)
		}
	}
}

func TestKnownBackupStructureRangesIncludeStormControlMatrix(t *testing.T) {
	ranges := knownBackupStructureRanges()
	labelsByOffset := map[int]string{}
	stormCount := 0
	for _, r := range ranges {
		labelsByOffset[r.Offset] = r.Label
		if strings.HasPrefix(r.Label, "storm gi") {
			stormCount++
		}
	}

	if stormCount != stormControlPortCount*stormControlSlotCount {
		t.Fatalf("storm known range count = %d, want %d", stormCount, stormControlPortCount*stormControlSlotCount)
	}

	want := map[int]string{
		stormControlOffset(0, 0): "storm gi1 broadcast",
		stormControlOffset(0, 1): "storm gi1 multicast",
		stormControlOffset(0, 2): "storm gi1 unknown-unicast",
		stormControlOffset(0, 3): "storm gi1 all",
		stormControlOffset(1, 0): "storm gi2 broadcast",
		stormControlOffset(1, 2): "storm gi2 unknown-unicast",
		stormControlOffset(7, 3): "storm gi8 all",
	}
	for offset, label := range want {
		got, ok := labelsByOffset[offset]
		if !ok {
			t.Fatalf("missing known storm range at offset 0x%04x", offset)
		}
		if got != label {
			t.Fatalf("storm range label at 0x%04x = %q want %q", offset, got, label)
		}
	}
}
