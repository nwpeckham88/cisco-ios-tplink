package tplink

import (
	"fmt"
	"sort"
	"strings"
)

type BackupStructureRange struct {
	Offset int
	Length int
	Label  string
}

type BackupStructureSample struct {
	Name             string
	Size             int
	ChangedByteCount int
	ChangedRuns      []BackupDiffRun
}

type BackupStructureReport struct {
	BaselineName            string
	BaselineSize            int
	ComparedSpan            int
	SampleCount             int
	KnownRanges             []BackupStructureRange
	UnionChangedRuns        []BackupDiffRun
	UndocumentedChangedRuns []BackupDiffRun
	UnknownStaticRanges     []BackupDiffRun
	Samples                 []BackupStructureSample
}

func InferBackupStructure(baselineName string, baseline []byte, samples map[string][]byte) (BackupStructureReport, error) {
	if len(baseline) == 0 {
		return BackupStructureReport{}, fmt.Errorf("baseline backup must not be empty")
	}
	if len(samples) == 0 {
		return BackupStructureReport{}, fmt.Errorf("at least one sample backup is required")
	}

	names := make([]string, 0, len(samples))
	maxLen := len(baseline)
	for name, sample := range samples {
		if strings.TrimSpace(name) == "" {
			return BackupStructureReport{}, fmt.Errorf("sample name must not be empty")
		}
		names = append(names, name)
		if len(sample) > maxLen {
			maxLen = len(sample)
		}
	}
	sort.Strings(names)

	report := BackupStructureReport{
		BaselineName: baselineName,
		BaselineSize: len(baseline),
		ComparedSpan: maxLen,
		SampleCount:  len(samples),
		KnownRanges:  knownBackupStructureRanges(),
		Samples:      make([]BackupStructureSample, 0, len(samples)),
	}

	allChanged := make([]BackupDiffRun, 0)
	for _, name := range names {
		sample := samples[name]
		runs, changedByteCount := computeChangedRuns(baseline, sample)
		report.Samples = append(report.Samples, BackupStructureSample{
			Name:             name,
			Size:             len(sample),
			ChangedByteCount: changedByteCount,
			ChangedRuns:      runs,
		})
		allChanged = append(allChanged, runs...)
	}

	report.UnionChangedRuns = mergeRuns(allChanged)

	knownRuns := make([]BackupDiffRun, 0, len(report.KnownRanges))
	for _, entry := range report.KnownRanges {
		knownRuns = append(knownRuns, BackupDiffRun{Offset: entry.Offset, Length: entry.Length})
	}
	knownRuns = mergeRuns(knownRuns)

	report.UndocumentedChangedRuns = subtractRuns(report.UnionChangedRuns, knownRuns)

	coverage := append([]BackupDiffRun{}, knownRuns...)
	coverage = append(coverage, report.UnionChangedRuns...)
	coverage = mergeRuns(coverage)
	report.UnknownStaticRanges = complementRuns(coverage, report.ComparedSpan)

	return report, nil
}

func FormatBackupStructureReport(report BackupStructureReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Backup Structure Inference\n")
	fmt.Fprintf(&b, "  Baseline            : %s (%d bytes)\n", fallback(report.BaselineName, "(unnamed)"), report.BaselineSize)
	fmt.Fprintf(&b, "  Compared span       : %d bytes\n", report.ComparedSpan)
	fmt.Fprintf(&b, "  Samples             : %d\n", report.SampleCount)

	fmt.Fprintf(&b, "\nKnown ranges\n")
	for _, entry := range report.KnownRanges {
		end := entry.Offset + entry.Length - 1
		fmt.Fprintf(&b, "  - 0x%04x..0x%04x (%d bytes): %s\n", entry.Offset, end, entry.Length, entry.Label)
	}

	fmt.Fprintf(&b, "\nUnion changed ranges\n")
	if len(report.UnionChangedRuns) == 0 {
		fmt.Fprintf(&b, "  (none)\n")
	} else {
		for _, run := range report.UnionChangedRuns {
			end := run.Offset + run.Length - 1
			fmt.Fprintf(&b, "  - 0x%04x..0x%04x (%d bytes)\n", run.Offset, end, run.Length)
		}
	}

	fmt.Fprintf(&b, "\nUndocumented changed ranges\n")
	if len(report.UndocumentedChangedRuns) == 0 {
		fmt.Fprintf(&b, "  (none)\n")
	} else {
		for _, run := range report.UndocumentedChangedRuns {
			end := run.Offset + run.Length - 1
			fmt.Fprintf(&b, "  - 0x%04x..0x%04x (%d bytes)\n", run.Offset, end, run.Length)
		}
	}

	fmt.Fprintf(&b, "\nUnknown static ranges\n")
	if len(report.UnknownStaticRanges) == 0 {
		fmt.Fprintf(&b, "  (none)\n")
	} else {
		for _, run := range report.UnknownStaticRanges {
			end := run.Offset + run.Length - 1
			fmt.Fprintf(&b, "  - 0x%04x..0x%04x (%d bytes)\n", run.Offset, end, run.Length)
		}
	}

	fmt.Fprintf(&b, "\nSample deltas\n")
	for _, sample := range report.Samples {
		fmt.Fprintf(&b, "  - %s: %d changed bytes across %d runs\n", sample.Name, sample.ChangedByteCount, len(sample.ChangedRuns))
	}
	return b.String()
}

func knownBackupStructureRanges() []BackupStructureRange {
	return []BackupStructureRange{
		{Offset: 0x00, Length: 4, Label: "magic"},
		{Offset: offsetIP, Length: 4, Label: "ip"},
		{Offset: offsetNetmask, Length: 4, Label: "netmask"},
		{Offset: offsetGateway, Length: 4, Label: "gateway"},
		{Offset: offsetDHCPFlag, Length: 1, Label: "dhcp flag"},
		{Offset: offsetHostname, Length: maxHostnameLen, Label: "hostname"},
		{Offset: offsetCredentialBlob, Length: credentialBlobLen, Label: "credential blob"},
		{Offset: offsetObfuscatedPassword, Length: obfuscatedPasswordLen, Label: "obfuscated password slot"},
		{Offset: offsetVLANName, Length: maxVLANNameLen, Label: "vlan name"},
	}
}

func computeChangedRuns(base []byte, candidate []byte) ([]BackupDiffRun, int) {
	maxLen := len(base)
	if len(candidate) > maxLen {
		maxLen = len(candidate)
	}

	runs := make([]BackupDiffRun, 0)
	changed := 0
	runStart := -1
	runLen := 0
	for i := 0; i < maxLen; i++ {
		same := byteAt(base, i) == byteAt(candidate, i) && inRange(base, i) == inRange(candidate, i)
		if same {
			if runStart >= 0 {
				runs = append(runs, BackupDiffRun{Offset: runStart, Length: runLen})
				runStart = -1
				runLen = 0
			}
			continue
		}

		changed++
		if runStart < 0 {
			runStart = i
			runLen = 1
			continue
		}
		runLen++
	}
	if runStart >= 0 {
		runs = append(runs, BackupDiffRun{Offset: runStart, Length: runLen})
	}
	return runs, changed
}

func byteAt(data []byte, index int) byte {
	if !inRange(data, index) {
		return 0
	}
	return data[index]
}

func inRange(data []byte, index int) bool {
	return index >= 0 && index < len(data)
}

func mergeRuns(runs []BackupDiffRun) []BackupDiffRun {
	if len(runs) == 0 {
		return nil
	}
	copyRuns := append([]BackupDiffRun{}, runs...)
	sort.Slice(copyRuns, func(i, j int) bool {
		if copyRuns[i].Offset == copyRuns[j].Offset {
			return copyRuns[i].Length < copyRuns[j].Length
		}
		return copyRuns[i].Offset < copyRuns[j].Offset
	})

	merged := make([]BackupDiffRun, 0, len(copyRuns))
	for _, run := range copyRuns {
		if run.Length <= 0 {
			continue
		}
		if len(merged) == 0 {
			merged = append(merged, run)
			continue
		}
		last := &merged[len(merged)-1]
		lastEnd := last.Offset + last.Length
		runEnd := run.Offset + run.Length
		if run.Offset > lastEnd {
			merged = append(merged, run)
			continue
		}
		if runEnd > lastEnd {
			last.Length = runEnd - last.Offset
		}
	}
	return merged
}

func subtractRuns(runs []BackupDiffRun, subtract []BackupDiffRun) []BackupDiffRun {
	if len(runs) == 0 {
		return nil
	}
	if len(subtract) == 0 {
		return append([]BackupDiffRun{}, runs...)
	}

	runs = mergeRuns(runs)
	subtract = mergeRuns(subtract)
	result := make([]BackupDiffRun, 0)

	j := 0
	for _, run := range runs {
		currentStart := run.Offset
		runEnd := run.Offset + run.Length

		for j < len(subtract) && subtract[j].Offset+subtract[j].Length <= currentStart {
			j++
		}

		k := j
		for k < len(subtract) && subtract[k].Offset < runEnd {
			sub := subtract[k]
			subStart := sub.Offset
			subEnd := sub.Offset + sub.Length

			if subStart > currentStart {
				result = append(result, BackupDiffRun{Offset: currentStart, Length: subStart - currentStart})
			}
			if subEnd > currentStart {
				currentStart = subEnd
			}
			if currentStart >= runEnd {
				break
			}
			k++
		}

		if currentStart < runEnd {
			result = append(result, BackupDiffRun{Offset: currentStart, Length: runEnd - currentStart})
		}
	}

	return mergeRuns(result)
}

func complementRuns(covered []BackupDiffRun, span int) []BackupDiffRun {
	if span <= 0 {
		return nil
	}
	covered = mergeRuns(covered)
	if len(covered) == 0 {
		return []BackupDiffRun{{Offset: 0, Length: span}}
	}

	result := make([]BackupDiffRun, 0)
	cursor := 0
	for _, run := range covered {
		if run.Offset > span {
			break
		}
		start := run.Offset
		if start < 0 {
			start = 0
		}
		if start > cursor {
			result = append(result, BackupDiffRun{Offset: cursor, Length: start - cursor})
		}
		runEnd := run.Offset + run.Length
		if runEnd > cursor {
			cursor = runEnd
		}
		if cursor >= span {
			break
		}
	}
	if cursor < span {
		result = append(result, BackupDiffRun{Offset: cursor, Length: span - cursor})
	}
	return mergeRuns(result)
}
