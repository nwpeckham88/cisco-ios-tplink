package tplink

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func buildSyntheticBackup() []byte {
	data := make([]byte, 2258)
	data[0] = 0x23
	data[1] = 0x89
	data[2] = 0x23
	data[3] = 0x89

	copy(data[5:9], []byte{192, 168, 3, 49})
	copy(data[9:13], []byte{255, 255, 254, 0})
	copy(data[13:17], []byte{192, 168, 2, 1})
	data[16] = 1 // DHCP enabled

	copy(data[23:], []byte("TPLINK-DIST-SWITCH\x00"))
	copy(data[0x4a6:], []byte("Default\x00"))

	copy(data[0x2c:0x4c], []byte{
		0xbb, 0x65, 0xaf, 0xa3, 0x58, 0x40, 0x92, 0x13,
		0x3a, 0x4b, 0x4a, 0x00, 0x3d, 0x10, 0x07, 0x6d,
		0x13, 0xbe, 0xb0, 0xb2, 0xfb, 0x6b, 0x06, 0xc3,
		0x14, 0x95, 0x7e, 0x95, 0x00, 0x28, 0x11, 0x19,
	})
	copy(data[0x4c:0x51], []byte{0x70, 0x0d, 0xdf, 0xc3, 0xc1})
	data[0x00de] = 0x00 // mirror destination disabled
	data[0x19c] = 0x01  // port-vlan member mask (gi1)
	for i := 1; i < 8; i++ {
		data[0x19c+(i*4)] = 0xfe
	}
	data[0x418] = 0x02 // port-vlan ID table
	for i := 1; i < 8; i++ {
		data[0x418+i] = 0x01
	}
	data[0x3f4] = 0x01 // Port-VLAN mode signature: disabled
	data[0x3f5] = 0x02
	data[0x7e4] = 0x00 // gi1 QoS priority 1
	data[0x831] = 1    // Loop prevention enabled
	data[0x83b] = 0xff // Loop prevention mode/sentinel
	data[0x83e] = 1    // IGMP snooping enabled
	data[0x83f] = 0    // IGMP report suppression disabled
	data[0x847] = 0x04 // QoS mode signature: DSCP
	data[0x84b] = 0x05
	data[0x853] = 0x06
	data[0x8c8] = 1 // LED enabled

	return data
}

func TestDecodeBackupConfigParsesKnownOffsets(t *testing.T) {
	decoded, err := DecodeBackupConfig(buildSyntheticBackup())
	if err != nil {
		t.Fatalf("DecodeBackupConfig() error = %v", err)
	}

	if decoded.Magic != 0x23892389 {
		t.Fatalf("Magic = %#x", decoded.Magic)
	}
	if decoded.Size != 2258 {
		t.Fatalf("Size = %d", decoded.Size)
	}
	if decoded.Hostname != "TPLINK-DIST-SWITCH" {
		t.Fatalf("Hostname = %q", decoded.Hostname)
	}
	if decoded.IP != "192.168.3.49" {
		t.Fatalf("IP = %q", decoded.IP)
	}
	if decoded.Netmask != "255.255.254.0" {
		t.Fatalf("Netmask = %q", decoded.Netmask)
	}
	if decoded.Gateway != "192.168.2.1" {
		t.Fatalf("Gateway = %q", decoded.Gateway)
	}
	if !decoded.DHCPEnabled {
		t.Fatal("DHCPEnabled = false, want true")
	}
	if !decoded.MirrorDestinationPresent || !decoded.MirrorDestinationKnown || decoded.MirrorDestinationPort != 0 {
		t.Fatalf("Mirror destination decode = present:%t known:%t port:%d, want present:true known:true port:0", decoded.MirrorDestinationPresent, decoded.MirrorDestinationKnown, decoded.MirrorDestinationPort)
	}
	if !decoded.PortVLANModePresent || !decoded.PortVLANModeKnown || decoded.PortVLANModeEnabled {
		t.Fatalf("PortVLAN mode decode = present:%t known:%t enabled:%t, want present:true known:true enabled:false", decoded.PortVLANModePresent, decoded.PortVLANModeKnown, decoded.PortVLANModeEnabled)
	}
	if !decoded.PortVLANMatrixPresent || decoded.PortVLANMatrix[0] != 0x01 {
		t.Fatalf("PortVLAN matrix decode = present:%t gi1mask:0x%02x, want present:true gi1mask:0x01", decoded.PortVLANMatrixPresent, decoded.PortVLANMatrix[0])
	}
	if !decoded.PortVLANPortIDsPresent || decoded.PortVLANPortIDs[0] != 2 || decoded.PortVLANPortIDs[1] != 1 {
		t.Fatalf("PortVLAN IDs decode unexpected: present:%t ids:%v", decoded.PortVLANPortIDsPresent, decoded.PortVLANPortIDs)
	}
	if !decoded.QoSModePresent || !decoded.QoSModeKnown || decoded.QoSMode != "dscp" {
		t.Fatalf("QoS decode = present:%t known:%t mode:%q, want present:true known:true mode:dscp", decoded.QoSModePresent, decoded.QoSModeKnown, decoded.QoSMode)
	}
	if !decoded.QoSPort1PriorityPresent || !decoded.QoSPort1PriorityKnown || decoded.QoSPort1Priority != 1 {
		t.Fatalf("QoS gi1 priority decode = present:%t known:%t priority:%d, want present:true known:true priority:1", decoded.QoSPort1PriorityPresent, decoded.QoSPort1PriorityKnown, decoded.QoSPort1Priority)
	}
	if !decoded.QoSPortPrioritiesPresent || !decoded.QoSPortPrioritiesKnown {
		t.Fatalf("QoS priority map decode = present:%t known:%t, want present:true known:true", decoded.QoSPortPrioritiesPresent, decoded.QoSPortPrioritiesKnown)
	}
	for i := 0; i < 8; i++ {
		if decoded.QoSPortPriorities[i] != 1 {
			t.Fatalf("QoS priority map gi%d=%d want 1", i+1, decoded.QoSPortPriorities[i])
		}
	}
	if !decoded.LoopPreventionPresent || !decoded.LoopPreventionEnabled {
		t.Fatalf("loop prevention decode = present:%t enabled:%t, want present:true enabled:true", decoded.LoopPreventionPresent, decoded.LoopPreventionEnabled)
	}
	if !decoded.StormControlPresent {
		t.Fatal("StormControlPresent = false, want true")
	}
	for port := 0; port < stormControlPortCount; port++ {
		for slot := 0; slot < stormControlSlotCount; slot++ {
			if decoded.StormControlRaw[port][slot] != 0x00 {
				t.Fatalf("StormControlRaw[gi%d][slot%d] = 0x%02x, want 0x00", port+1, slot, decoded.StormControlRaw[port][slot])
			}
		}
	}
	if !decoded.IGMPSnoopingEnabled {
		t.Fatal("IGMPSnoopingEnabled = false, want true")
	}
	if !decoded.IGMPReportSuppressionPresent || decoded.IGMPReportSuppressionEnabled {
		t.Fatalf("IGMP report suppression decode = present:%t enabled:%t, want present:true enabled:false", decoded.IGMPReportSuppressionPresent, decoded.IGMPReportSuppressionEnabled)
	}
	if decoded.VLANName != "Default" {
		t.Fatalf("VLANName = %q", decoded.VLANName)
	}
	if !decoded.LEDEnabled {
		t.Fatal("LEDEnabled = false, want true")
	}
	if len(decoded.CredentialBlob) != 32 {
		t.Fatalf("CredentialBlob length = %d", len(decoded.CredentialBlob))
	}
}

func TestAnalyzeCredentialBlobDetectsMD5Candidate(t *testing.T) {
	d := md5.Sum([]byte("admin"))
	blob := append(bytes.Clone(d[:]), make([]byte, 16)...)
	report := AnalyzeCredentialBlob(blob)

	if len(report.CandidateMatches) == 0 {
		t.Fatal("expected at least one candidate match")
	}
}

func TestAnalyzeCredentialBlobNoSimpleHashMatch(t *testing.T) {
	blob := []byte{
		0xbb, 0x65, 0xaf, 0xa3, 0x58, 0x40, 0x92, 0x13,
		0x3a, 0x4b, 0x4a, 0x00, 0x3d, 0x10, 0x07, 0x6d,
		0x13, 0xbe, 0xb0, 0xb2, 0xfb, 0x6b, 0x06, 0xc3,
		0x14, 0x95, 0x7e, 0x95, 0x00, 0x28, 0x11, 0x19,
	}
	report := AnalyzeCredentialBlob(blob)

	if len(report.CandidateMatches) != 0 {
		t.Fatalf("unexpected candidate matches: %v", report.CandidateMatches)
	}
}

func TestDecodeBackupConfigErrorsOnShortInput(t *testing.T) {
	_, err := DecodeBackupConfig(make([]byte, 12))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestDecodeBackupConfigErrorsOnBadMagic(t *testing.T) {
	data := buildSyntheticBackup()
	data[0] = 0
	_, err := DecodeBackupConfig(data)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestAnalyzeCredentialBlobDeduplicatesMatches(t *testing.T) {
	sum := sha256.Sum256([]byte("admin"))
	report := AnalyzeCredentialBlob(sum[:])

	if len(report.CandidateMatches) == 0 {
		t.Fatal("expected at least one candidate match")
	}
	joined := strings.Join(report.CandidateMatches, "\n")
	if strings.Count(joined, "candidate=\"admin\"") > 1 {
		t.Fatalf("expected deduplicated matches, got %v", report.CandidateMatches)
	}
}

func TestFormatDecodedBackupIncludesCoreFields(t *testing.T) {
	decoded, err := DecodeBackupConfig(buildSyntheticBackup())
	if err != nil {
		t.Fatalf("DecodeBackupConfig() error = %v", err)
	}

	output := FormatDecodedBackup(decoded)
	checks := []string{
		"Backup Decode (best-effort)",
		"Hostname   : TPLINK-DIST-SWITCH",
		"IP         : 192.168.3.49",
		"Netmask    : 255.255.254.0",
		"Gateway    : 192.168.2.1",
		"DHCP       : enabled",
		"Mirror dst : disabled",
		"Port VLAN  : disabled",
		"Port VLAN M: gi1",
		"Port VLAN I: gi1=2,gi2=1,gi3=1,gi4=1,gi5=1,gi6=1,gi7=1,gi8=1",
		"QoS mode   : dscp",
		"QoS pri map: gi1=1,gi2=1,gi3=1,gi4=1,gi5=1,gi6=1,gi7=1,gi8=1",
		"QoS gi1 pri: 1",
		"Storm ctl  : all-off",
		"STP        : enabled",
		"IGMP       : enabled",
		"IGMP RS    : disabled",
		"LED        : on",
		"VLAN name  : Default",
		"Credential Block (offset 0x2c, 32 bytes)",
		"Password   : testpass",
		"Matches    : none against default credential candidates",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("expected output to contain %q\n%s", check, output)
		}
	}
}

func TestDecodeBackupConfigRecoversPasswordFromKnownObfuscation(t *testing.T) {
	decoded, err := DecodeBackupConfig(buildSyntheticBackup())
	if err != nil {
		t.Fatalf("DecodeBackupConfig() error = %v", err)
	}

	if decoded.CredentialInfo.RecoveredPassword != FirmwarePassword {
		t.Fatalf("RecoveredPassword = %q, want %q", decoded.CredentialInfo.RecoveredPassword, FirmwarePassword)
	}
	if decoded.CredentialInfo.ObfuscatedPasswordHex != "281119700ddfc3c1" {
		t.Fatalf("ObfuscatedPasswordHex = %q", decoded.CredentialInfo.ObfuscatedPasswordHex)
	}
}

func TestDecodeBackupConfigRecoversNullPaddedShortPassword(t *testing.T) {
	data := buildSyntheticBackup()
	for i := 0; i < obfuscatedPasswordLen; i++ {
		data[offsetObfuscatedPassword+i] = knownPasswordXORKey[i]
	}
	short := []byte("secret")
	for i := 0; i < len(short); i++ {
		data[offsetObfuscatedPassword+i] = short[i] ^ knownPasswordXORKey[i]
	}

	decoded, err := DecodeBackupConfig(data)
	if err != nil {
		t.Fatalf("DecodeBackupConfig() error = %v", err)
	}
	if decoded.CredentialInfo.RecoveredPassword != "secret" {
		t.Fatalf("RecoveredPassword = %q, want %q", decoded.CredentialInfo.RecoveredPassword, "secret")
	}
}

func TestCompareBackupConfigsDetectsFieldAndCredentialChanges(t *testing.T) {
	base := buildSyntheticBackup()
	modified := buildSyntheticBackup()

	copy(modified[5:9], []byte{10, 0, 0, 42})
	modified[0x2c] ^= 0xff

	report, err := CompareBackupConfigs(base, modified)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	if report.ChangedByteCount != 5 {
		t.Fatalf("ChangedByteCount = %d, want 5", report.ChangedByteCount)
	}
	if !report.CredentialBlockChanged {
		t.Fatal("CredentialBlockChanged = false, want true")
	}
	if report.CredentialBlockChangedBytes != 1 {
		t.Fatalf("CredentialBlockChangedBytes = %d, want 1", report.CredentialBlockChangedBytes)
	}

	joinedFields := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joinedFields, "IP") {
		t.Fatalf("expected IP in field changes, got %q", joinedFields)
	}
}

func TestFormatBackupDiffIncludesSummaryAndRuns(t *testing.T) {
	base := buildSyntheticBackup()
	modified := buildSyntheticBackup()

	modified[5] = 172
	modified[6] = 16
	modified[7] = 8
	modified[8] = 99

	report, err := CompareBackupConfigs(base, modified)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	output := FormatBackupDiff(report)
	checks := []string{
		"Backup Diff (best-effort)",
		"Compared   :",
		"Changed    :",
		"Runs       :",
		"Field changes",
		"IP",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("expected output to contain %q\n%s", check, output)
		}
	}
}

func TestFormatDecodedBackupIncludesCredentialPolicyContext(t *testing.T) {
	decoded, err := DecodeBackupConfig(buildSyntheticBackup())
	if err != nil {
		t.Fatalf("DecodeBackupConfig() error = %v", err)
	}
	output := FormatDecodedBackup(decoded)
	checks := []string{
		"Policy     : username 1-16 [A-Za-z0-9_], password 6-16 [A-Za-z0-9_]",
		"Coverage   : password decode currently mapped to 8-byte obfuscated slot at 0x49",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Fatalf("expected output to contain %q\n%s", check, output)
		}
	}
}

func TestFormatBackupDiffPercentageNotOverHundredOnSizeDelta(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	for i := 4; i < len(candidate); i++ {
		candidate[i] ^= 0xff
	}
	candidate = append(candidate, 0xaa, 0xbb, 0xcc, 0xdd)

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	output := FormatBackupDiff(report)
	re := regexp.MustCompile(`Changed\s+:\s+\d+ bytes \(([0-9]+\.[0-9]+)%\)`)
	m := re.FindStringSubmatch(output)
	if len(m) != 2 {
		t.Fatalf("could not parse changed percent from output:\n%s", output)
	}
	pct, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatalf("ParseFloat(%q): %v", m[1], err)
	}
	if pct > 100.0 {
		t.Fatalf("changed percent = %.2f, want <= 100.0", pct)
	}
}

func TestCompareBackupConfigsIncludesRecoveredPasswordFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	for i, ch := range []byte("passtest") {
		candidate[offsetObfuscatedPassword+i] = ch ^ knownPasswordXORKey[i]
	}

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `Password (obfuscated@0x49): "testpass" -> "passtest"`) {
		t.Fatalf("expected recovered password field change, got %q", joined)
	}
	if report.PasswordSlotChangedBytes != 6 {
		t.Fatalf("PasswordSlotChangedBytes = %d, want 6", report.PasswordSlotChangedBytes)
	}
}

func TestCompareBackupConfigsTracksPasswordSlotOutsideCredentialBlob(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	// offset 0x4c is inside obfuscated password slot but outside 0x2c..0x4b blob
	candidate[offsetObfuscatedPassword+3] = 's' ^ knownPasswordXORKey[3]

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}
	if report.CredentialBlockChangedBytes != 0 {
		t.Fatalf("CredentialBlockChangedBytes = %d, want 0", report.CredentialBlockChangedBytes)
	}
	if !report.PasswordSlotChanged {
		t.Fatal("PasswordSlotChanged = false, want true")
	}
	if report.PasswordSlotChangedBytes != 1 {
		t.Fatalf("PasswordSlotChangedBytes = %d, want 1", report.PasswordSlotChangedBytes)
	}
	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `Password (obfuscated@0x49): "testpass" -> "tesspass"`) {
		t.Fatalf("expected password field change from slot delta, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesLEDFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	candidate[0x8c8] = 0

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `LED: "on" -> "off"`) {
		t.Fatalf("expected LED field change, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesIGMPFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	candidate[0x83e] = 0

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `IGMP: "enabled" -> "disabled"`) {
		t.Fatalf("expected IGMP field change, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesIGMPReportSuppressionFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	candidate[0x83f] = 1

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `IGMP report-suppression: "disabled" -> "enabled"`) {
		t.Fatalf("expected IGMP report-suppression field change, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesQoSModeFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	// dot1p signature observed from live captures
	candidate[0x847] = 0x05
	candidate[0x84b] = 0x06
	candidate[0x853] = 0x00

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `QoS mode: "dscp" -> "dot1p"`) {
		t.Fatalf("expected QoS mode field change, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesPortVLANModeFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	// Enabled signature observed from live capture.
	candidate[offsetPortVLANModeA] = 0x00
	candidate[offsetPortVLANModeB] = 0x01

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `Port VLAN mode: "disabled" -> "enabled"`) {
		t.Fatalf("expected Port VLAN mode field change, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesMirrorDestinationFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	candidate[offsetMirrorDestination] = 0x03

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `Mirror destination: "disabled" -> "gi3"`) {
		t.Fatalf("expected Mirror destination field change, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesPortVLANMembersFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	// Add gi2 to member mask for row gi1.
	candidate[offsetPortVLANMatrixBase] = 0x03

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `Port VLAN members: "gi1" -> "gi1,gi2"`) {
		t.Fatalf("expected Port VLAN members field change, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesPortVLANIDsFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	// gi2 changes from ID 1 to 2 when included in pvlan members.
	candidate[offsetPortVLANPortIDs+1] = 0x02

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `Port VLAN IDs: "gi1=2,gi2=1,gi3=1,gi4=1,gi5=1,gi6=1,gi7=1,gi8=1" -> "gi1=2,gi2=2,gi3=1,gi4=1,gi5=1,gi6=1,gi7=1,gi8=1"`) {
		t.Fatalf("expected Port VLAN IDs field change, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesQoSPortPriorityFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	// gi1 priority 2
	candidate[0x7e4] = 0x02

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `QoS gi1 priority: "1" -> "2"`) {
		t.Fatalf("expected QoS gi1 priority field change, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesQoSPortPriorityMapFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	// gi2 priority 2 (offset mapped from live sweep)
	candidate[0x7eb] = 0x02

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `QoS priorities: "gi1=1,gi2=1,gi3=1,gi4=1,gi5=1,gi6=1,gi7=1,gi8=1" -> "gi1=1,gi2=2,gi3=1,gi4=1,gi5=1,gi6=1,gi7=1,gi8=1"`) {
		t.Fatalf("expected QoS priorities map field change, got %q", joined)
	}
}

func TestCompareBackupConfigsIncludesSpanningTreeFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	candidate[0x831] = 0

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `Spanning tree: "enabled" -> "disabled"`) {
		t.Fatalf("expected spanning tree field change, got %q", joined)
	}
}

func TestDecodeBackupConfigParsesStormControlOffsets(t *testing.T) {
	data := buildSyntheticBackup()
	data[stormControlOffset(0, 0)] = stormControlEnabledValue // gi1 broadcast
	data[stormControlOffset(0, 2)] = stormControlEnabledValue // gi1 unknown-unicast
	data[stormControlOffset(1, 0)] = stormControlEnabledValue // gi2 broadcast
	data[stormControlOffset(1, 2)] = stormControlEnabledValue // gi2 unknown-unicast

	decoded, err := DecodeBackupConfig(data)
	if err != nil {
		t.Fatalf("DecodeBackupConfig() error = %v", err)
	}
	if !decoded.StormControlPresent {
		t.Fatal("StormControlPresent = false, want true")
	}
	if decoded.StormControlRaw[0][0] != stormControlEnabledValue {
		t.Fatalf("StormControlRaw gi1 broadcast = 0x%02x, want 0x%02x", decoded.StormControlRaw[0][0], stormControlEnabledValue)
	}
	if decoded.StormControlRaw[0][2] != stormControlEnabledValue {
		t.Fatalf("StormControlRaw gi1 unknown-unicast = 0x%02x, want 0x%02x", decoded.StormControlRaw[0][2], stormControlEnabledValue)
	}
	if decoded.StormControlRaw[1][0] != stormControlEnabledValue {
		t.Fatalf("StormControlRaw gi2 broadcast = 0x%02x, want 0x%02x", decoded.StormControlRaw[1][0], stormControlEnabledValue)
	}
	if decoded.StormControlRaw[1][2] != stormControlEnabledValue {
		t.Fatalf("StormControlRaw gi2 unknown-unicast = 0x%02x, want 0x%02x", decoded.StormControlRaw[1][2], stormControlEnabledValue)
	}
}

func TestCompareBackupConfigsIncludesStormControlFieldChange(t *testing.T) {
	base := buildSyntheticBackup()
	candidate := buildSyntheticBackup()

	candidate[stormControlOffset(0, 0)] = stormControlEnabledValue // gi1 broadcast
	candidate[stormControlOffset(1, 2)] = stormControlEnabledValue // gi2 unknown-unicast

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if !strings.Contains(joined, `Storm gi1 broadcast: "off" -> "on"`) {
		t.Fatalf("expected gi1 storm broadcast field change, got %q", joined)
	}
	if !strings.Contains(joined, `Storm gi2 unknown-unicast: "off" -> "on"`) {
		t.Fatalf("expected gi2 storm unknown-unicast field change, got %q", joined)
	}
}

func TestFormatDecodedBackupIncludesStormControlEnabledSummary(t *testing.T) {
	data := buildSyntheticBackup()
	data[stormControlOffset(0, 0)] = stormControlEnabledValue // gi1 broadcast
	data[stormControlOffset(1, 2)] = stormControlEnabledValue // gi2 unknown-unicast

	decoded, err := DecodeBackupConfig(data)
	if err != nil {
		t.Fatalf("DecodeBackupConfig() error = %v", err)
	}

	output := FormatDecodedBackup(decoded)
	if !strings.Contains(output, "Storm ctl  : gi1:broadcast,gi2:unknown-unicast") {
		t.Fatalf("expected storm control summary in output, got:\n%s", output)
	}
}

func TestFormatDecodedBackupShowsUnknownForAbsentOptionalFlags(t *testing.T) {
	data := buildSyntheticBackup()
	// Keep minimum valid decode length while excluding IGMP/LED offsets.
	data = data[:offsetVLANName+maxVLANNameLen]

	decoded, err := DecodeBackupConfig(data)
	if err != nil {
		t.Fatalf("DecodeBackupConfig() error = %v", err)
	}

	output := FormatDecodedBackup(decoded)
	if !strings.Contains(output, "STP        : unknown") {
		t.Fatalf("expected STP unknown, got:\n%s", output)
	}
	if !strings.Contains(output, "IGMP       : unknown") {
		t.Fatalf("expected IGMP unknown, got:\n%s", output)
	}
	if !strings.Contains(output, "QoS mode   : unknown") {
		t.Fatalf("expected QoS mode unknown, got:\n%s", output)
	}
	if !strings.Contains(output, "QoS pri map: unknown") {
		t.Fatalf("expected QoS priority map unknown, got:\n%s", output)
	}
	if !strings.Contains(output, "QoS gi1 pri: unknown") {
		t.Fatalf("expected QoS gi1 priority unknown, got:\n%s", output)
	}
	if !strings.Contains(output, "Storm ctl  : all-off") {
		t.Fatalf("expected storm control all-off, got:\n%s", output)
	}
	if !strings.Contains(output, "IGMP RS    : unknown") {
		t.Fatalf("expected IGMP RS unknown, got:\n%s", output)
	}
	if !strings.Contains(output, "LED        : unknown") {
		t.Fatalf("expected LED unknown, got:\n%s", output)
	}
}

func TestCompareBackupConfigsSkipsOptionalFlagDiffWhenAbsent(t *testing.T) {
	base := buildSyntheticBackup()[:offsetVLANName+maxVLANNameLen]
	candidate := buildSyntheticBackup()[:offsetVLANName+maxVLANNameLen]

	report, err := CompareBackupConfigs(base, candidate)
	if err != nil {
		t.Fatalf("CompareBackupConfigs() error = %v", err)
	}

	joined := strings.Join(report.FieldChanges, "\n")
	if strings.Contains(joined, "QoS mode:") || strings.Contains(joined, "QoS priorities:") || strings.Contains(joined, "QoS gi1 priority:") || strings.Contains(joined, "Storm gi") || strings.Contains(joined, "Spanning tree:") || strings.Contains(joined, "IGMP:") || strings.Contains(joined, "IGMP report-suppression:") || strings.Contains(joined, "LED:") {
		t.Fatalf("did not expect optional flag diff when bytes absent, got %q", joined)
	}
}
