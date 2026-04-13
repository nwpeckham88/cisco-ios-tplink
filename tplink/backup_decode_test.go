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
	if decoded.VLANName != "Default" {
		t.Fatalf("VLANName = %q", decoded.VLANName)
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
