package tplink

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	backupMagic              = 0x23892389
	offsetIP                 = 5
	offsetNetmask            = 9
	offsetGateway            = 13
	offsetDHCPFlag           = 16
	offsetHostname           = 23
	maxHostnameLen           = 32
	offsetCredentialBlob     = 0x2c
	credentialBlobLen        = 32
	offsetObfuscatedPassword = 0x49
	obfuscatedPasswordLen    = 8
	offsetVLANName           = 0x4a6
	maxVLANNameLen           = 32
	minUsernameLen           = 1
	maxUsernameLen           = 16
	minPasswordLen           = 6
	maxPasswordLen           = 16
)

var knownPasswordXORKey = [obfuscatedPasswordLen]byte{0x5c, 0x74, 0x6a, 0x04, 0x7d, 0xbe, 0xb0, 0xb2}

type BackupCredentialReport struct {
	BlobHex               string
	PrintableFragments    []string
	CandidateMatches      []string
	LikelyMeaning         string
	ObfuscatedPasswordHex string
	RecoveredPassword     string
	RecoveryMethod        string
}

type BackupDiffRun struct {
	Offset int
	Length int
}

type BackupDiffReport struct {
	BaseSize                    int
	CandidateSize               int
	ComparedBytes               int
	ChangedByteCount            int
	ChangedRuns                 []BackupDiffRun
	FieldChanges                []string
	CredentialBlockChanged      bool
	CredentialBlockChangedBytes int
	BaseCredentialHex           string
	CandidateCredentialHex      string
}

type DecodedBackupConfig struct {
	Size           int
	Magic          uint32
	IP             string
	Netmask        string
	Gateway        string
	DHCPEnabled    bool
	Hostname       string
	VLANName       string
	CredentialBlob []byte
	CredentialInfo BackupCredentialReport
}

func DecodeBackupConfig(data []byte) (DecodedBackupConfig, error) {
	minLen := offsetVLANName + maxVLANNameLen
	if len(data) < minLen {
		return DecodedBackupConfig{}, fmt.Errorf("backup too short: got %d bytes, want >= %d", len(data), minLen)
	}

	magic := binary.BigEndian.Uint32(data[:4])
	if magic != backupMagic {
		return DecodedBackupConfig{}, fmt.Errorf("unexpected backup magic: got %#x", magic)
	}

	cred := bytes.Clone(data[offsetCredentialBlob : offsetCredentialBlob+credentialBlobLen])
	decoded := DecodedBackupConfig{
		Size:           len(data),
		Magic:          magic,
		IP:             ip4String(data[offsetIP : offsetIP+4]),
		Netmask:        ip4String(data[offsetNetmask : offsetNetmask+4]),
		Gateway:        ip4String(data[offsetGateway : offsetGateway+4]),
		DHCPEnabled:    data[offsetDHCPFlag] != 0,
		Hostname:       readCString(data, offsetHostname, maxHostnameLen),
		VLANName:       readCString(data, offsetVLANName, maxVLANNameLen),
		CredentialBlob: cred,
		CredentialInfo: AnalyzeCredentialBlob(cred),
	}
	decoded.CredentialInfo.ObfuscatedPasswordHex, decoded.CredentialInfo.RecoveredPassword, decoded.CredentialInfo.RecoveryMethod = recoverObfuscatedPassword(data)
	return decoded, nil
}

func CompareBackupConfigs(base []byte, candidate []byte) (BackupDiffReport, error) {
	baseDecoded, err := DecodeBackupConfig(base)
	if err != nil {
		return BackupDiffReport{}, fmt.Errorf("decode base backup: %w", err)
	}
	candidateDecoded, err := DecodeBackupConfig(candidate)
	if err != nil {
		return BackupDiffReport{}, fmt.Errorf("decode candidate backup: %w", err)
	}

	compared := len(base)
	if len(candidate) < compared {
		compared = len(candidate)
	}

	report := BackupDiffReport{
		BaseSize:                    len(base),
		CandidateSize:               len(candidate),
		ComparedBytes:               compared,
		BaseCredentialHex:           hex.EncodeToString(baseDecoded.CredentialBlob),
		CandidateCredentialHex:      hex.EncodeToString(candidateDecoded.CredentialBlob),
		CredentialBlockChangedBytes: credentialDiffBytes(baseDecoded.CredentialBlob, candidateDecoded.CredentialBlob),
	}
	report.CredentialBlockChanged = report.CredentialBlockChangedBytes > 0

	runStart := -1
	runLen := 0
	for i := 0; i < compared; i++ {
		if base[i] == candidate[i] {
			if runStart >= 0 {
				report.ChangedRuns = append(report.ChangedRuns, BackupDiffRun{Offset: runStart, Length: runLen})
				runStart = -1
				runLen = 0
			}
			continue
		}

		report.ChangedByteCount++
		if runStart < 0 {
			runStart = i
			runLen = 1
			continue
		}
		runLen++
	}
	if runStart >= 0 {
		report.ChangedRuns = append(report.ChangedRuns, BackupDiffRun{Offset: runStart, Length: runLen})
	}

	if len(base) != len(candidate) {
		extra := absInt(len(base) - len(candidate))
		report.ChangedByteCount += extra
		report.ChangedRuns = append(report.ChangedRuns, BackupDiffRun{Offset: compared, Length: extra})
	}

	appendFieldChange(&report.FieldChanges, "Hostname", baseDecoded.Hostname, candidateDecoded.Hostname)
	appendFieldChange(&report.FieldChanges, "IP", baseDecoded.IP, candidateDecoded.IP)
	appendFieldChange(&report.FieldChanges, "Netmask", baseDecoded.Netmask, candidateDecoded.Netmask)
	appendFieldChange(&report.FieldChanges, "Gateway", baseDecoded.Gateway, candidateDecoded.Gateway)
	appendFieldChange(&report.FieldChanges, "DHCP", ternary(baseDecoded.DHCPEnabled, "enabled", "disabled"), ternary(candidateDecoded.DHCPEnabled, "enabled", "disabled"))
	appendFieldChange(&report.FieldChanges, "VLAN name", baseDecoded.VLANName, candidateDecoded.VLANName)
	if baseDecoded.CredentialInfo.RecoveredPassword != "" && candidateDecoded.CredentialInfo.RecoveredPassword != "" {
		appendFieldChange(&report.FieldChanges, "Password (obfuscated@0x49)", baseDecoded.CredentialInfo.RecoveredPassword, candidateDecoded.CredentialInfo.RecoveredPassword)
	}

	return report, nil
}

func FormatBackupDiff(report BackupDiffReport) string {
	var b strings.Builder
	changedPct := 0.0
	denominator := report.BaseSize
	if report.CandidateSize > denominator {
		denominator = report.CandidateSize
	}
	if denominator > 0 {
		changedPct = float64(report.ChangedByteCount) * 100.0 / float64(denominator)
	}

	fmt.Fprintf(&b, "Backup Diff (best-effort)\n")
	fmt.Fprintf(&b, "  Base size  : %d bytes\n", report.BaseSize)
	fmt.Fprintf(&b, "  Candidate  : %d bytes\n", report.CandidateSize)
	fmt.Fprintf(&b, "  Compared   : %d bytes\n", report.ComparedBytes)
	fmt.Fprintf(&b, "  Changed    : %d bytes (%.2f%%)\n", report.ChangedByteCount, changedPct)
	fmt.Fprintf(&b, "  Runs       : %d\n", len(report.ChangedRuns))

	if len(report.ChangedRuns) > 0 {
		fmt.Fprintf(&b, "\nChanged ranges\n")
		for _, run := range report.ChangedRuns {
			end := run.Offset + run.Length - 1
			fmt.Fprintf(&b, "  - 0x%04x..0x%04x (%d bytes)\n", run.Offset, end, run.Length)
		}
	}

	fmt.Fprintf(&b, "\nField changes\n")
	if len(report.FieldChanges) == 0 {
		fmt.Fprintf(&b, "  (none in known decoded fields)\n")
	} else {
		for _, change := range report.FieldChanges {
			fmt.Fprintf(&b, "  - %s\n", change)
		}
	}

	fmt.Fprintf(&b, "\nCredential block\n")
	fmt.Fprintf(&b, "  Changed    : %s\n", ternary(report.CredentialBlockChanged, "yes", "no"))
	fmt.Fprintf(&b, "  Delta      : %d bytes\n", report.CredentialBlockChangedBytes)
	fmt.Fprintf(&b, "  Base       : %s\n", fallback(report.BaseCredentialHex, "(empty)"))
	fmt.Fprintf(&b, "  Candidate  : %s\n", fallback(report.CandidateCredentialHex, "(empty)"))

	return b.String()
}

func AnalyzeCredentialBlob(blob []byte) BackupCredentialReport {
	report := BackupCredentialReport{BlobHex: hex.EncodeToString(blob)}
	report.PrintableFragments = printableFragments(blob)

	if len(blob) >= 32 {
		first16 := blob[:16]
		second16 := blob[16:32]
		for _, candidate := range candidateSecrets() {
			md5Sum := md5.Sum([]byte(candidate))
			sha1Sum := sha1.Sum([]byte(candidate))
			sha256Sum := sha256.Sum256([]byte(candidate))
			appendDigestMatches(&report.CandidateMatches, candidate, "md5", md5Sum[:], blob, first16, second16)
			appendDigestMatches(&report.CandidateMatches, candidate, "sha1[:16]", sha1Sum[:16], blob, first16, second16)
			appendDigestMatches(&report.CandidateMatches, candidate, "sha256[:16]", sha256Sum[:16], blob, first16, second16)
		}
	}
	report.CandidateMatches = uniqueStringsInOrder(report.CandidateMatches)

	if len(report.CandidateMatches) == 0 {
		report.LikelyMeaning = "No direct match to common digest forms of default credentials; likely opaque/obfuscated credential material plus metadata."
	} else {
		report.LikelyMeaning = "Matches at least one common digest form; credential block may include hashed credential bytes."
	}

	return report
}

func FormatDecodedBackup(decoded DecodedBackupConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Backup Decode (best-effort)\n")
	fmt.Fprintf(&b, "  Size       : %d bytes\n", decoded.Size)
	fmt.Fprintf(&b, "  Magic      : %#08x\n", decoded.Magic)
	fmt.Fprintf(&b, "  Hostname   : %s\n", fallback(decoded.Hostname, "(empty)"))
	fmt.Fprintf(&b, "  IP         : %s\n", decoded.IP)
	fmt.Fprintf(&b, "  Netmask    : %s\n", decoded.Netmask)
	fmt.Fprintf(&b, "  Gateway    : %s\n", decoded.Gateway)
	fmt.Fprintf(&b, "  DHCP       : %s\n", ternary(decoded.DHCPEnabled, "enabled", "disabled"))
	fmt.Fprintf(&b, "  VLAN name  : %s\n", fallback(decoded.VLANName, "(empty)"))
	fmt.Fprintf(&b, "\nCredential Block (offset 0x2c, 32 bytes)\n")
	fmt.Fprintf(&b, "  Policy     : username %d-%d [A-Za-z0-9_], password %d-%d [A-Za-z0-9_]\n", minUsernameLen, maxUsernameLen, minPasswordLen, maxPasswordLen)
	fmt.Fprintf(&b, "  Coverage   : password decode currently mapped to %d-byte obfuscated slot at 0x%02x\n", obfuscatedPasswordLen, offsetObfuscatedPassword)
	fmt.Fprintf(&b, "  Hex        : %s\n", decoded.CredentialInfo.BlobHex)
	if decoded.CredentialInfo.RecoveredPassword != "" {
		fmt.Fprintf(&b, "  Password   : %s\n", decoded.CredentialInfo.RecoveredPassword)
		fmt.Fprintf(&b, "  Pw bytes   : %s (offset 0x%02x)\n", decoded.CredentialInfo.ObfuscatedPasswordHex, offsetObfuscatedPassword)
		fmt.Fprintf(&b, "  Method     : %s\n", decoded.CredentialInfo.RecoveryMethod)
	} else if decoded.CredentialInfo.ObfuscatedPasswordHex != "" {
		fmt.Fprintf(&b, "  Password   : (not recoverable from current mapping)\n")
		fmt.Fprintf(&b, "  Pw bytes   : %s (offset 0x%02x)\n", decoded.CredentialInfo.ObfuscatedPasswordHex, offsetObfuscatedPassword)
	}
	if len(decoded.CredentialInfo.PrintableFragments) > 0 {
		fmt.Fprintf(&b, "  Strings    : %s\n", strings.Join(decoded.CredentialInfo.PrintableFragments, ", "))
	} else {
		fmt.Fprintf(&b, "  Strings    : (none)\n")
	}
	if len(decoded.CredentialInfo.CandidateMatches) > 0 {
		fmt.Fprintf(&b, "  Matches    :\n")
		for _, match := range decoded.CredentialInfo.CandidateMatches {
			fmt.Fprintf(&b, "    - %s\n", match)
		}
	} else {
		fmt.Fprintf(&b, "  Matches    : none against default credential candidates\n")
	}
	fmt.Fprintf(&b, "  Analysis   : %s\n", decoded.CredentialInfo.LikelyMeaning)
	return b.String()
}

func appendDigestMatches(matches *[]string, candidate string, digestName string, digest []byte, full []byte, first16 []byte, second16 []byte) {
	if len(digest) == 0 {
		return
	}
	if bytes.Equal(full, digest) {
		*matches = append(*matches, fmt.Sprintf("candidate=%q digest=%s section=full", candidate, digestName))
	}
	if len(digest) >= 16 {
		if bytes.Equal(first16, digest[:16]) {
			*matches = append(*matches, fmt.Sprintf("candidate=%q digest=%s section=first16", candidate, digestName))
		}
		if bytes.Equal(second16, digest[:16]) {
			*matches = append(*matches, fmt.Sprintf("candidate=%q digest=%s section=second16", candidate, digestName))
		}
	}
}

func appendFieldChange(changes *[]string, field string, before string, after string) {
	if before == after {
		return
	}
	*changes = append(*changes, fmt.Sprintf("%s: %q -> %q", field, before, after))
}

func credentialDiffBytes(base []byte, candidate []byte) int {
	minLen := len(base)
	if len(candidate) < minLen {
		minLen = len(candidate)
	}
	diff := 0
	for i := 0; i < minLen; i++ {
		if base[i] != candidate[i] {
			diff++
		}
	}
	return diff + absInt(len(base)-len(candidate))
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func recoverObfuscatedPassword(data []byte) (string, string, string) {
	end := offsetObfuscatedPassword + obfuscatedPasswordLen
	if len(data) < end {
		return "", "", ""
	}
	raw := data[offsetObfuscatedPassword:end]
	decoded := make([]byte, obfuscatedPasswordLen)
	for i := 0; i < obfuscatedPasswordLen; i++ {
		decoded[i] = raw[i] ^ knownPasswordXORKey[i]
	}
	trimmed := bytes.TrimRight(decoded, "\x00")
	if len(trimmed) == 0 {
		return hex.EncodeToString(raw), "", ""
	}
	if !allPrintableASCII(trimmed) || !matchesCredentialCharset(trimmed) {
		return hex.EncodeToString(raw), "", ""
	}
	if len(trimmed) < minPasswordLen {
		return hex.EncodeToString(raw), "", ""
	}
	recovered := string(trimmed)
	method := fmt.Sprintf("xor(key=5c746a047dbeb0b2, tl-sg108e-v1 inferred); recovered up to %d bytes from mapped slot", obfuscatedPasswordLen)
	if len(trimmed) > maxPasswordLen {
		method += "; decoded value exceeds known UI password max"
	}
	return hex.EncodeToString(raw), recovered, method
}

func allPrintableASCII(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, ch := range data {
		if ch < 0x20 || ch > 0x7e {
			return false
		}
	}
	return true
}

func matchesCredentialCharset(data []byte) bool {
	for _, ch := range data {
		isLower := ch >= 'a' && ch <= 'z'
		isUpper := ch >= 'A' && ch <= 'Z'
		isDigit := ch >= '0' && ch <= '9'
		if !isLower && !isUpper && !isDigit && ch != '_' {
			return false
		}
	}
	return true
}

func candidateSecrets() []string {
	candidates := []string{
		"admin",
		FirmwarePassword,
		"admin:admin",
		"admin:" + FirmwarePassword,
		FirmwarePassword + ":admin",
		"TPLINK-DIST-SWITCH",
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	sort.Strings(out)
	return out
}

func ip4String(raw []byte) string {
	if len(raw) != 4 {
		return "0.0.0.0"
	}
	return net.IPv4(raw[0], raw[1], raw[2], raw[3]).String()
}

func readCString(data []byte, offset int, maxLen int) string {
	if offset < 0 || offset >= len(data) || maxLen <= 0 {
		return ""
	}
	end := offset + maxLen
	if end > len(data) {
		end = len(data)
	}
	raw := data[offset:end]
	nul := bytes.IndexByte(raw, 0)
	if nul >= 0 {
		raw = raw[:nul]
	}
	return strings.TrimSpace(string(raw))
}

func printableFragments(data []byte) []string {
	fragments := []string{}
	start := -1
	for i, ch := range data {
		isPrintable := ch >= 0x20 && ch <= 0x7e
		if isPrintable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 2 {
			fragments = append(fragments, string(data[start:i]))
		}
		start = -1
	}
	if start >= 0 && len(data)-start >= 2 {
		fragments = append(fragments, string(data[start:]))
	}
	return fragments
}

func uniqueStringsInOrder(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func fallback(value string, empty string) string {
	if value == "" {
		return empty
	}
	return value
}
