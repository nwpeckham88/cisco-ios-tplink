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
	backupMagic          = 0x23892389
	offsetIP             = 5
	offsetNetmask        = 9
	offsetGateway        = 13
	offsetDHCPFlag       = 16
	offsetHostname       = 23
	maxHostnameLen       = 32
	offsetCredentialBlob = 0x2c
	credentialBlobLen    = 32
	offsetVLANName       = 0x4a6
	maxVLANNameLen       = 32
)

type BackupCredentialReport struct {
	BlobHex            string
	PrintableFragments []string
	CandidateMatches   []string
	LikelyMeaning      string
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
	return decoded, nil
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
	fmt.Fprintf(&b, "  Hex        : %s\n", decoded.CredentialInfo.BlobHex)
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
