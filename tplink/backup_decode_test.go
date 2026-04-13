package tplink

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
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
