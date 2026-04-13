package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildDecodeFixture(size int) []byte {
	data := make([]byte, size)
	data[0] = 0x23
	data[1] = 0x89
	data[2] = 0x23
	data[3] = 0x89
	copy(data[5:9], []byte{192, 168, 3, 49})
	copy(data[9:13], []byte{255, 255, 254, 0})
	copy(data[13:17], []byte{192, 168, 2, 1})
	data[16] = 1
	copy(data[23:], []byte("TPLINK-DIST-SWITCH\x00"))
	copy(data[0x2c:0x4c], []byte{
		0xbb, 0x65, 0xaf, 0xa3, 0x58, 0x40, 0x92, 0x13,
		0x3a, 0x4b, 0x4a, 0x00, 0x3d, 0x10, 0x07, 0x6d,
		0x13, 0xbe, 0xb0, 0xb2, 0xfb, 0x6b, 0x06, 0xc3,
		0x14, 0x95, 0x7e, 0x95, 0x00, 0x28, 0x11, 0x19,
	})
	copy(data[0x4c:0x51], []byte{0x70, 0x0d, 0xdf, 0xc3, 0xc1})
	copy(data[0x4a6:], []byte("Default\x00"))
	return data
}

func runDecodeCLI(path string) ([]byte, error) {
	cmd := exec.Command("go", "run", ".", "--decode-backup", path)
	cmd.Dir = "."
	return cmd.CombinedOutput()
}

func runDiffCLI(basePath string, candidatePath string) ([]byte, error) {
	cmd := exec.Command("go", "run", ".", "--diff-backup-base", basePath, "--diff-backup-candidate", candidatePath)
	cmd.Dir = "."
	return cmd.CombinedOutput()
}

func TestDecodeBackupModeIsHostless(t *testing.T) {
	tmpDir := t.TempDir()
	backupPath := filepath.Join(tmpDir, "sample.cfg")

	data := buildDecodeFixture(2258)

	if err := os.WriteFile(backupPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", backupPath, err)
	}

	out, err := runDecodeCLI(backupPath)
	if err != nil {
		t.Fatalf("decode mode failed: %v\n%s", err, string(out))
	}

	text := string(out)
	if !strings.Contains(text, "Backup Decode") {
		t.Fatalf("expected decode output, got:\n%s", text)
	}
	if strings.Contains(text, "Connecting to") {
		t.Fatalf("decode mode should not attempt network login, got:\n%s", text)
	}
}

func TestDecodeBackupModeHonorsSizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	atLimit := filepath.Join(tmpDir, "at-limit.cfg")
	overLimit := filepath.Join(tmpDir, "over-limit.cfg")

	if err := os.WriteFile(atLimit, buildDecodeFixture(maxDecodeBackupSize), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", atLimit, err)
	}
	if err := os.WriteFile(overLimit, buildDecodeFixture(maxDecodeBackupSize+1), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", overLimit, err)
	}

	out, err := runDecodeCLI(atLimit)
	if err != nil {
		t.Fatalf("decode at limit should pass, err=%v output=%s", err, string(out))
	}

	out, err = runDecodeCLI(overLimit)
	if err == nil {
		t.Fatalf("decode over limit should fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "exceeds max decode size") {
		t.Fatalf("expected size-limit error, got:\n%s", string(out))
	}
}

func TestDecodeBackupModeFailsOnInvalidBackup(t *testing.T) {
	tmpDir := t.TempDir()
	invalid := filepath.Join(tmpDir, "invalid.cfg")
	if err := os.WriteFile(invalid, []byte("not-a-backup"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", invalid, err)
	}

	out, err := runDecodeCLI(invalid)
	if err == nil {
		t.Fatalf("invalid backup should fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "failed to decode backup") {
		t.Fatalf("expected decode error, got:\n%s", string(out))
	}
}

func TestDecodeBackupModeFailsOnMissingFile(t *testing.T) {
	out, err := runDecodeCLI(filepath.Join(t.TempDir(), "missing.cfg"))
	if err == nil {
		t.Fatalf("missing file should fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "failed to read backup file") {
		t.Fatalf("expected read error, got:\n%s", string(out))
	}
}

func TestDiffBackupModeIsHostless(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "base.cfg")
	candidatePath := filepath.Join(tmpDir, "candidate.cfg")

	base := buildDecodeFixture(2258)
	candidate := buildDecodeFixture(2258)
	copy(candidate[5:9], []byte{10, 0, 0, 42})

	if err := os.WriteFile(basePath, base, 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", basePath, err)
	}
	if err := os.WriteFile(candidatePath, candidate, 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", candidatePath, err)
	}

	out, err := runDiffCLI(basePath, candidatePath)
	if err != nil {
		t.Fatalf("diff mode failed: %v\n%s", err, string(out))
	}

	text := string(out)
	if !strings.Contains(text, "Backup Diff") {
		t.Fatalf("expected diff output, got:\n%s", text)
	}
	if strings.Contains(text, "Connecting to") {
		t.Fatalf("diff mode should not attempt network login, got:\n%s", text)
	}
}

func TestDiffBackupModeRequiresBothFiles(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "base.cfg")
	if err := os.WriteFile(basePath, buildDecodeFixture(2258), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", basePath, err)
	}

	cmd := exec.Command("go", "run", ".", "--diff-backup-base", basePath)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected missing diff args to fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "must be provided together") {
		t.Fatalf("expected paired-flag error, got:\n%s", string(out))
	}
}

func TestDecodeAndDiffModesConflict(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "base.cfg")
	candidatePath := filepath.Join(tmpDir, "candidate.cfg")
	if err := os.WriteFile(basePath, buildDecodeFixture(2258), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", basePath, err)
	}
	if err := os.WriteFile(candidatePath, buildDecodeFixture(2258), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", candidatePath, err)
	}

	cmd := exec.Command(
		"go",
		"run",
		".",
		"--decode-backup",
		basePath,
		"--diff-backup-base",
		basePath,
		"--diff-backup-candidate",
		candidatePath,
	)
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected conflicting modes to fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "mutually exclusive") {
		t.Fatalf("expected mutually-exclusive mode error, got:\n%s", string(out))
	}
}
