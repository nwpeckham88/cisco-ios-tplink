package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runSuiteModeCLI(args ...string) ([]byte, error) {
	cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
	cmd.Dir = "."
	return cmd.CombinedOutput()
}

func TestSuitePlanModeRejectsPositionalHost(t *testing.T) {
	out, err := runSuiteModeCLI("192.168.0.1", "--suite-plan", filepath.Join(t.TempDir(), "plan.json"))
	if err == nil {
		t.Fatalf("expected host+suite conflict to fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "hostless") {
		t.Fatalf("expected hostless conflict message, got:\n%s", string(out))
	}
}

func TestSuitePlanConflictsWithConfigFile(t *testing.T) {
	out, err := runSuiteModeCLI("--suite-plan", filepath.Join(t.TempDir(), "plan.json"), "--config-file", "dummy.cfg")
	if err == nil {
		t.Fatalf("expected suite+config conflict to fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "cannot be combined with --config-file") {
		t.Fatalf("expected config-file conflict message, got:\n%s", string(out))
	}
}

func TestSuitePlanConflictsWithDecodeMode(t *testing.T) {
	out, err := runSuiteModeCLI("--suite-plan", filepath.Join(t.TempDir(), "plan.json"), "--decode-backup", "fake.bin")
	if err == nil {
		t.Fatalf("expected suite+decode conflict to fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion message, got:\n%s", string(out))
	}
}

func TestSuitePlanMissingFileSurfacesSuiteError(t *testing.T) {
	missingPlan := filepath.Join(t.TempDir(), "missing-plan.json")
	out, err := runSuiteModeCLI("--suite-plan", missingPlan)
	if err == nil {
		t.Fatalf("expected missing suite plan to fail, output=%s", string(out))
	}
	text := string(out)
	if !strings.Contains(text, "suite run failed") {
		t.Fatalf("expected suite run failure prefix, got:\n%s", text)
	}
	if !strings.Contains(text, "read suite plan") {
		t.Fatalf("expected read suite plan error detail, got:\n%s", text)
	}
	if strings.Contains(text, "Connecting to") {
		t.Fatalf("suite mode with missing plan should fail before network login, got:\n%s", text)
	}
}
