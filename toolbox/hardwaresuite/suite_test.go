package hardwaresuite

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeHardwareSuiteOps struct {
	calls []string

	initialErr      error
	finalErr        error
	backupErrByName map[string]error
	mutationErrByID map[string]error
}

func (f *fakeHardwareSuiteOps) InitialFactoryReset(_ context.Context) error {
	f.calls = append(f.calls, "initial-reset")
	return f.initialErr
}

func (f *fakeHardwareSuiteOps) CaptureBackup(_ context.Context, label string, ordinal int) (hardwareSuiteSnapshot, error) {
	f.calls = append(f.calls, "backup:"+label)
	if err, ok := f.backupErrByName[label]; ok {
		return hardwareSuiteSnapshot{}, err
	}
	return hardwareSuiteSnapshot{
		Name:       label,
		File:       "backups/file.bin",
		Size:       10,
		SHA256:     "abc",
		CapturedAt: "2026-01-01T00:00:00Z",
	}, nil
}

func (f *fakeHardwareSuiteOps) ApplyMutation(_ context.Context, mutation hardwareSuiteMutation) error {
	f.calls = append(f.calls, "mutate:"+mutation.ID)
	if err, ok := f.mutationErrByID[mutation.ID]; ok {
		return err
	}
	return nil
}

func (f *fakeHardwareSuiteOps) FinalFactoryReset(_ context.Context) error {
	f.calls = append(f.calls, "final-reset")
	return f.finalErr
}

func TestHardwareSuitePlanValidationRequiresSafetyAck(t *testing.T) {
	plan := validHardwareSuitePlanForTests()
	plan.Safety.Confirm = "WRONG"

	err := plan.normalizeAndValidate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "safety.confirm") {
		t.Fatalf("expected safety.confirm error, got %v", err)
	}
}

func TestRunHardwareSuiteWithOpsHappyPathOrder(t *testing.T) {
	plan := validHardwareSuitePlanForTests()
	ops := &fakeHardwareSuiteOps{}
	now := func() time.Time { return time.Date(2026, time.April, 13, 10, 0, 0, 0, time.UTC) }

	index, err := runHardwareSuiteWithOps(context.Background(), plan, ops, now)
	if err != nil {
		t.Fatalf("runHardwareSuiteWithOps error = %v", err)
	}
	if index.Status != "success" {
		t.Fatalf("status = %q want success", index.Status)
	}

	wantCalls := []string{
		"initial-reset",
		"backup:baseline",
		"mutate:change-pass-1",
		"backup:change-pass-1",
		"mutate:inline-1",
		"backup:inline-1",
		"final-reset",
	}
	if !reflect.DeepEqual(ops.calls, wantCalls) {
		t.Fatalf("calls = %v\nwant  %v", ops.calls, wantCalls)
	}
	if len(index.Snapshots) != 3 {
		t.Fatalf("snapshot count = %d want 3", len(index.Snapshots))
	}
	if len(index.Mutations) != 2 {
		t.Fatalf("mutation results = %d want 2", len(index.Mutations))
	}
}

func TestRunHardwareSuiteWithOpsFinalResetOnMutationFailure(t *testing.T) {
	plan := validHardwareSuitePlanForTests()
	ops := &fakeHardwareSuiteOps{
		mutationErrByID: map[string]error{"change-pass-1": errors.New("boom")},
	}
	now := func() time.Time { return time.Date(2026, time.April, 13, 10, 0, 0, 0, time.UTC) }

	index, err := runHardwareSuiteWithOps(context.Background(), plan, ops, now)
	if err == nil {
		t.Fatal("expected error")
	}
	if index.Status != "failed" {
		t.Fatalf("status = %q want failed", index.Status)
	}
	if !index.Cleanup.FinalResetAttempted {
		t.Fatal("expected final reset attempt")
	}
	if !index.Cleanup.FinalResetSucceeded {
		t.Fatal("expected successful final reset")
	}

	wantCalls := []string{
		"initial-reset",
		"backup:baseline",
		"mutate:change-pass-1",
		"final-reset",
	}
	if !reflect.DeepEqual(ops.calls, wantCalls) {
		t.Fatalf("calls = %v\nwant  %v", ops.calls, wantCalls)
	}
}

func TestRunHardwareSuiteWithOpsCombinesFinalResetError(t *testing.T) {
	plan := validHardwareSuitePlanForTests()
	ops := &fakeHardwareSuiteOps{
		mutationErrByID: map[string]error{"change-pass-1": errors.New("mutation failed")},
		finalErr:        errors.New("final reset failed"),
	}
	now := func() time.Time { return time.Date(2026, time.April, 13, 10, 0, 0, 0, time.UTC) }

	index, err := runHardwareSuiteWithOps(context.Background(), plan, ops, now)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "final factory reset") {
		t.Fatalf("expected combined error, got %v", err)
	}
	if index.Cleanup.FinalResetError == "" {
		t.Fatal("expected cleanup error recorded")
	}
}

func validHardwareSuitePlanForTests() hardwareSuitePlan {
	decode := true
	plan := hardwareSuitePlan{
		Version: 1,
		Target: hardwareSuiteTarget{
			Host:              "192.0.2.10",
			Username:          "admin",
			InitialPassword:   "initial-pass",
			PostResetPassword: "testpass",
		},
		Safety: hardwareSuiteSafety{
			Enabled: true,
			Confirm: hardwareSuiteConfirmToken,
		},
		Timing: hardwareSuiteTiming{
			PostMutationSettle: "0s",
		},
		Artifacts: hardwareSuiteArtifacts{
			DecodeSummary: &decode,
			OutputDir:     "artifacts/test-suite",
		},
		Mutations: []hardwareSuiteMutation{
			{
				ID:          "change-pass-1",
				Kind:        "change-password",
				OldPassword: "testpass",
				NewPassword: "newpass01",
			},
			{
				ID:          "inline-1",
				Kind:        "script-inline",
				ScriptLines: []string{"configure terminal", "hostname lab-switch", "end"},
			},
		},
	}
	if err := plan.normalizeAndValidate(); err != nil {
		panic(err)
	}
	return plan
}
