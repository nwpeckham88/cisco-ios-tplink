package hardwaresuite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nwpeckham88/cisco-ios-tplink/tplink"
)

const hardwareSuiteConfirmToken = "I_UNDERSTAND_THIS_WILL_FACTORY_RESET_MY_SWITCH"

type hardwareSuitePlan struct {
	Version   int                     `json:"version"`
	Target    hardwareSuiteTarget     `json:"target"`
	Safety    hardwareSuiteSafety     `json:"safety"`
	Timing    hardwareSuiteTiming     `json:"timing"`
	Artifacts hardwareSuiteArtifacts  `json:"artifacts"`
	Mutations []hardwareSuiteMutation `json:"mutations"`

	timingValues    hardwareSuiteTimingValues `json:"-"`
	decodeSummary   bool                      `json:"-"`
	resolvedUser    string                    `json:"-"`
	initialPassword string                    `json:"-"`
	postResetPass   string                    `json:"-"`
	planBaseDir     string                    `json:"-"`
}

type hardwareSuiteTarget struct {
	Host               string `json:"host"`
	Username           string `json:"username"`
	InitialPassword    string `json:"initial_password"`
	InitialPasswordEnv string `json:"initial_password_env"`
	PostResetPassword  string `json:"post_reset_password"`
}

type hardwareSuiteSafety struct {
	Enabled bool   `json:"enabled"`
	Confirm string `json:"confirm"`
}

type hardwareSuiteTiming struct {
	ResetGrace         string `json:"reset_grace"`
	ReconnectTimeout   string `json:"reconnect_timeout"`
	PollInterval       string `json:"poll_interval"`
	PostMutationSettle string `json:"post_mutation_settle"`
}

type hardwareSuiteTimingValues struct {
	ResetGrace         time.Duration
	ReconnectTimeout   time.Duration
	PollInterval       time.Duration
	PostMutationSettle time.Duration
}

type hardwareSuiteArtifacts struct {
	OutputDir     string `json:"output_dir"`
	DecodeSummary *bool  `json:"decode_summary,omitempty"`
}

type hardwareSuiteMutation struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Username     string   `json:"username,omitempty"`
	OldPassword  string   `json:"old_password,omitempty"`
	NewPassword  string   `json:"new_password,omitempty"`
	NextPassword string   `json:"next_password,omitempty"`
	ScriptFile   string   `json:"script_file,omitempty"`
	ScriptLines  []string `json:"script_lines,omitempty"`
}

type hardwareSuiteIndex struct {
	Version    int                         `json:"version"`
	RunID      string                      `json:"run_id"`
	PlanPath   string                      `json:"plan_path"`
	OutputDir  string                      `json:"output_dir"`
	Status     string                      `json:"status"`
	StartedAt  string                      `json:"started_at"`
	FinishedAt string                      `json:"finished_at"`
	Target     hardwareSuiteIndexTarget    `json:"target"`
	Safety     hardwareSuiteSafety         `json:"safety"`
	Snapshots  []hardwareSuiteSnapshot     `json:"snapshots"`
	Mutations  []hardwareSuiteMutationInfo `json:"mutations"`
	Cleanup    hardwareSuiteCleanup        `json:"cleanup"`
	Error      string                      `json:"error,omitempty"`
}

type hardwareSuiteIndexTarget struct {
	Host                    string `json:"host"`
	Username                string `json:"username"`
	UsesDefaultPostResetPwd bool   `json:"uses_default_post_reset_password"`
}

type hardwareSuiteCleanup struct {
	FinalResetAttempted bool   `json:"final_reset_attempted"`
	FinalResetSucceeded bool   `json:"final_reset_succeeded"`
	FinalResetError     string `json:"final_reset_error,omitempty"`
}

type hardwareSuiteMutationInfo struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	SnapshotFile string `json:"snapshot_file,omitempty"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
}

type hardwareSuiteSnapshot struct {
	Name       string                     `json:"name"`
	File       string                     `json:"file"`
	Size       int                        `json:"size"`
	SHA256     string                     `json:"sha256"`
	CapturedAt string                     `json:"captured_at"`
	Decoded    *hardwareSuiteDecodedBrief `json:"decoded,omitempty"`
	DecodeErr  string                     `json:"decode_error,omitempty"`
}

type hardwareSuiteDecodedBrief struct {
	Hostname                   string `json:"hostname"`
	IP                         string `json:"ip"`
	Netmask                    string `json:"netmask"`
	Gateway                    string `json:"gateway"`
	DHCP                       bool   `json:"dhcp"`
	QoSMode                    string `json:"qos_mode"`
	QoSModeKnown               bool   `json:"qos_mode_known"`
	QoSGi1Priority             int    `json:"qos_gi1_priority"`
	QoSGi1PriorityKnown        bool   `json:"qos_gi1_priority_known"`
	STP                        bool   `json:"stp"`
	STPKnown                   bool   `json:"stp_known"`
	IGMP                       bool   `json:"igmp"`
	IGMPKnown                  bool   `json:"igmp_known"`
	IGMPReportSuppression      bool   `json:"igmp_report_suppression"`
	IGMPReportSuppressionKnown bool   `json:"igmp_report_suppression_known"`
	LED                        bool   `json:"led"`
	LEDKnown                   bool   `json:"led_known"`
	VLANName                   string `json:"vlan_name"`
}

func decodeSummaryBrief(decoded tplink.DecodedBackupConfig) hardwareSuiteDecodedBrief {
	return hardwareSuiteDecodedBrief{
		Hostname:                   decoded.Hostname,
		IP:                         decoded.IP,
		Netmask:                    decoded.Netmask,
		Gateway:                    decoded.Gateway,
		DHCP:                       decoded.DHCPEnabled,
		QoSMode:                    decoded.QoSMode,
		QoSModeKnown:               decoded.QoSModeKnown,
		QoSGi1Priority:             decoded.QoSPort1Priority,
		QoSGi1PriorityKnown:        decoded.QoSPort1PriorityKnown,
		STP:                        decoded.LoopPreventionEnabled,
		STPKnown:                   decoded.LoopPreventionPresent,
		IGMP:                       decoded.IGMPSnoopingEnabled,
		IGMPKnown:                  decoded.IGMPSnoopingPresent,
		IGMPReportSuppression:      decoded.IGMPReportSuppressionEnabled,
		IGMPReportSuppressionKnown: decoded.IGMPReportSuppressionPresent,
		LED:                        decoded.LEDEnabled,
		LEDKnown:                   decoded.LEDPresent,
		VLANName:                   decoded.VLANName,
	}
}

type hardwareSuiteOps interface {
	InitialFactoryReset(ctx context.Context) error
	CaptureBackup(ctx context.Context, label string, ordinal int) (hardwareSuiteSnapshot, error)
	ApplyMutation(ctx context.Context, mutation hardwareSuiteMutation) error
	FinalFactoryReset(ctx context.Context) error
}

type hardwareSuiteRealOps struct {
	plan       *hardwareSuitePlan
	runDir     string
	backupsDir string

	client          *tplink.Client
	currentPassword string
}

func loadHardwareSuitePlan(path string) (hardwareSuitePlan, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return hardwareSuitePlan{}, fmt.Errorf("resolve suite plan path %q: %w", path, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return hardwareSuitePlan{}, fmt.Errorf("read suite plan %q: %w", path, err)
	}

	var plan hardwareSuitePlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return hardwareSuitePlan{}, fmt.Errorf("parse suite plan %q: %w", path, err)
	}
	if err := plan.normalizeAndValidate(); err != nil {
		return hardwareSuitePlan{}, err
	}
	plan.planBaseDir = filepath.Dir(absPath)
	if err := plan.resolveScriptPaths(); err != nil {
		return hardwareSuitePlan{}, err
	}
	return plan, nil
}

func (p *hardwareSuitePlan) normalizeAndValidate() error {
	if p.Version == 0 {
		p.Version = 1
	}
	if p.Version != 1 {
		return fmt.Errorf("suite plan version must be 1")
	}

	if !p.Safety.Enabled {
		return errors.New("suite safety.enabled must be true")
	}
	if p.Safety.Confirm != hardwareSuiteConfirmToken {
		return fmt.Errorf("suite safety.confirm must equal %q", hardwareSuiteConfirmToken)
	}

	host := strings.TrimSpace(p.Target.Host)
	if host == "" {
		return errors.New("suite target.host must not be empty")
	}
	p.Target.Host = host

	p.resolvedUser = strings.TrimSpace(p.Target.Username)
	if p.resolvedUser == "" {
		p.resolvedUser = "admin"
	}

	envName := strings.TrimSpace(p.Target.InitialPasswordEnv)
	if envName == "" {
		envName = "TPLINK_PASSWORD"
	}
	p.Target.InitialPasswordEnv = envName

	p.postResetPass = strings.TrimSpace(p.Target.PostResetPassword)
	if p.postResetPass == "" {
		p.postResetPass = tplink.FirmwarePassword
	}

	p.initialPassword = strings.TrimSpace(p.Target.InitialPassword)
	if p.initialPassword == "" {
		p.initialPassword = strings.TrimSpace(os.Getenv(envName))
	}
	if p.initialPassword == "" {
		p.initialPassword = p.postResetPass
	}

	if strings.TrimSpace(p.Artifacts.OutputDir) == "" {
		p.Artifacts.OutputDir = filepath.Join("artifacts", "hardware-suite")
	}
	if p.Artifacts.DecodeSummary == nil {
		p.decodeSummary = true
	} else {
		p.decodeSummary = *p.Artifacts.DecodeSummary
	}

	resetGrace, err := parseSuiteDuration(p.Timing.ResetGrace, 5*time.Second, "timing.reset_grace")
	if err != nil {
		return err
	}
	reconnectTimeout, err := parseSuiteDuration(p.Timing.ReconnectTimeout, 180*time.Second, "timing.reconnect_timeout")
	if err != nil {
		return err
	}
	pollInterval, err := parseSuiteDuration(p.Timing.PollInterval, 2*time.Second, "timing.poll_interval")
	if err != nil {
		return err
	}
	postSettle, err := parseSuiteDuration(p.Timing.PostMutationSettle, 2*time.Second, "timing.post_mutation_settle")
	if err != nil {
		return err
	}
	if reconnectTimeout <= 0 {
		return errors.New("timing.reconnect_timeout must be > 0")
	}
	if pollInterval <= 0 {
		return errors.New("timing.poll_interval must be > 0")
	}
	if pollInterval > reconnectTimeout {
		return errors.New("timing.poll_interval must be <= timing.reconnect_timeout")
	}
	p.timingValues = hardwareSuiteTimingValues{
		ResetGrace:         resetGrace,
		ReconnectTimeout:   reconnectTimeout,
		PollInterval:       pollInterval,
		PostMutationSettle: postSettle,
	}

	if len(p.Mutations) == 0 {
		return errors.New("suite mutations must contain at least one mutation")
	}

	seenIDs := map[string]struct{}{}
	for i := range p.Mutations {
		m := &p.Mutations[i]
		m.ID = strings.TrimSpace(m.ID)
		if m.ID == "" {
			m.ID = fmt.Sprintf("mutation-%02d", i+1)
		}
		if _, ok := seenIDs[m.ID]; ok {
			return fmt.Errorf("duplicate mutation id %q", m.ID)
		}
		seenIDs[m.ID] = struct{}{}

		m.Kind = strings.ToLower(strings.TrimSpace(m.Kind))
		switch m.Kind {
		case "change-password":
			if strings.TrimSpace(m.NewPassword) == "" {
				return fmt.Errorf("mutation %q kind=change-password requires new_password", m.ID)
			}
			if strings.TrimSpace(m.Username) == "" {
				m.Username = p.resolvedUser
			}
		case "script-file":
			if strings.TrimSpace(m.ScriptFile) == "" {
				return fmt.Errorf("mutation %q kind=script-file requires script_file", m.ID)
			}
		case "script-inline":
			if len(m.ScriptLines) == 0 {
				return fmt.Errorf("mutation %q kind=script-inline requires script_lines", m.ID)
			}
		default:
			return fmt.Errorf("mutation %q has unsupported kind %q", m.ID, m.Kind)
		}
	}

	return nil
}

func parseSuiteDuration(raw string, fallback time.Duration, field string) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s duration %q: %w", field, value, err)
	}
	return duration, nil
}

func (p *hardwareSuitePlan) resolveScriptPaths() error {
	baseDir := p.planBaseDir
	if strings.TrimSpace(baseDir) == "" {
		baseDir = "."
	}

	for i := range p.Mutations {
		mutation := &p.Mutations[i]
		if mutation.Kind != "script-file" {
			continue
		}

		scriptPath := strings.TrimSpace(mutation.ScriptFile)
		if !filepath.IsAbs(scriptPath) {
			scriptPath = filepath.Join(baseDir, scriptPath)
		}
		scriptPath = filepath.Clean(scriptPath)

		info, err := os.Stat(scriptPath)
		if err != nil {
			return fmt.Errorf("mutation %q script_file %q: %w", mutation.ID, mutation.ScriptFile, err)
		}
		if info.IsDir() {
			return fmt.Errorf("mutation %q script_file %q points to a directory", mutation.ID, scriptPath)
		}
		mutation.ScriptFile = scriptPath
	}

	return nil
}

func runHardwareSuiteWithOps(ctx context.Context, plan hardwareSuitePlan, ops hardwareSuiteOps, nowFn func() time.Time) (hardwareSuiteIndex, error) {
	startedAt := nowFn().UTC()
	index := hardwareSuiteIndex{
		Version:   1,
		Status:    "running",
		StartedAt: startedAt.Format(time.RFC3339),
		Target: hardwareSuiteIndexTarget{
			Host:                    plan.Target.Host,
			Username:                plan.resolvedUser,
			UsesDefaultPostResetPwd: plan.postResetPass == tplink.FirmwarePassword,
		},
		Safety: plan.Safety,
	}

	primaryErr := error(nil)
	mutationStarted := false

	if err := ops.InitialFactoryReset(ctx); err != nil {
		primaryErr = fmt.Errorf("initial factory reset: %w", err)
	} else {
		baseline, err := ops.CaptureBackup(ctx, "baseline", 0)
		if err != nil {
			primaryErr = fmt.Errorf("capture baseline backup: %w", err)
		} else {
			index.Snapshots = append(index.Snapshots, baseline)
		}
	}

	if primaryErr == nil {
		for i, mutation := range plan.Mutations {
			if ctx.Err() != nil {
				primaryErr = ctx.Err()
				break
			}

			mutationStarted = true
			result := hardwareSuiteMutationInfo{ID: mutation.ID, Kind: mutation.Kind, Status: "running"}
			if err := ops.ApplyMutation(ctx, mutation); err != nil {
				result.Status = "failed"
				result.Error = err.Error()
				index.Mutations = append(index.Mutations, result)
				primaryErr = fmt.Errorf("apply mutation %q: %w", mutation.ID, err)
				break
			}

			if err := sleepWithContext(ctx, plan.timingValues.PostMutationSettle); err != nil {
				result.Status = "failed"
				result.Error = err.Error()
				index.Mutations = append(index.Mutations, result)
				primaryErr = fmt.Errorf("post-mutation settle for %q: %w", mutation.ID, err)
				break
			}

			snapshot, err := ops.CaptureBackup(ctx, mutation.ID, i+1)
			if err != nil {
				result.Status = "failed"
				result.Error = err.Error()
				index.Mutations = append(index.Mutations, result)
				primaryErr = fmt.Errorf("capture backup for mutation %q: %w", mutation.ID, err)
				break
			}

			index.Snapshots = append(index.Snapshots, snapshot)
			result.SnapshotFile = snapshot.File
			result.Status = "ok"
			index.Mutations = append(index.Mutations, result)
		}
	}

	if mutationStarted || primaryErr != nil {
		index.Cleanup.FinalResetAttempted = true
		if err := ops.FinalFactoryReset(ctx); err != nil {
			index.Cleanup.FinalResetError = err.Error()
			if primaryErr != nil {
				primaryErr = fmt.Errorf("%w; final factory reset: %v", primaryErr, err)
			} else {
				primaryErr = fmt.Errorf("final factory reset: %w", err)
			}
		} else {
			index.Cleanup.FinalResetSucceeded = true
		}
	}

	finishedAt := nowFn().UTC()
	index.FinishedAt = finishedAt.Format(time.RFC3339)
	if primaryErr != nil {
		index.Status = "failed"
		index.Error = primaryErr.Error()
		return index, primaryErr
	}
	index.Status = "success"
	return index, nil
}

func RunHardwareSuite(ctx context.Context, planPath string, outputDirOverride string) (string, error) {
	plan, err := loadHardwareSuitePlan(planPath)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(outputDirOverride) != "" {
		plan.Artifacts.OutputDir = outputDirOverride
	}
	artifactsRoot, err := resolveSuiteOutputDir(plan.Artifacts.OutputDir)
	if err != nil {
		return "", err
	}
	plan.Artifacts.OutputDir = artifactsRoot

	runID := buildHardwareSuiteRunID(plan.Target.Host, time.Now().UTC())
	runDir := filepath.Join(artifactsRoot, runID)
	backupsDir := filepath.Join(runDir, "backups")
	if err := os.MkdirAll(artifactsRoot, 0o700); err != nil {
		return "", fmt.Errorf("create suite artifacts root %q: %w", artifactsRoot, err)
	}
	if err := os.Mkdir(runDir, 0o700); err != nil {
		return "", fmt.Errorf("create suite run dir %q: %w", runDir, err)
	}
	if err := os.Mkdir(backupsDir, 0o700); err != nil {
		return "", fmt.Errorf("create suite artifacts dir %q: %w", backupsDir, err)
	}

	realOps := &hardwareSuiteRealOps{
		plan:            &plan,
		runDir:          runDir,
		backupsDir:      backupsDir,
		currentPassword: plan.initialPassword,
	}

	index, runErr := runHardwareSuiteWithOps(ctx, plan, realOps, time.Now)
	index.RunID = runID
	index.PlanPath = planPath
	index.OutputDir = runDir
	index.Target = hardwareSuiteIndexTarget{
		Host:                    plan.Target.Host,
		Username:                plan.resolvedUser,
		UsesDefaultPostResetPwd: plan.postResetPass == tplink.FirmwarePassword,
	}
	index.Safety = plan.Safety

	indexPath := filepath.Join(runDir, "index.json")
	if err := writeHardwareSuiteIndex(indexPath, index); err != nil {
		if runErr != nil {
			return runDir, fmt.Errorf("%w; write suite index: %v", runErr, err)
		}
		return runDir, fmt.Errorf("write suite index %q: %w", indexPath, err)
	}

	if runErr != nil {
		return runDir, runErr
	}
	return runDir, nil
}

func buildHardwareSuiteRunID(host string, now time.Time) string {
	safeHost := sanitizeSnapshotName(host)
	if safeHost == "" {
		safeHost = "switch"
	}
	return fmt.Sprintf("%s-%s", now.UTC().Format("20060102T150405.000000000Z"), safeHost)
}

func resolveSuiteOutputDir(outputDir string) (string, error) {
	cleaned := filepath.Clean(strings.TrimSpace(outputDir))
	if cleaned == "" || cleaned == "." {
		return "", errors.New("suite artifacts output_dir must not be empty")
	}
	absPath, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve suite output_dir %q: %w", outputDir, err)
	}
	return absPath, nil
}

func writeHardwareSuiteIndex(path string, index hardwareSuiteIndex) error {
	payload, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal suite index: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return err
	}
	return nil
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	t := time.NewTimer(duration)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (o *hardwareSuiteRealOps) InitialFactoryReset(ctx context.Context) error {
	if err := o.ensureConnectedWithCandidates(ctx, []string{o.plan.initialPassword, o.currentPassword, o.plan.postResetPass}); err != nil {
		return err
	}
	if err := o.client.FactoryReset(); err != nil {
		return err
	}
	o.client = nil
	if err := sleepWithContext(ctx, o.plan.timingValues.ResetGrace); err != nil {
		return err
	}
	if err := o.waitForReconnect(ctx, o.plan.postResetPass); err != nil {
		return err
	}
	o.currentPassword = o.plan.postResetPass
	return nil
}

func (o *hardwareSuiteRealOps) CaptureBackup(ctx context.Context, label string, ordinal int) (hardwareSuiteSnapshot, error) {
	if err := o.ensureConnectedWithCandidates(ctx, []string{o.currentPassword, o.plan.postResetPass, o.plan.initialPassword}); err != nil {
		return hardwareSuiteSnapshot{}, err
	}
	if ctx.Err() != nil {
		return hardwareSuiteSnapshot{}, ctx.Err()
	}

	data, err := o.client.BackupConfig()
	if err != nil {
		return hardwareSuiteSnapshot{}, err
	}

	name := sanitizeSnapshotName(label)
	if name == "" {
		name = fmt.Sprintf("snapshot-%03d", ordinal)
	}
	filename := fmt.Sprintf("%03d-%s.bin", ordinal, name)
	relPath := filepath.ToSlash(filepath.Join("backups", filename))
	absPath := filepath.Join(o.backupsDir, filename)
	if err := os.WriteFile(absPath, data, 0o600); err != nil {
		return hardwareSuiteSnapshot{}, err
	}

	sum := sha256.Sum256(data)
	snapshot := hardwareSuiteSnapshot{
		Name:       label,
		File:       relPath,
		Size:       len(data),
		SHA256:     hex.EncodeToString(sum[:]),
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if o.plan.decodeSummary {
		decoded, decodeErr := tplink.DecodeBackupConfig(data)
		if decodeErr != nil {
			snapshot.DecodeErr = decodeErr.Error()
		} else {
			brief := decodeSummaryBrief(decoded)
			snapshot.Decoded = &brief
		}
	}

	return snapshot, nil
}

func (o *hardwareSuiteRealOps) ApplyMutation(ctx context.Context, mutation hardwareSuiteMutation) error {
	if err := o.ensureConnectedWithCandidates(ctx, []string{o.currentPassword, o.plan.postResetPass, o.plan.initialPassword}); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	switch mutation.Kind {
	case "change-password":
		oldPassword := strings.TrimSpace(mutation.OldPassword)
		if oldPassword == "" {
			oldPassword = o.currentPassword
		}
		username := strings.TrimSpace(mutation.Username)
		if username == "" {
			username = o.plan.resolvedUser
		}
		if err := o.client.ChangePassword(oldPassword, mutation.NewPassword, username); err != nil {
			return err
		}
		o.currentPassword = mutation.NewPassword
		return nil
	case "script-file":
		cli := tplink.NewCLI(o.client, "switch")
		if err := cli.RunScriptFile(mutation.ScriptFile); err != nil {
			return err
		}
	case "script-inline":
		cli := tplink.NewCLI(o.client, "switch")
		script := strings.Join(mutation.ScriptLines, "\n")
		if !strings.HasSuffix(script, "\n") {
			script += "\n"
		}
		if err := cli.RunScript(strings.NewReader(script), "suite-inline:"+mutation.ID); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported mutation kind %q", mutation.Kind)
	}

	if strings.TrimSpace(mutation.NextPassword) != "" {
		o.currentPassword = strings.TrimSpace(mutation.NextPassword)
	}
	return nil
}

func (o *hardwareSuiteRealOps) FinalFactoryReset(ctx context.Context) error {
	if err := o.ensureConnectedWithCandidates(ctx, []string{o.currentPassword, o.plan.postResetPass, o.plan.initialPassword}); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := o.client.FactoryReset(); err != nil {
		return err
	}
	o.client = nil
	return nil
}

func (o *hardwareSuiteRealOps) waitForReconnect(ctx context.Context, password string) error {
	deadline := time.Now().Add(o.plan.timingValues.ReconnectTimeout)
	var lastErr error
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("reconnect timeout after %s: last error: %w", o.plan.timingValues.ReconnectTimeout, lastErr)
			}
			return fmt.Errorf("reconnect timeout after %s", o.plan.timingValues.ReconnectTimeout)
		}

		client, err := tplink.NewClient(o.plan.Target.Host, tplink.WithUsername(o.plan.resolvedUser), tplink.WithPassword(password))
		if err != nil {
			lastErr = err
		} else if err := client.Login(); err != nil {
			lastErr = err
		} else {
			o.client = client
			return nil
		}

		if err := sleepWithContext(ctx, o.plan.timingValues.PollInterval); err != nil {
			return err
		}
	}
}

func (o *hardwareSuiteRealOps) ensureConnectedWithCandidates(ctx context.Context, candidates []string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if o.client != nil {
		if err := o.client.Login(); err == nil {
			return nil
		}
		o.client = nil
	}

	for _, candidate := range dedupeNonEmpty(candidates) {
		client, err := tplink.NewClient(o.plan.Target.Host, tplink.WithUsername(o.plan.resolvedUser), tplink.WithPassword(candidate))
		if err != nil {
			continue
		}
		if err := client.Login(); err != nil {
			continue
		}
		o.client = client
		o.currentPassword = candidate
		return nil
	}
	return fmt.Errorf("unable to authenticate to %s as %s with configured password candidates", o.plan.Target.Host, o.plan.resolvedUser)
}

func dedupeNonEmpty(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

var nonAlnum = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func sanitizeSnapshotName(value string) string {
	clean := strings.TrimSpace(strings.ToLower(value))
	clean = strings.ReplaceAll(clean, " ", "-")
	clean = nonAlnum.ReplaceAllString(clean, "-")
	clean = strings.Trim(clean, "-._")
	if clean == "" {
		return ""
	}
	parts := strings.Split(clean, "-")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	if len(filtered) == 0 {
		return ""
	}
	return strings.Join(filtered, "-")
}
