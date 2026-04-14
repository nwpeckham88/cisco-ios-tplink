package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nwpeckham88/cisco-ios-tplink/toolbox/hardwaresuite"
	"github.com/nwpeckham88/cisco-ios-tplink/tplink"
)

const maxDecodeBackupSize = 2 << 20

type scanFailureSummary struct {
	AuthFailures      int
	NonTPLinkFailures int
	OtherFailures     int
}

func summarizeScanFailures(results []tplink.ScanResult) scanFailureSummary {
	out := scanFailureSummary{}
	for _, result := range results {
		if result.Err == nil {
			continue
		}
		if errors.Is(result.Err, tplink.ErrNonTPLinkSmartSwitch) {
			out.NonTPLinkFailures++
			continue
		}
		if errors.Is(result.Err, tplink.ErrAuthenticationFailed) {
			out.AuthFailures++
			continue
		}
		out.OtherFailures++
	}
	return out
}

func usageText() string {
	return "usage: tplink-cli <host> [--user USER] [--password PASSWORD] [--config-file FILE] | tplink-cli --scan-cidr CIDR [--scan-port PORT --scan-timeout DURATION --scan-workers N --scan-max-hosts N] | tplink-cli --decode-backup FILE | tplink-cli --diff-backup-base FILE --diff-backup-candidate FILE | tplink-cli --infer-backup-structure-dir DIR [--infer-backup-baseline FILE] | tplink-cli --suite-plan FILE [--suite-output-dir DIR]"
}

func loadBackupsForStructureInference(dirPath string, baselinePath string) (string, []byte, map[string][]byte, error) {
	absDir, err := filepath.Abs(filepath.Clean(strings.TrimSpace(dirPath)))
	if err != nil {
		return "", nil, nil, fmt.Errorf("resolve backup directory %q: %w", dirPath, err)
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		return "", nil, nil, fmt.Errorf("read backup directory %q: %w", absDir, err)
	}

	paths := make([]string, 0, len(entries))
	pathSet := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".bin") {
			continue
		}

		absPath := filepath.Join(absDir, name)
		info, err := os.Lstat(absPath)
		if err != nil {
			return "", nil, nil, fmt.Errorf("stat backup file %q: %w", absPath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}

		paths = append(paths, absPath)
		pathSet[absPath] = struct{}{}
	}
	if len(paths) == 0 {
		return "", nil, nil, fmt.Errorf("no .bin backup files found in %q", absDir)
	}
	sort.Strings(paths)

	selectedBaseline := strings.TrimSpace(baselinePath)
	if selectedBaseline == "" {
		for _, path := range paths {
			base := filepath.Base(path)
			if strings.Contains(strings.ToLower(base), "baseline") {
				selectedBaseline = path
				break
			}
		}
		if selectedBaseline == "" {
			selectedBaseline = paths[0]
		}
	} else {
		if !filepath.IsAbs(selectedBaseline) {
			selectedBaseline = filepath.Join(absDir, selectedBaseline)
		}
		selectedBaseline, err = filepath.Abs(filepath.Clean(selectedBaseline))
		if err != nil {
			return "", nil, nil, fmt.Errorf("resolve baseline path %q: %w", baselinePath, err)
		}
		if !isPathWithin(selectedBaseline, absDir) {
			return "", nil, nil, fmt.Errorf("baseline %q must be inside %q", selectedBaseline, absDir)
		}
		if _, ok := pathSet[selectedBaseline]; !ok {
			return "", nil, nil, fmt.Errorf("baseline %q is not a regular .bin file in %q", selectedBaseline, absDir)
		}
	}

	baselineData, err := readBackupFile(selectedBaseline)
	if err != nil {
		return "", nil, nil, err
	}

	baselineName := filepath.Base(selectedBaseline)
	samples := make(map[string][]byte)
	for _, path := range paths {
		if path == selectedBaseline {
			continue
		}
		data, err := readBackupFile(path)
		if err != nil {
			return "", nil, nil, err
		}
		samples[filepath.Base(path)] = data
	}
	if len(samples) == 0 {
		return "", nil, nil, fmt.Errorf("need at least one candidate backup in %q besides baseline %q", absDir, baselineName)
	}

	return baselineName, baselineData, samples, nil
}

func isPathWithin(path string, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." {
		return false
	}
	upPrefix := ".." + string(os.PathSeparator)
	return !strings.HasPrefix(rel, upPrefix)
}

func readBackupFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file %q: %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxDecodeBackupSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file %q: %w", path, err)
	}
	if len(data) > maxDecodeBackupSize {
		return nil, fmt.Errorf("backup file %q exceeds max decode size (%d bytes)", path, maxDecodeBackupSize)
	}
	return data, nil
}

func main() {
	var user string
	var password string
	var passwordStdin bool
	var passwordFile string
	var passwordEnv string
	var configFile string
	var decodeBackupFile string
	var diffBackupBase string
	var diffBackupCandidate string
	var scanCIDR string
	var scanPort int
	var scanTimeout time.Duration
	var scanWorkers int
	var scanMaxHosts int
	var scanVerbose bool
	var inferBackupStructureDir string
	var inferBackupBaseline string
	var suitePlanFile string
	var suiteOutputDir string
	var host string

	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.StringVar(&user, "user", "admin", "Username (default: admin)")
	fs.StringVar(&user, "u", "admin", "Username (shorthand)")
	fs.StringVar(&password, "password", "", "Password override")
	fs.StringVar(&password, "p", "", "Password override (shorthand)")
	fs.BoolVar(&passwordStdin, "password-stdin", false, "Read password from stdin")
	fs.StringVar(&passwordFile, "password-file", "", "Read password from file")
	fs.StringVar(&passwordEnv, "password-env", "TPLINK_PASSWORD", "Environment variable for password")
	fs.StringVar(&configFile, "config-file", "", "Run commands from file and exit")
	fs.StringVar(&decodeBackupFile, "decode-backup", "", "Decode a binary TP-Link backup file and exit")
	fs.StringVar(&diffBackupBase, "diff-backup-base", "", "Base backup file for byte/field diff")
	fs.StringVar(&diffBackupCandidate, "diff-backup-candidate", "", "Candidate backup file for byte/field diff")
	fs.StringVar(&scanCIDR, "scan-cidr", "", "Scan an IPv4 CIDR for reachable switches and exit")
	fs.IntVar(&scanPort, "scan-port", 80, "Management HTTP port to probe during scan")
	fs.DurationVar(&scanTimeout, "scan-timeout", 1500*time.Millisecond, "Per-host scan timeout")
	fs.IntVar(&scanWorkers, "scan-workers", 16, "Number of concurrent scan workers")
	fs.IntVar(&scanMaxHosts, "scan-max-hosts", 1024, "Maximum hosts to probe from CIDR")
	fs.BoolVar(&scanVerbose, "scan-verbose", false, "Print failed probe errors during scan")
	fs.StringVar(&inferBackupStructureDir, "infer-backup-structure-dir", "", "Infer backup.cfg structure from a directory of backup .bin files")
	fs.StringVar(&inferBackupBaseline, "infer-backup-baseline", "", "Baseline backup filename/path within --infer-backup-structure-dir")
	fs.StringVar(&suitePlanFile, "suite-plan", "", "Run a destructive real-switch mutation suite plan and exit")
	fs.StringVar(&suiteOutputDir, "suite-output-dir", "", "Override suite artifact output directory")

	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		host = args[0]
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	setFlags := map[string]struct{}{}
	fs.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = struct{}{}
	})
	hasFlag := func(name string) bool {
		_, ok := setFlags[name]
		return ok
	}
	scanUserExplicit := hasFlag("user") || hasFlag("u")
	scanPasswordExplicit := hasFlag("password") || hasFlag("p") || hasFlag("password-stdin") || hasFlag("password-file") || hasFlag("password-env")
	scanAuthenticate := scanUserExplicit && scanPasswordExplicit

	if decodeBackupFile != "" && (diffBackupBase != "" || diffBackupCandidate != "") {
		fmt.Fprintln(os.Stderr, "--decode-backup is mutually exclusive with --diff-backup-base/--diff-backup-candidate")
		os.Exit(2)
	}
	if inferBackupStructureDir != "" && (decodeBackupFile != "" || diffBackupBase != "" || diffBackupCandidate != "") {
		fmt.Fprintln(os.Stderr, "--infer-backup-structure-dir is mutually exclusive with backup decode/diff modes")
		os.Exit(2)
	}
	if suitePlanFile != "" && (decodeBackupFile != "" || diffBackupBase != "" || diffBackupCandidate != "") {
		fmt.Fprintln(os.Stderr, "--suite-plan is mutually exclusive with backup decode/diff modes")
		os.Exit(2)
	}
	if scanCIDR != "" && (decodeBackupFile != "" || diffBackupBase != "" || diffBackupCandidate != "") {
		fmt.Fprintln(os.Stderr, "--scan-cidr is mutually exclusive with backup decode/diff modes")
		os.Exit(2)
	}
	if scanCIDR != "" && suitePlanFile != "" {
		fmt.Fprintln(os.Stderr, "--scan-cidr is mutually exclusive with --suite-plan")
		os.Exit(2)
	}
	if scanCIDR != "" && inferBackupStructureDir != "" {
		fmt.Fprintln(os.Stderr, "--scan-cidr is mutually exclusive with --infer-backup-structure-dir")
		os.Exit(2)
	}
	if inferBackupStructureDir != "" && suitePlanFile != "" {
		fmt.Fprintln(os.Stderr, "--infer-backup-structure-dir is mutually exclusive with --suite-plan")
		os.Exit(2)
	}

	if decodeBackupFile != "" {
		data, err := readBackupFile(decodeBackupFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		decoded, err := tplink.DecodeBackupConfig(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to decode backup %q: %v\n", decodeBackupFile, err)
			os.Exit(1)
		}
		fmt.Print(tplink.FormatDecodedBackup(decoded))
		return
	}

	if (diffBackupBase == "") != (diffBackupCandidate == "") {
		fmt.Fprintln(os.Stderr, "--diff-backup-base and --diff-backup-candidate must be provided together")
		os.Exit(2)
	}
	if diffBackupBase != "" {
		baseData, err := readBackupFile(diffBackupBase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		candidateData, err := readBackupFile(diffBackupCandidate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}

		report, err := tplink.CompareBackupConfigs(baseData, candidateData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to diff backups %q and %q: %v\n", diffBackupBase, diffBackupCandidate, err)
			os.Exit(1)
		}
		fmt.Print(tplink.FormatBackupDiff(report))
		return
	}

	if scanCIDR != "" {
		if host != "" {
			fmt.Fprintln(os.Stderr, "--scan-cidr is hostless and cannot be used with a positional host")
			os.Exit(2)
		}
		if fs.NArg() > 0 {
			fmt.Fprintln(os.Stderr, "--scan-cidr is hostless and cannot be used with positional arguments")
			os.Exit(2)
		}
		if configFile != "" {
			fmt.Fprintln(os.Stderr, "--scan-cidr cannot be combined with --config-file")
			os.Exit(2)
		}

		resolvedPassword := ""
		if scanAuthenticate {
			var err error
			resolvedPassword, err = tplink.ResolvePassword(password, passwordStdin, passwordFile, passwordEnv)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(2)
			}
		}

		report, err := tplink.ScanNetwork(tplink.ScanOptions{
			CIDR:            scanCIDR,
			Port:            scanPort,
			Timeout:         scanTimeout,
			Workers:         scanWorkers,
			MaxHosts:        scanMaxHosts,
			Username:        user,
			Password:        resolvedPassword,
			FingerprintOnly: !scanAuthenticate,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
			os.Exit(2)
		}

		successes := report.Successful()
		fmt.Printf("Scan Results for %s\n", scanCIDR)
		if !scanAuthenticate {
			fmt.Println("  Note: --scan-cidr ran in fingerprint-only mode (no login) because explicit --user and password flags were not both provided.")
		}
		if report.Truncated {
			fmt.Printf("  Note: host range exceeded --scan-max-hosts; scanning first %d hosts only.\n", report.ScannedHosts)
		}
		if len(successes) == 0 {
			fmt.Println("  No reachable switches found.")
		} else {
			for _, result := range successes {
				fmt.Printf("  %s  |  %s  |  FW: %s  |  IP: %s\n", result.Host, result.Info.Description, result.Info.Firmware, result.Info.IP)
			}
		}

		failureSummary := summarizeScanFailures(report.Results)
		totalFailures := failureSummary.AuthFailures + failureSummary.NonTPLinkFailures + failureSummary.OtherFailures
		if totalFailures > 0 {
			fmt.Printf("  Failure Summary: auth=%d, non-tp-link=%d, other=%d. Use --scan-verbose for per-host errors.\n",
				failureSummary.AuthFailures,
				failureSummary.NonTPLinkFailures,
				failureSummary.OtherFailures,
			)
		}

		if scanVerbose {
			for _, result := range report.Results {
				if result.Err != nil {
					fmt.Printf("  %s  |  ERROR: %v\n", result.Host, result.Err)
				}
			}
		}

		fmt.Printf("\nScanned %d host(s); found %d switch(es).\n", report.ScannedHosts, len(successes))
		return
	}

	if inferBackupStructureDir != "" {
		if host != "" {
			fmt.Fprintln(os.Stderr, "--infer-backup-structure-dir is hostless and cannot be used with a positional host")
			os.Exit(2)
		}
		if fs.NArg() > 0 {
			fmt.Fprintln(os.Stderr, "--infer-backup-structure-dir is hostless and cannot be used with positional arguments")
			os.Exit(2)
		}
		if configFile != "" {
			fmt.Fprintln(os.Stderr, "--infer-backup-structure-dir cannot be combined with --config-file")
			os.Exit(2)
		}

		baselineName, baselineData, samples, err := loadBackupsForStructureInference(inferBackupStructureDir, inferBackupBaseline)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}

		report, err := tplink.InferBackupStructure(baselineName, baselineData, samples)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to infer backup structure: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(tplink.FormatBackupStructureReport(report))
		return
	}

	if suitePlanFile != "" {
		if host != "" {
			fmt.Fprintln(os.Stderr, "--suite-plan is hostless and cannot be used with a positional host")
			os.Exit(2)
		}
		if fs.NArg() > 0 {
			fmt.Fprintln(os.Stderr, "--suite-plan is hostless and cannot be used with positional arguments")
			os.Exit(2)
		}
		if configFile != "" {
			fmt.Fprintln(os.Stderr, "--suite-plan cannot be combined with --config-file")
			os.Exit(2)
		}

		runDir, err := hardwaresuite.RunHardwareSuite(context.Background(), suitePlanFile, suiteOutputDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "suite run failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "suite artifacts: %s\n", runDir)
			os.Exit(1)
		}
		fmt.Printf("Suite completed. Artifacts: %s\n", runDir)
		return
	}

	if host == "" {
		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, usageText())
			os.Exit(2)
		}
		host = fs.Arg(0)
	}

	if host == "" {
		fmt.Fprintln(os.Stderr, usageText())
		os.Exit(2)
	}

	resolvedPassword, err := tplink.ResolvePassword(password, passwordStdin, passwordFile, passwordEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}

	fmt.Printf("Connecting to %s... ", host)
	client, err := tplink.NewClient(host, tplink.WithUsername(user), tplink.WithPassword(resolvedPassword))
	if err != nil {
		fmt.Println("FAILED")
		fmt.Println(err)
		os.Exit(1)
	}
	if err := client.Login(); err != nil {
		fmt.Println("FAILED")
		fmt.Println(err)
		os.Exit(1)
	}
	defer client.Logout()

	info, err := client.GetSystemInfo()
	if err != nil {
		fmt.Println("FAILED")
		fmt.Println(err)
		os.Exit(1)
	}
	hostname := regexp.MustCompile(`[^A-Za-z0-9_-]`).ReplaceAllString(info.Description, "-")
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		hostname = "switch"
	}

	fmt.Println("OK")
	fmt.Printf("  %s  |  FW: %s  |  IP: %s\n\n", info.Description, info.Firmware, info.IP)
	cli := tplink.NewCLI(client, hostname)
	if configFile != "" {
		if err := cli.RunScriptFile(configFile); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Println("In interactive terminals: press ? for immediate help and Tab for completion. Type 'exit' to disconnect.")
	fmt.Println()
	if err := cli.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
