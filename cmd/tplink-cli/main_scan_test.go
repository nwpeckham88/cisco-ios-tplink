package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
)

func runScanModeCLI(args ...string) ([]byte, error) {
	cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
	cmd.Dir = "."
	return cmd.CombinedOutput()
}

func testSwitchServer(t *testing.T) *httptest.Server {
	t.Helper()
	return testSwitchServerWithCredentials(t, "admin", "test")
}

func testSwitchServerWithCredentials(t *testing.T, expectedUser string, expectedPassword string) *httptest.Server {
	t.Helper()
	srv, _ := testSwitchServerWithCredentialsAndPostCounter(t, expectedUser, expectedPassword)
	return srv
}

func testSwitchServerWithCredentialsAndPostCounter(t *testing.T, expectedUser string, expectedPassword string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	postCount := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><head><title>TP-Link Easy Smart Configuration Utility</title></head><body>TL-SG108E</body></html>`)
		case "/logon.cgi":
			if r.Method == http.MethodPost {
				postCount.Add(1)
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.PostForm.Get("username") != expectedUser || r.PostForm.Get("password") != expectedPassword {
				fmt.Fprint(w, `<script>errType=1</script><div>TP-Link Easy Smart</div>`)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "H_P_SSID", Value: "ok"})
			fmt.Fprint(w, `<script>errType=0</script><div>TP-Link Easy Smart</div>`)
		case "/PortSettingRpm.htm":
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
		case "/SystemInfoRpm.htm":
			fmt.Fprint(w, `<script>var info_ds = {descriStr:['TL-SG108E-LAB'],macStr:['AA:BB:CC:DD:EE:FF'],ipStr:['127.0.0.1'],netmaskStr:['255.0.0.0'],gatewayStr:['127.0.0.1'],firmwareStr:['1.0.1'],hardwareStr:['TL-SG108E 6.0']};</script>`)
		case "/Logout.htm":
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	return server, postCount
}

func testNonTPLinkServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	postCount := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><h1>Acme Login</h1><form action="/logon.cgi"></form></body></html>`)
		case "/logon.cgi":
			if r.Method == http.MethodPost {
				postCount.Add(1)
			}
			fmt.Fprint(w, `<html><body>Generic Appliance Login</body></html>`)
		case "/PortSettingRpm.htm":
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
		case "/SystemInfoRpm.htm":
			fmt.Fprint(w, `<script>var info_ds = {descriStr:['Admin Portal'],macStr:['AA:BB:CC:DD:EE:FF'],ipStr:['127.0.0.1'],netmaskStr:['255.0.0.0'],gatewayStr:['127.0.0.1'],firmwareStr:['9.9.9'],hardwareStr:['Generic-Web-UI']};</script>`)
		case "/Logout.htm":
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	return server, postCount
}

func extractPort(t *testing.T, serverURL string) string {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("Parse(%q): %v", serverURL, err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", u.Host, err)
	}
	return port
}

func TestScanCIDRModeIsHostless(t *testing.T) {
	srv := testSwitchServer(t)
	t.Cleanup(srv.Close)

	port := extractPort(t, srv.URL)
	out, err := runScanModeCLI(
		"--scan-cidr", "127.0.0.1/32",
		"--scan-port", port,
		"--scan-timeout", "2s",
		"--scan-workers", "1",
		"--user", "admin",
		"--password", "test",
	)
	if err != nil {
		t.Fatalf("scan mode failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if strings.Contains(text, "Connecting to") {
		t.Fatalf("scan mode should not use direct connect flow:\n%s", text)
	}
	if !strings.Contains(text, "Scan Results") {
		t.Fatalf("expected scan output, got:\n%s", text)
	}
	if !strings.Contains(text, "TL-SG108E-LAB") {
		t.Fatalf("expected discovered switch details, got:\n%s", text)
	}
}

func TestScanCIDRFingerprintOnlyWithoutCredentialsSkipsLogin(t *testing.T) {
	srv, postCount := testSwitchServerWithCredentialsAndPostCounter(t, "admin", "test")
	t.Cleanup(srv.Close)

	port := extractPort(t, srv.URL)
	out, err := runScanModeCLI(
		"--scan-cidr", "127.0.0.1/32",
		"--scan-port", port,
		"--scan-timeout", "2s",
		"--scan-workers", "1",
	)
	if err != nil {
		t.Fatalf("scan mode failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "fingerprint-only mode") {
		t.Fatalf("expected fingerprint-only note, got:\n%s", text)
	}
	if !strings.Contains(text, "TP-Link web UI fingerprint") {
		t.Fatalf("expected unauthenticated fingerprint result, got:\n%s", text)
	}
	if got := postCount.Load(); got != 0 {
		t.Fatalf("expected zero login POSTs in fingerprint-only mode, got %d", got)
	}
}

func TestScanCIDRUsesUserAndPasswordFlags(t *testing.T) {
	srv := testSwitchServerWithCredentials(t, "operator", "supersecret")
	t.Cleanup(srv.Close)

	port := extractPort(t, srv.URL)
	out, err := runScanModeCLI(
		"--scan-cidr", "127.0.0.1/32",
		"--scan-port", port,
		"--scan-timeout", "2s",
		"--scan-workers", "1",
		"--user", "operator",
		"--password", "supersecret",
	)
	if err != nil {
		t.Fatalf("scan mode failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "TL-SG108E-LAB") {
		t.Fatalf("expected discovered switch details with custom credentials, got:\n%s", text)
	}
}

func TestScanCIDRRejectsNonTPLinkDevice(t *testing.T) {
	srv, loginPostCount := testNonTPLinkServer(t)
	t.Cleanup(srv.Close)

	port := extractPort(t, srv.URL)
	out, err := runScanModeCLI(
		"--scan-cidr", "127.0.0.1/32",
		"--scan-port", port,
		"--scan-timeout", "2s",
		"--scan-workers", "1",
		"--password", "test",
		"--scan-verbose",
	)
	if err != nil {
		t.Fatalf("scan mode failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if strings.Contains(text, "|  Admin Portal  |") {
		t.Fatalf("non-TP-Link device should not be treated as discovered switch:\n%s", text)
	}
	if !strings.Contains(text, "No reachable switches found") {
		t.Fatalf("expected no-switch output for non-TP-Link device, got:\n%s", text)
	}
	if !strings.Contains(text, "Failure Summary: auth=0, non-tp-link=1, other=0") {
		t.Fatalf("expected non-TP-Link summary counts, got:\n%s", text)
	}
	if !strings.Contains(text, "ERROR: device did not match TP-Link smart switch signature") {
		t.Fatalf("expected TP-Link signature failure detail, got:\n%s", text)
	}
	if got := loginPostCount.Load(); got != 0 {
		t.Fatalf("expected zero credential POST attempts to non-TP-Link page, got %d", got)
	}
}

func TestScanCIDRNonVerboseSummaryIncludesFailures(t *testing.T) {
	srv := testSwitchServerWithCredentials(t, "admin", "goodpass")
	t.Cleanup(srv.Close)

	port := extractPort(t, srv.URL)
	out, err := runScanModeCLI(
		"--scan-cidr", "127.0.0.1/32",
		"--scan-port", port,
		"--scan-timeout", "2s",
		"--scan-workers", "1",
		"--user", "admin",
		"--password", "badpass",
	)
	if err != nil {
		t.Fatalf("scan mode failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if strings.Contains(text, "|  ERROR:") {
		t.Fatalf("non-verbose mode should not emit per-host error lines:\n%s", text)
	}
	if !strings.Contains(text, "Failure Summary:") {
		t.Fatalf("expected non-verbose failure summary line, got:\n%s", text)
	}
	if !strings.Contains(text, "Failure Summary: auth=1, non-tp-link=0, other=0") {
		t.Fatalf("expected exact auth failure summary counts, got:\n%s", text)
	}
	if !strings.Contains(text, "Use --scan-verbose") {
		t.Fatalf("expected scan-verbose hint in summary, got:\n%s", text)
	}
}

func TestScanCIDROtherFailureSummaryIncludesTransportErrors(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	stop := make(chan struct{})
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		_ = listener.Close()
	})

	out, err := runScanModeCLI(
		"--scan-cidr", "127.0.0.1/32",
		"--scan-port", fmt.Sprintf("%d", port),
		"--scan-timeout", "150ms",
		"--scan-workers", "1",
		"--password", "test",
	)
	if err != nil {
		t.Fatalf("scan mode failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "Failure Summary: auth=0, non-tp-link=0, other=1") {
		t.Fatalf("expected transport errors to be classified as other, got:\n%s", text)
	}
}

func TestScanCIDRRejectsPositionalHost(t *testing.T) {
	out, err := runScanModeCLI("192.168.0.1", "--scan-cidr", "192.168.0.0/24")
	if err == nil {
		t.Fatalf("expected host+scan conflict to fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "hostless") {
		t.Fatalf("expected hostless conflict message, got:\n%s", string(out))
	}
}

func TestScanCIDRRejectsTrailingPositionalArg(t *testing.T) {
	out, err := runScanModeCLI("--scan-cidr", "192.168.0.0/24", "192.168.0.10")
	if err == nil {
		t.Fatalf("expected trailing positional arg conflict to fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "hostless") {
		t.Fatalf("expected hostless conflict message, got:\n%s", string(out))
	}
}

func TestScanCIDRConflictsWithBackupModes(t *testing.T) {
	out, err := runScanModeCLI("--scan-cidr", "192.168.0.0/24", "--decode-backup", "fake.bin")
	if err == nil {
		t.Fatalf("expected scan+decode conflict to fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion message, got:\n%s", string(out))
	}
}

func TestScanCIDRRejectsInvalidCIDR(t *testing.T) {
	out, err := runScanModeCLI("--scan-cidr", "not-a-cidr")
	if err == nil {
		t.Fatalf("expected invalid CIDR to fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "invalid CIDR") {
		t.Fatalf("expected invalid CIDR message, got:\n%s", string(out))
	}
}

func TestScanCIDRHonorsMaxHostLimit(t *testing.T) {
	out, err := runScanModeCLI(
		"--scan-cidr", "10.0.0.0/24",
		"--scan-max-hosts", "1",
		"--scan-timeout", "100ms",
		"--scan-workers", "1",
	)
	if err != nil {
		t.Fatalf("scan mode should complete with host cap: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "host range exceeded --scan-max-hosts") {
		t.Fatalf("expected truncation message, got:\n%s", string(out))
	}
}

func TestScanCIDRConflictsWithConfigFile(t *testing.T) {
	out, err := runScanModeCLI("--scan-cidr", "192.168.0.0/24", "--config-file", "dummy.cfg")
	if err == nil {
		t.Fatalf("expected scan+config conflict to fail, output=%s", string(out))
	}
	if !strings.Contains(string(out), "cannot be combined with --config-file") {
		t.Fatalf("expected config-file conflict message, got:\n%s", string(out))
	}
}
