package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"
)

func runScanModeCLI(args ...string) ([]byte, error) {
	cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
	cmd.Dir = "."
	return cmd.CombinedOutput()
}

func testSwitchServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logon.cgi":
			http.SetCookie(w, &http.Cookie{Name: "H_P_SSID", Value: "ok"})
			fmt.Fprint(w, "<script>errType=0</script>")
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