package tplink

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newWriteEraseCLI(t *testing.T) (*CLI, *atomic.Int32) {
	t.Helper()

	var resetCalls atomic.Int32
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logon.cgi":
			http.SetCookie(w, &http.Cookie{Name: "H_P_SSID", Value: "ok"})
			fmt.Fprint(w, "<script>errType=0</script>")
		case "/PortSettingRpm.htm":
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
		case "/IpSettingRpm.htm":
			fmt.Fprint(w, `<script>var ip_ds = {state:0, ipStr:['10.1.1.239'], netmaskStr:['255.255.255.0'], gatewayStr:['10.1.1.1']};</script>`)
		case "/Vlan8021QRpm.htm":
			fmt.Fprint(w, `<script>var qvlan_ds = {state:1, count:2, vids:[1,10], names:['VLAN1','Users'], tagMbrs:[0,3], untagMbrs:[255,28]};</script>`)
		case "/Vlan8021QPvidRpm.htm":
			fmt.Fprint(w, `<script>var pvid_ds = {pvids:[1,1,10,10,10,1,1,1]};</script>`)
		case "/config_back.cgi":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(buildSyntheticBackup())
		case "/reset.cgi":
			resetCalls.Add(1)
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	})

	return NewCLI(client, "switch"), &resetCalls
}

func withStdinInput(t *testing.T, input string, fn func()) {
	t.Helper()

	original := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := io.WriteString(w, input); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	_ = w.Close()

	os.Stdin = r
	defer func() {
		os.Stdin = original
		_ = r.Close()
	}()

	fn()
}

func TestWriteEraseRequiresExactResetToken(t *testing.T) {
	c, resetCalls := newWriteEraseCLI(t)

	out := captureStdout(t, func() {
		withStdinInput(t, "reset\n", func() {
			quit, err := c.cmdWrite("erase")
			if err != nil {
				t.Fatalf("cmdWrite: %v", err)
			}
			if quit {
				t.Fatal("expected CLI to continue after cancelled reset")
			}
		})
	})

	if resetCalls.Load() != 0 {
		t.Fatalf("FactoryReset should not be called for lowercase token, calls=%d", resetCalls.Load())
	}
	if !strings.Contains(out, "Type RESET to confirm") {
		t.Fatalf("missing RESET confirmation prompt in output: %q", out)
	}
	if !strings.Contains(out, "Cancelled") {
		t.Fatalf("missing cancellation message in output: %q", out)
	}
}

func TestWriteEraseExecutesOnCorrectToken(t *testing.T) {
	c, resetCalls := newWriteEraseCLI(t)

	out := captureStdout(t, func() {
		withStdinInput(t, "RESET\n", func() {
			quit, err := c.cmdWrite("erase")
			if err != nil {
				t.Fatalf("cmdWrite: %v", err)
			}
			if !quit {
				t.Fatal("expected CLI to exit after factory reset")
			}
		})
	})

	if resetCalls.Load() != 1 {
		t.Fatalf("FactoryReset should be called exactly once, calls=%d", resetCalls.Load())
	}
	if !strings.Contains(out, "192.168.0.1") {
		t.Fatalf("expected reconnect advisory to include default IP, got: %q", out)
	}
}

func TestWriteEraseShowsVLANSummary(t *testing.T) {
	c, _ := newWriteEraseCLI(t)

	out := captureStdout(t, func() {
		withStdinInput(t, "cancel\n", func() {
			_, _ = c.cmdWrite("erase")
		})
	})

	if !strings.Contains(out, "Current VLANs:") {
		t.Fatalf("missing VLAN summary header in output: %q", out)
	}
	if !strings.Contains(out, "10") || !strings.Contains(out, "tagged") || !strings.Contains(out, "untagged") {
		t.Fatalf("missing expected VLAN details in output: %q", out)
	}
}

func TestWriteEraseShowsIPAddress(t *testing.T) {
	c, _ := newWriteEraseCLI(t)

	out := captureStdout(t, func() {
		withStdinInput(t, "cancel\n", func() {
			_, _ = c.cmdWrite("erase")
		})
	})

	if !strings.Contains(out, "Current IP:") {
		t.Fatalf("missing Current IP line in output: %q", out)
	}
	if !strings.Contains(out, "10.1.1.239") {
		t.Fatalf("missing expected IP value in output: %q", out)
	}
}

func TestWriteMemoryAlias(t *testing.T) {
	c, resetCalls := newWriteEraseCLI(t)

	out := captureStdout(t, func() {
		quit, err := c.cmdWrite("memory")
		if err != nil {
			t.Fatalf("cmdWrite(memory): %v", err)
		}
		if quit {
			t.Fatal("expected write memory to keep session open")
		}
	})

	if resetCalls.Load() != 0 {
		t.Fatalf("write memory should not trigger reset, calls=%d", resetCalls.Load())
	}
	if !strings.Contains(out, "Building configuration") || !strings.Contains(out, "[OK]") {
		t.Fatalf("missing IOS-style save output: %q", out)
	}
}

func TestEraseStartupConfigAlias(t *testing.T) {
	c, resetCalls := newWriteEraseCLI(t)

	out := captureStdout(t, func() {
		withStdinInput(t, "RESET\n", func() {
			quit, err := c.cmdErase("startup-config")
			if err != nil {
				t.Fatalf("cmdErase(startup-config): %v", err)
			}
			if !quit {
				t.Fatal("expected erase startup-config to exit after reset")
			}
		})
	})

	if resetCalls.Load() != 1 {
		t.Fatalf("erase startup-config should call FactoryReset once, calls=%d", resetCalls.Load())
	}
	if !strings.Contains(out, "Type RESET to confirm") {
		t.Fatalf("missing destructive confirmation prompt: %q", out)
	}
}

func TestCopyRunningStartupAlias(t *testing.T) {
	c, resetCalls := newWriteEraseCLI(t)

	out := captureStdout(t, func() {
		quit, err := c.cmdCopy("running-config startup-config")
		if err != nil {
			t.Fatalf("cmdCopy(running-config startup-config): %v", err)
		}
		if quit {
			t.Fatal("expected copy running-config startup-config to keep session open")
		}
	})

	if resetCalls.Load() != 0 {
		t.Fatalf("copy running-config startup-config should not trigger reset, calls=%d", resetCalls.Load())
	}
	if !strings.Contains(out, "Building configuration") || !strings.Contains(out, "[OK]") {
		t.Fatalf("missing IOS-style save output: %q", out)
	}
}

func TestCopyRunningConfigToFile(t *testing.T) {
	c, resetCalls := newWriteEraseCLI(t)

	dest := filepath.Join(t.TempDir(), "live-backup.bin")
	out := captureStdout(t, func() {
		quit, err := c.cmdCopy("running-config " + dest)
		if err != nil {
			t.Fatalf("cmdCopy(running-config <file>): %v", err)
		}
		if quit {
			t.Fatal("expected backup download to keep session open")
		}
	})

	if resetCalls.Load() != 0 {
		t.Fatalf("copy running-config <file> should not trigger reset, calls=%d", resetCalls.Load())
	}
	if !strings.Contains(out, "Config saved to") {
		t.Fatalf("missing save confirmation output: %q", out)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", dest, err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty backup file")
	}
	decoded, err := DecodeBackupConfig(data)
	if err != nil {
		t.Fatalf("DecodeBackupConfig(downloaded): %v", err)
	}
	if decoded.Magic != backupMagic {
		t.Fatalf("unexpected backup magic: %#x", decoded.Magic)
	}
}

func TestExecLineWriteMemoryAbbreviation(t *testing.T) {
	c, _ := newWriteEraseCLI(t)

	out := captureStdout(t, func() {
		quit, err := c.execLine("wr mem")
		if err != nil {
			t.Fatalf("execLine(wr mem): %v", err)
		}
		if quit {
			t.Fatal("expected wr mem to keep session open")
		}
	})

	if !strings.Contains(out, "Building configuration") || !strings.Contains(out, "[OK]") {
		t.Fatalf("missing IOS-style save output: %q", out)
	}
}

func TestCopyShortFilenameNotTreatedAsAlias(t *testing.T) {
	c, _ := newWriteEraseCLI(t)

	_, err := c.cmdCopy("run running-config")
	if err == nil {
		t.Fatal("expected missing source file error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "no such") {
		t.Fatalf("expected file read error, got: %v", err)
	}
}

func TestCopyRestoreShowsBackupPreviewAndDate(t *testing.T) {
	c, _ := newWriteEraseCLI(t)

	backupFile := filepath.Join(t.TempDir(), "config.cfg")
	if err := os.WriteFile(backupFile, buildSyntheticBackup(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	expectedDate := time.Date(2026, time.April, 12, 9, 30, 0, 0, time.Local)
	if err := os.Chtimes(backupFile, expectedDate, expectedDate); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	out := captureStdout(t, func() {
		withStdinInput(t, "n\n", func() {
			quit, err := c.cmdCopy(fmt.Sprintf("%s running-config", backupFile))
			if err != nil {
				t.Fatalf("cmdCopy(<file> running-config): %v", err)
			}
			if quit {
				t.Fatal("expected cancelled restore to keep session open")
			}
		})
	})

	checks := []string{
		"Backup preview from",
		"Backup date",
		formatBackupDate(expectedDate),
		"Hostname    : TPLINK-DIST-SWITCH",
		"IP          : 192.168.3.49",
		"Netmask     : 255.255.254.0",
		"Gateway     : 192.168.2.1",
		"DHCP        : enabled",
		"Restore from",
		"Cancelled",
	}
	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Fatalf("missing %q in output: %q", check, out)
		}
	}
}
