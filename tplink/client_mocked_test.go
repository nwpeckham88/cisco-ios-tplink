package tplink

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	c, err := NewClient(host, WithUsername("admin"), WithPassword("test"), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, srv
}

func TestLoginSuccessRequiresCookie(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logon.cgi":
			http.SetCookie(w, &http.Cookie{Name: "H_P_SSID", Value: "ok"})
			fmt.Fprint(w, "<script>errType=0</script>")
		case "/PortSettingRpm.htm":
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
		default:
			http.NotFound(w, r)
		}
	})

	if err := client.Login(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
}

func TestLoginFailureErrType(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logon.cgi" {
			fmt.Fprint(w, "<script>errType=1</script>")
			return
		}
		if r.URL.Path == "/PortSettingRpm.htm" {
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
			return
		}
		http.NotFound(w, r)
	})
	if err := client.Login(); err == nil {
		t.Fatal("expected login failure")
	}
}

func TestLoginFailureErrTypeFromLogonInfoArray(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logon.cgi" {
			fmt.Fprint(w, "<script>var logonInfo = new Array(1,0,0); var errType=logonInfo[0];</script>")
			return
		}
		if r.URL.Path == "/PortSettingRpm.htm" {
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
			return
		}
		http.NotFound(w, r)
	})
	err := client.Login()
	if err == nil {
		t.Fatal("expected login failure")
	}
	if !strings.Contains(err.Error(), "errType=1") {
		t.Fatalf("expected errType failure, got: %v", err)
	}
}

func TestLoginNoCookieFails(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logon.cgi" {
			fmt.Fprint(w, "<script>errType=0</script>")
			return
		}
		if r.URL.Path == "/PortSettingRpm.htm" {
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
			return
		}
		http.NotFound(w, r)
	})
	if err := client.Login(); err == nil {
		t.Fatal("expected missing cookie error")
	}
}

func TestReauthOnLoginPage(t *testing.T) {
	var systemCount int32
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logon.cgi":
			http.SetCookie(w, &http.Cookie{Name: "H_P_SSID", Value: "ok"})
			fmt.Fprint(w, "<script>errType=0</script>")
		case "/PortSettingRpm.htm":
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
		case "/SystemInfoRpm.htm":
			if atomic.AddInt32(&systemCount, 1) == 1 {
				fmt.Fprint(w, `Please login <form action="logon.cgi">errType</form>`)
				return
			}
			fmt.Fprint(w, `<script>var info_ds = {descriStr:['TL-SG108E'],macStr:['AA:BB:CC:DD:EE:FF'],ipStr:['10.1.1.239'],netmaskStr:['255.255.255.0'],gatewayStr:['10.1.1.1'],firmwareStr:['1.0.0'],hardwareStr:['TL-SG108E 6.0']};</script>`)
		default:
			http.NotFound(w, r)
		}
	})

	if err := client.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
	info, err := client.GetSystemInfo()
	if err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	if info.IP != "10.1.1.239" {
		t.Fatalf("unexpected ip %q", info.IP)
	}
	if atomic.LoadInt32(&systemCount) != 2 {
		t.Fatalf("expected 2 system calls, got %d", systemCount)
	}
}

func TestSetIPSettingsPreservesUnspecifiedValues(t *testing.T) {
	var writeQuery url.Values
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logon.cgi":
			http.SetCookie(w, &http.Cookie{Name: "H_P_SSID", Value: "ok"})
			fmt.Fprint(w, "<script>errType=0</script>")
		case "/PortSettingRpm.htm":
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
		case "/IpSettingRpm.htm":
			fmt.Fprint(w, `<script>var ip_ds = {state:0, ipStr:['10.1.1.239'], netmaskStr:['255.255.255.0'], gatewayStr:['10.1.1.1']};</script>`)
		case "/ip_setting.cgi":
			writeQuery = r.URL.Query()
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	})

	if err := client.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := client.SetIPSettings("10.1.1.100", "", "", nil); err != nil {
		t.Fatalf("SetIPSettings: %v", err)
	}
	if got := writeQuery.Get("ip_address"); got != "10.1.1.100" {
		t.Fatalf("ip_address=%q", got)
	}
	if got := writeQuery.Get("ip_netmask"); got != "255.255.255.0" {
		t.Fatalf("ip_netmask=%q", got)
	}
	if got := writeQuery.Get("ip_gateway"); got != "10.1.1.1" {
		t.Fatalf("ip_gateway=%q", got)
	}
}

func TestSetPortsNoChangeSentinel(t *testing.T) {
	var q url.Values
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logon.cgi":
			http.SetCookie(w, &http.Cookie{Name: "H_P_SSID", Value: "ok"})
			fmt.Fprint(w, "<script>errType=0</script>")
		case "/PortSettingRpm.htm":
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
		case "/port_setting.cgi":
			q = r.URL.Query()
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	})

	if err := client.Login(); err != nil {
		t.Fatalf("login: %v", err)
	}
	speed := PortSpeedAuto
	if err := client.SetPort(1, nil, &speed, nil); err != nil {
		t.Fatalf("SetPort: %v", err)
	}
	if q.Get("state") != "7" || q.Get("flowcontrol") != "7" {
		t.Fatalf("expected no-change sentinels, got state=%s flowcontrol=%s", q.Get("state"), q.Get("flowcontrol"))
	}
	if q.Get("speed") != "1" {
		t.Fatalf("expected speed=1 got %s", q.Get("speed"))
	}
}
