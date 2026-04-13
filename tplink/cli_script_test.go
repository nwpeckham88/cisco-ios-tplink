package tplink

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newScriptTestCLI(t *testing.T, mutations *[]string) *CLI {
	t.Helper()

	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logon.cgi":
			http.SetCookie(w, &http.Cookie{Name: "H_P_SSID", Value: "ok"})
			fmt.Fprint(w, "<script>errType=0</script>")
		case "/PortSettingRpm.htm":
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
		case "/IpSettingRpm.htm":
			fmt.Fprint(w, `<script>var ip_ds = {state:0, ipStr:['192.0.2.10'], netmaskStr:['255.255.255.0'], gatewayStr:['192.0.2.1']};</script>`)
		case "/Vlan8021QRpm.htm":
			fmt.Fprint(w, `<script>var qvlan_ds = {state:0, count:0, vids:[], names:[], tagMbrs:[], untagMbrs:[]};</script>`)
		case "/PortTrunkRpm.htm":
			fmt.Fprint(w, `<script>var trunk_conf = {maxTrunkNum:2, portNum:8, portStr_g1:[0,0,0,0,0,0,0,0], portStr_g2:[0,0,0,0,0,0,0,0]};</script>`)
		default:
			if strings.HasSuffix(r.URL.Path, ".cgi") {
				*mutations = append(*mutations, r.URL.Path)
				fmt.Fprint(w, "ok")
				return
			}
			http.NotFound(w, r)
		}
	})
	if err := client.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return NewCLI(client, "switch")
}

func TestRunScriptAppliesCommandsInOrder(t *testing.T) {
	mutations := []string{}
	cli := newScriptTestCLI(t, &mutations)

	script := strings.Join([]string{
		"! v1 static profile",
		"configure terminal",
		"hostname lab-switch",
		"ip address dhcp",
		"interface gi1",
		"switchport pvid 10",
		"exit",
		"interface range gi5-6",
		"channel-group 1",
		"exit",
		"vlan 10",
		"name USERS",
		"exit",
		"end",
		"write memory",
	}, "\n")

	if err := cli.RunScript(strings.NewReader(script), "v1-static.cfg"); err != nil {
		t.Fatalf("RunScript: %v", err)
	}

	want := []string{
		"/system_name_set.cgi",
		"/ip_setting.cgi",
		"/vlanPvidSet.cgi",
		"/port_trunk_set.cgi",
		"/qvlanSet.cgi",
		"/qvlanSet.cgi",
	}
	if len(mutations) != len(want) {
		t.Fatalf("mutation count=%d want=%d (%v)", len(mutations), len(want), mutations)
	}
	for i := range want {
		if mutations[i] != want[i] {
			t.Fatalf("mutation[%d]=%q want %q (all=%v)", i, mutations[i], want[i], mutations)
		}
	}
}

func TestRunScriptSkipsBlankLinesAndComments(t *testing.T) {
	mutations := []string{}
	cli := newScriptTestCLI(t, &mutations)

	script := "! comment\n\nconfigure terminal\n\nhostname lab-switch\nend\n"
	if err := cli.RunScript(strings.NewReader(script), "comments.cfg"); err != nil {
		t.Fatalf("RunScript: %v", err)
	}

	if len(mutations) != 1 || mutations[0] != "/system_name_set.cgi" {
		t.Fatalf("unexpected mutations: %v", mutations)
	}
}

func TestRunScriptStopsOnFirstErrorWithLineContext(t *testing.T) {
	mutations := []string{}
	cli := newScriptTestCLI(t, &mutations)

	script := strings.Join([]string{
		"configure terminal",
		"hostname lab-switch",
		"bad command",
		"ip address dhcp",
	}, "\n")

	err := cli.RunScript(strings.NewReader(script), "bad.cfg")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "bad.cfg:3") {
		t.Fatalf("error=%v", err)
	}
	if len(mutations) != 1 || mutations[0] != "/system_name_set.cgi" {
		t.Fatalf("script should stop after first mutation, got %v", mutations)
	}
}

func TestRunScriptFileReadsFromDisk(t *testing.T) {
	mutations := []string{}
	cli := newScriptTestCLI(t, &mutations)

	path := filepath.Join(t.TempDir(), "script.cfg")
	content := "configure terminal\nhostname disk-switch\nend\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := cli.RunScriptFile(path); err != nil {
		t.Fatalf("RunScriptFile: %v", err)
	}
	if len(mutations) != 1 || mutations[0] != "/system_name_set.cgi" {
		t.Fatalf("unexpected mutations: %v", mutations)
	}
}
