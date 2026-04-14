package tplink

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAssertTPLinkWebUISignatureAcceptsFingerprintPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><img src="logo.png"><div style="background-image:url(top_bg.gif)"></div><script>var a='button.gif';</script></html>`)
		case "/logon.cgi":
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "http://")
	client, err := NewClient(host, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := assertTPLinkWebUISignature(client); err != nil {
		t.Fatalf("assertTPLinkWebUISignature: %v", err)
	}
}

func TestAssertTPLinkWebUISignatureRejectsGenericPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/logon.cgi":
			fmt.Fprint(w, `<html><body><h1>Generic Appliance</h1><form action="/login"></form></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "http://")
	client, err := NewClient(host, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = assertTPLinkWebUISignature(client)
	if err == nil {
		t.Fatalf("expected non-TP-Link rejection")
	}
	if !errors.Is(err, ErrNonTPLinkSmartSwitch) {
		t.Fatalf("expected ErrNonTPLinkSmartSwitch, got: %v", err)
	}
}

func TestAssertTPLinkWebUISignaturePropagatesHTTPProbeErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not available", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "http://")
	client, err := NewClient(host, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = assertTPLinkWebUISignature(client)
	if err == nil {
		t.Fatalf("expected probe error")
	}
	if errors.Is(err, ErrNonTPLinkSmartSwitch) {
		t.Fatalf("expected underlying HTTP error, got non-tp-link sentinel")
	}
}

func TestLooksLikeTPLinkWebUIAcceptsImageAssetFingerprints(t *testing.T) {
	body := `<html><head><style>.top{background-image:url(top_bg.gif)}</style></head><body><img src="logo.png"><script>var b='button.gif';</script></body></html>`
	if !looksLikeTPLinkWebUI(body) {
		t.Fatalf("expected TP-Link web UI fingerprint match")
	}
}

func TestLooksLikeTPLinkWebUIRejectsGenericLoginMarkup(t *testing.T) {
	body := `<html><body><h1>Sign In</h1><form action="/login"></form><img src="logo.png"></body></html>`
	if looksLikeTPLinkWebUI(body) {
		t.Fatalf("expected generic login page to be rejected")
	}
}

func TestLooksLikeTPLinkWebUIRejectsSingleSpoofedToken(t *testing.T) {
	body := `<html><body><h1>Welcome</h1><div>TP-Link compatible management page</div></body></html>`
	if looksLikeTPLinkWebUI(body) {
		t.Fatalf("expected single-token spoof to be rejected")
	}
}

func TestLooksLikeTPLinkWebUIAcceptsBrandAndLegacyScriptSignals(t *testing.T) {
	body := `<script>var logonInfo = new Array(0,0,0); var errType=logonInfo[0];</script><div>TP-Link Corporation Limited</div>`
	if !looksLikeTPLinkWebUI(body) {
		t.Fatalf("expected multi-signal TP-Link fingerprint match")
	}
}

func TestExpandCIDRHostsIPv4ExcludesNetworkAndBroadcast(t *testing.T) {
	hosts, truncated, err := ExpandCIDRHosts("192.168.1.0/30", 10)
	if err != nil {
		t.Fatalf("ExpandCIDRHosts: %v", err)
	}
	if truncated {
		t.Fatalf("expected not truncated")
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0] != "192.168.1.1" || hosts[1] != "192.168.1.2" {
		t.Fatalf("unexpected hosts: %#v", hosts)
	}
}

func TestExpandCIDRHostsRespectsMaxHosts(t *testing.T) {
	hosts, truncated, err := ExpandCIDRHosts("10.0.0.0/24", 5)
	if err != nil {
		t.Fatalf("ExpandCIDRHosts: %v", err)
	}
	if !truncated {
		t.Fatalf("expected truncated=true")
	}
	if len(hosts) != 5 {
		t.Fatalf("expected 5 hosts, got %d", len(hosts))
	}
	if hosts[0] != "10.0.0.1" || hosts[4] != "10.0.0.5" {
		t.Fatalf("unexpected hosts: %#v", hosts)
	}
}

func TestScanNetworkDiscoversReachableSwitches(t *testing.T) {
	reachable := map[string]SystemInfo{
		"192.168.10.1": {Description: "switch-1", Firmware: "1.0.0", IP: "192.168.10.1"},
		"192.168.10.2": {Description: "switch-2", Firmware: "1.1.0", IP: "192.168.10.2"},
	}
	report, err := ScanNetwork(ScanOptions{
		CIDR:     "192.168.10.0/30",
		Port:     80,
		Timeout:  100 * time.Millisecond,
		Workers:  2,
		MaxHosts: 20,
		Probe: func(host string, _ ScanOptions) (*SystemInfo, error) {
			if info, ok := reachable[host]; ok {
				copyInfo := info
				return &copyInfo, nil
			}
			return nil, fmt.Errorf("unreachable")
		},
	})
	if err != nil {
		t.Fatalf("ScanNetwork: %v", err)
	}
	if report.TotalHosts != 2 {
		t.Fatalf("expected TotalHosts=2 got %d", report.TotalHosts)
	}
	found := report.Successful()
	if len(found) != 2 {
		t.Fatalf("expected 2 successes, got %d", len(found))
	}
	if found[0].Info.Description != "switch-1" {
		t.Fatalf("unexpected first description: %q", found[0].Info.Description)
	}
	if found[1].Info.Description != "switch-2" {
		t.Fatalf("unexpected second description: %q", found[1].Info.Description)
	}
}

func TestScanNetworkSkipsLoginFailuresAndContinues(t *testing.T) {
	report, err := ScanNetwork(ScanOptions{
		CIDR:     "10.10.0.0/30",
		Port:     80,
		Timeout:  100 * time.Millisecond,
		Workers:  2,
		MaxHosts: 20,
		Probe: func(host string, _ ScanOptions) (*SystemInfo, error) {
			if host == "10.10.0.1" {
				return &SystemInfo{Description: "switch-ok", IP: host}, nil
			}
			return nil, fmt.Errorf("login failed")
		},
	})
	if err != nil {
		t.Fatalf("ScanNetwork: %v", err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(report.Results))
	}
	if len(report.Successful()) != 1 {
		t.Fatalf("expected 1 successful result, got %d", len(report.Successful()))
	}
}

func TestScanNetworkHonorsWorkerLimit(t *testing.T) {
	var current int32
	var maxSeen int32
	report, err := ScanNetwork(ScanOptions{
		CIDR:     "10.20.0.0/28",
		Port:     80,
		Timeout:  250 * time.Millisecond,
		Workers:  3,
		MaxHosts: 50,
		Probe: func(host string, _ ScanOptions) (*SystemInfo, error) {
			now := atomic.AddInt32(&current, 1)
			for {
				seen := atomic.LoadInt32(&maxSeen)
				if now <= seen || atomic.CompareAndSwapInt32(&maxSeen, seen, now) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&current, -1)
			return &SystemInfo{Description: "ok", IP: host}, nil
		},
	})
	if err != nil {
		t.Fatalf("ScanNetwork: %v", err)
	}
	if report.TotalHosts != 14 {
		t.Fatalf("expected TotalHosts=14 got %d", report.TotalHosts)
	}
	if got := atomic.LoadInt32(&maxSeen); got > 3 {
		t.Fatalf("expected max concurrent probes <= 3, got %d", got)
	}
}

func TestScanNetworkRejectsInvalidOptions(t *testing.T) {
	base := ScanOptions{CIDR: "10.0.0.0/30", Port: 80, Timeout: time.Second, Workers: 1, MaxHosts: 8}
	cases := []struct {
		name string
		mut  func(*ScanOptions)
	}{
		{name: "empty cidr", mut: func(o *ScanOptions) { o.CIDR = "" }},
		{name: "invalid port", mut: func(o *ScanOptions) { o.Port = 0 }},
		{name: "invalid timeout", mut: func(o *ScanOptions) { o.Timeout = 0 }},
		{name: "invalid workers", mut: func(o *ScanOptions) { o.Workers = 0 }},
		{name: "invalid max hosts", mut: func(o *ScanOptions) { o.MaxHosts = 0 }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			tc.mut(&opts)
			_, err := ScanNetwork(opts)
			if err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestScanNetworkIPv4OrderingIsStable(t *testing.T) {
	var mu sync.Mutex
	visited := make([]string, 0, 4)
	report, err := ScanNetwork(ScanOptions{
		CIDR:     "10.30.0.0/30",
		Port:     80,
		Timeout:  100 * time.Millisecond,
		Workers:  2,
		MaxHosts: 20,
		Probe: func(host string, _ ScanOptions) (*SystemInfo, error) {
			mu.Lock()
			visited = append(visited, host)
			mu.Unlock()
			return nil, fmt.Errorf("no device")
		},
	})
	if err != nil {
		t.Fatalf("ScanNetwork: %v", err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(report.Results))
	}
	if report.Results[0].Host != "10.30.0.1" || report.Results[1].Host != "10.30.0.2" {
		t.Fatalf("unexpected result ordering: %#v", report.Results)
	}
	if len(visited) != 2 {
		t.Fatalf("expected two probe calls, got %d", len(visited))
	}
}
