package tplink

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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