package tplink

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrNonTPLinkSmartSwitch = errors.New("device did not match TP-Link smart switch signature")

const maxFingerprintBodyBytes int64 = 64 << 10

type ScanOptions struct {
	CIDR     string
	Port     int
	Timeout  time.Duration
	Workers  int
	MaxHosts int
	Username string
	Password string

	// FingerprintOnly skips login and only fingerprints the web UI.
	FingerprintOnly bool

	// Probe is optional and intended for tests.
	Probe func(host string, options ScanOptions) (*SystemInfo, error)
}

type ScanResult struct {
	Host string
	Info *SystemInfo
	Err  error
}

type ScanReport struct {
	CIDR         string
	TotalHosts   int
	ScannedHosts int
	Truncated    bool
	Results      []ScanResult
}

func (r ScanReport) Successful() []ScanResult {
	out := make([]ScanResult, 0, len(r.Results))
	for _, result := range r.Results {
		if result.Err == nil && result.Info != nil {
			out = append(out, result)
		}
	}
	return out
}

func ExpandCIDRHosts(cidr string, maxHosts int) ([]string, bool, error) {
	if maxHosts <= 0 {
		return nil, false, fmt.Errorf("maxHosts must be > 0")
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if !prefix.Addr().Is4() {
		return nil, false, fmt.Errorf("only IPv4 CIDR ranges are supported: %q", cidr)
	}

	prefix = prefix.Masked()
	bits := prefix.Bits()
	if bits < 0 || bits > 32 {
		return nil, false, fmt.Errorf("invalid CIDR prefix length: %d", bits)
	}

	total := uint64(1) << (32 - bits)
	start := ipToUint32(prefix.Addr())
	hostStart := start
	hostCount := total

	if bits < 31 {
		hostStart = start + 1
		hostCount = total - 2
	}

	if hostCount == 0 {
		return []string{}, false, nil
	}

	truncated := hostCount > uint64(maxHosts)
	limit := hostCount
	if truncated {
		limit = uint64(maxHosts)
	}

	hosts := make([]string, 0, limit)
	for i := uint64(0); i < limit; i++ {
		hosts = append(hosts, uint32ToAddr(hostStart+uint32(i)).String())
	}
	return hosts, truncated, nil
}

func ScanNetwork(options ScanOptions) (ScanReport, error) {
	if options.CIDR == "" {
		return ScanReport{}, fmt.Errorf("scan CIDR must not be empty")
	}
	if options.Port <= 0 || options.Port > 65535 {
		return ScanReport{}, fmt.Errorf("scan port must be in range 1-65535")
	}
	if options.Timeout <= 0 {
		return ScanReport{}, fmt.Errorf("scan timeout must be > 0")
	}
	if options.Workers <= 0 {
		return ScanReport{}, fmt.Errorf("scan workers must be > 0")
	}
	if options.MaxHosts <= 0 {
		return ScanReport{}, fmt.Errorf("scan max hosts must be > 0")
	}

	hosts, truncated, err := ExpandCIDRHosts(options.CIDR, options.MaxHosts)
	if err != nil {
		return ScanReport{}, err
	}

	probe := options.Probe
	if probe == nil {
		probe = defaultScanProbe
	}

	jobs := make(chan string)
	results := make(chan ScanResult, len(hosts))

	workerCount := options.Workers
	if workerCount > len(hosts) && len(hosts) > 0 {
		workerCount = len(hosts)
	}

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				info, probeErr := probe(host, options)
				results <- ScanResult{Host: host, Info: info, Err: probeErr}
			}
		}()
	}

	for _, host := range hosts {
		jobs <- host
	}
	close(jobs)
	wg.Wait()
	close(results)

	out := make([]ScanResult, 0, len(hosts))
	for result := range results {
		out = append(out, result)
	}
	sort.Slice(out, func(i, j int) bool {
		return ipCompare(out[i].Host, out[j].Host) < 0
	})

	return ScanReport{
		CIDR:         options.CIDR,
		TotalHosts:   len(hosts),
		ScannedHosts: len(hosts),
		Truncated:    truncated,
		Results:      out,
	}, nil
}

func defaultScanProbe(host string, options ScanOptions) (*SystemInfo, error) {
	targetHost := host
	if options.Port != 80 {
		targetHost = fmt.Sprintf("%s:%d", host, options.Port)
	}

	client, err := NewClient(
		targetHost,
		WithUsername(options.Username),
		WithPassword(options.Password),
		WithTimeout(options.Timeout),
	)
	if err != nil {
		return nil, err
	}
	if err := assertTPLinkWebUISignature(client); err != nil {
		return nil, err
	}
	if options.FingerprintOnly {
		return &SystemInfo{
			Description: "TP-Link web UI fingerprint",
			Firmware:    "unknown (unauthenticated)",
			IP:          host,
			Hardware:    "unknown (unauthenticated)",
		}, nil
	}
	if err := client.Login(); err != nil {
		return nil, err
	}
	defer client.Logout()

	info, err := client.GetSystemInfo()
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func assertTPLinkWebUISignature(client *Client) error {
	candidates := []string{"/", "/logon.cgi"}
	var lastErr error
	hadResponse := false
	for _, path := range candidates {
		body, err := fingerprintProbeBody(client, path)
		if err != nil {
			lastErr = err
			continue
		}
		hadResponse = true
		if looksLikeTPLinkWebUI(body) {
			return nil
		}
	}
	if !hadResponse && lastErr != nil {
		return lastErr
	}
	return ErrNonTPLinkSmartSwitch
}

func fingerprintProbeBody(client *Client, path string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, client.URL(path), nil)
	if err != nil {
		return "", fmt.Errorf("build %s request: %w", http.MethodGet, err)
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("%s %s failed: status %d body=%q", http.MethodGet, req.URL.String(), resp.StatusCode, string(b))
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFingerprintBodyBytes))
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}
	return string(b), nil
}

func looksLikeTPLinkWebUI(body string) bool {
	normalized := strings.ToUpper(body)
	hasBrand := strings.Contains(normalized, "TP-LINK") || strings.Contains(normalized, "TPLINK")
	hasModelFamily := strings.Contains(normalized, "TL-SG") || strings.Contains(normalized, "TL-SF") || strings.Contains(normalized, "EASY SMART")
	hasLegacyScript := strings.Contains(normalized, "LOGONINFO = NEW ARRAY") || strings.Contains(normalized, "ERRTYPE=LOGONINFO")

	assetHits := 0
	for _, marker := range []string{"LOGO.PNG", "TOP_BG.GIF", "BUTTON.GIF"} {
		if strings.Contains(normalized, marker) {
			assetHits++
		}
	}

	// Full legacy asset triplet is a strong TP-Link fingerprint by itself.
	if assetHits >= 3 {
		return true
	}

	classes := 0
	if hasBrand {
		classes++
	}
	if hasModelFamily {
		classes++
	}
	if hasLegacyScript {
		classes++
	}
	if assetHits >= 2 {
		classes++
	}

	return classes >= 2
}

func ipToUint32(addr netip.Addr) uint32 {
	v := addr.As4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func uint32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func ipCompare(left string, right string) int {
	l, err := netip.ParseAddr(left)
	if err != nil {
		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
		return 0
	}
	r, err := netip.ParseAddr(right)
	if err != nil {
		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
		return 0
	}
	if l.Less(r) {
		return -1
	}
	if r.Less(l) {
		return 1
	}
	return 0
}
