package tplink

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Option func(*Client)

func WithUsername(username string) Option {
	return func(c *Client) {
		if username != "" {
			c.Username = username
		}
	}
}

func WithPassword(password string) Option {
	return func(c *Client) {
		if password != "" {
			c.password = password
		}
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		if timeout > 0 {
			c.Timeout = timeout
			if c.httpClient != nil {
				c.httpClient.Timeout = timeout
			}
		}
	}
}

func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
			if c.Timeout > 0 {
				c.httpClient.Timeout = c.Timeout
			}
		}
	}
}

type Client struct {
	Host     string
	Username string
	Timeout  time.Duration

	password   string
	httpClient *http.Client
	loggedIn   bool
	loginTime  time.Time
	sessionTTL time.Duration
	portCount  int
}

func NewClient(host string, opts ...Option) (*Client, error) {
	if strings.TrimSpace(host) == "" {
		return nil, fmt.Errorf("host must not be empty")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	c := &Client{
		Host:       host,
		Username:   "admin",
		password:   FirmwarePassword,
		Timeout:    10 * time.Second,
		sessionTTL: 550 * time.Second,
		portCount:  8,
		httpClient: &http.Client{Timeout: 10 * time.Second, Jar: jar},
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.httpClient.Jar == nil {
		c.httpClient.Jar = jar
	}
	if c.httpClient.Timeout == 0 {
		c.httpClient.Timeout = c.Timeout
	}
	return c, nil
}

func (c *Client) URL(path string) string {
	return fmt.Sprintf("http://%s/%s", c.Host, strings.TrimPrefix(path, "/"))
}

func isLoginPage(text string) bool {
	return strings.Contains(text, "logon.cgi") && strings.Contains(text, "errType")
}

func (c *Client) ensureSession() error {
	if !c.loggedIn || time.Since(c.loginTime) > c.sessionTTL {
		return c.Login()
	}
	return nil
}

func (c *Client) doGet(path string, query url.Values) ([]byte, error) {
	if err := c.ensureSession(); err != nil {
		return nil, err
	}
	body, err := c.rawRequest(http.MethodGet, path, query, nil, "")
	if err != nil {
		return nil, err
	}
	if isLoginPage(string(body)) {
		c.loggedIn = false
		if err := c.Login(); err != nil {
			return nil, err
		}
		return c.rawRequest(http.MethodGet, path, query, nil, "")
	}
	return body, nil
}

func (c *Client) cfgGet(path string, query url.Values) ([]byte, error) {
	if err := c.ensureSession(); err != nil {
		return nil, err
	}
	body, err := c.rawRequest(http.MethodGet, path, query, nil, "")
	if err != nil {
		if isConnDrop(err) {
			c.loggedIn = false
			return nil, nil
		}
		return nil, err
	}
	if isLoginPage(string(body)) {
		c.loggedIn = false
		if err := c.Login(); err != nil {
			return nil, err
		}
		return c.rawRequest(http.MethodGet, path, query, nil, "")
	}
	return body, nil
}

func (c *Client) cfgPost(path string, form url.Values) ([]byte, error) {
	if err := c.ensureSession(); err != nil {
		return nil, err
	}
	body, err := c.rawRequest(http.MethodPost, path, nil, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		if isConnDrop(err) {
			c.loggedIn = false
			return nil, nil
		}
		return nil, err
	}
	if isLoginPage(string(body)) {
		c.loggedIn = false
		if err := c.Login(); err != nil {
			return nil, err
		}
		return c.rawRequest(http.MethodPost, path, nil, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	}
	return body, nil
}

func (c *Client) rawRequest(method, path string, query url.Values, body io.Reader, contentType string) ([]byte, error) {
	u, err := url.Parse(c.URL(path))
	if err != nil {
		return nil, fmt.Errorf("parse url %q: %w", path, err)
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", method, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s %s failed: status %d body=%q", method, u.String(), resp.StatusCode, string(b))
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return payload, nil
}

func (c *Client) page(name string) (string, error) {
	body, err := c.doGet(name+".htm", nil)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) Login() error {
	form := url.Values{}
	form.Set("username", c.Username)
	form.Set("password", c.password)
	form.Set("logon", "Login")

	body, err := c.rawRequest(
		http.MethodPost,
		"logon.cgi",
		nil,
		strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded",
	)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	if strings.Contains(string(body), "errType") {
		m := regexp.MustCompile(`errType\s*=\s*(\d+)`).FindStringSubmatch(string(body))
		if len(m) == 2 {
			errType, _ := strconv.Atoi(m[1])
			if errType != 0 {
				return fmt.Errorf("login failed (errType=%d): check username and password", errType)
			}
		}
	}

	if !c.hasSSIDCookie() {
		return fmt.Errorf("login did not return a session cookie")
	}

	c.loggedIn = true
	c.loginTime = time.Now()

	// Best-effort port count cache.
	if body, err := c.rawRequest(http.MethodGet, "PortSettingRpm.htm", nil, nil, ""); err == nil {
		if n := asInt(extractVar(string(body), "max_port_num")); n > 0 {
			c.portCount = n
		}
	}
	if c.portCount <= 0 {
		c.portCount = 8
	}
	return nil
}

func (c *Client) Logout() {
	if c.loggedIn {
		_, _ = c.rawRequest(http.MethodGet, "Logout.htm", nil, nil, "")
	}
	c.clearCookies()
	c.loggedIn = false
}

func (c *Client) Close() {
	c.Logout()
}

func (c *Client) hasSSIDCookie() bool {
	u, err := url.Parse(c.URL("/"))
	if err != nil {
		return false
	}
	for _, cookie := range c.httpClient.Jar.Cookies(u) {
		if strings.Contains(cookie.Name, "H_P_SSID") {
			return true
		}
	}
	return false
}

func (c *Client) clearCookies() {
	jar, _ := cookiejar.New(nil)
	c.httpClient.Jar = jar
}

func isConnDrop(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection aborted") ||
		strings.Contains(msg, "eof")
}

func (c *Client) maxPort() int {
	if c.portCount > 0 {
		return c.portCount
	}
	return 8
}

func (c *Client) validatePort(port int, maxPort int) error {
	if maxPort <= 0 {
		maxPort = c.maxPort()
	}
	if port < 1 || port > maxPort {
		return fmt.Errorf("port must be in range 1-%d: %d", maxPort, port)
	}
	return nil
}

func (c *Client) validatePorts(ports []int, allowEmpty bool, maxPort int) ([]int, error) {
	if len(ports) == 0 && !allowEmpty {
		return nil, fmt.Errorf("ports must contain at least one port number")
	}
	seen := map[int]struct{}{}
	validated := make([]int, 0, len(ports))
	for _, p := range ports {
		if err := c.validatePort(p, maxPort); err != nil {
			return nil, err
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		validated = append(validated, p)
	}
	sort.Ints(validated)
	return validated, nil
}

func validateVLANID(vid int, fieldName string) error {
	if fieldName == "" {
		fieldName = "vid"
	}
	if vid < 1 || vid > 4094 {
		return fmt.Errorf("%s must be in range 1-4094: %d", fieldName, vid)
	}
	return nil
}

func validateIPv4(value string, fieldName string) error {
	if fieldName == "" {
		fieldName = "ip"
	}
	if _, err := netip.ParseAddr(value); err != nil {
		return fmt.Errorf("%s must be a valid IPv4 address: %q", fieldName, value)
	}
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s must be IPv4: %q", fieldName, value)
	}
	return nil
}

func validateNetmask(value string) error {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return fmt.Errorf("netmask must be a valid IPv4 netmask: %q", value)
	}
	mask := 0
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return fmt.Errorf("netmask must be a valid IPv4 netmask: %q", value)
		}
		mask = (mask << 8) | n
	}
	seenZero := false
	for i := 31; i >= 0; i-- {
		bit := (mask >> i) & 1
		if bit == 0 {
			seenZero = true
			continue
		}
		if seenZero {
			return fmt.Errorf("netmask must be a valid IPv4 netmask: %q", value)
		}
	}
	return nil
}

func validateSecret(value string, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must be a non-empty string", fieldName)
	}
	return nil
}

func validateQoSPriority(priority int) error {
	if priority < 1 || priority > 4 {
		return fmt.Errorf("priority must be in range 1-4: %d", priority)
	}
	return nil
}

func validateBandwidthRate(rate int, fieldName string) error {
	if _, ok := bandwidthRateKbps[rate]; !ok {
		allowed := make([]int, 0, len(bandwidthRateKbps))
		for v := range bandwidthRateKbps {
			allowed = append(allowed, v)
		}
		sort.Ints(allowed)
		parts := make([]string, 0, len(allowed))
		for _, v := range allowed {
			parts = append(parts, strconv.Itoa(v))
		}
		return fmt.Errorf("%s must be one of supported rates (%s); got %d", fieldName, strings.Join(parts, ", "), rate)
	}
	return nil
}

func validateStormRateIndex(rate int) error {
	if _, ok := StormRateKbps[rate]; !ok {
		keys := make([]int, 0, len(StormRateKbps))
		for k := range StormRateKbps {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, strconv.Itoa(k))
		}
		return fmt.Errorf("rate_index must be one of %s", strings.Join(parts, ", "))
	}
	return nil
}

func ptrSpeed(speed PortSpeed) *PortSpeed {
	s := speed
	return &s
}

func getListValue(v map[string]any, key string) []any {
	if raw, ok := v[key]; ok {
		return asSlice(raw)
	}
	return nil
}

func toIntSlice(raw []any) []int {
	out := make([]int, len(raw))
	for i := range raw {
		out[i] = asInt(raw[i])
	}
	return out
}

func toStringSlice(raw []any) []string {
	out := make([]string, len(raw))
	for i := range raw {
		out[i] = asString(raw[i])
	}
	return out
}

func oneBasedIndex(raw []any, idx int) int {
	if idx >= 0 && idx < len(raw) {
		return asInt(raw[idx])
	}
	return 0
}

func restoreMultipartBody(configData []byte) (io.Reader, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("configfile", "config.bin")
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(configData); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return &buf, w.FormDataContentType(), nil
}
