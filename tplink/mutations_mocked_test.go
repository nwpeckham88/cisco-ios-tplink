package tplink

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type requestCapture struct {
	path   string
	method string
	query  url.Values
	body   url.Values
}

func newMutationTestClient(t *testing.T, cap *requestCapture) *Client {
	t.Helper()

	h := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logon.cgi":
			http.SetCookie(w, &http.Cookie{Name: "H_P_SSID", Value: "ok"})
			fmt.Fprint(w, "<script>errType=0</script>")
		case "/PortSettingRpm.htm":
			fmt.Fprint(w, `<script>var max_port_num = 8;</script>`)
		default:
			cap.path = r.URL.Path
			cap.method = r.Method
			cap.query = r.URL.Query()
			cap.body = url.Values{}
			if r.Body != nil {
				raw, _ := io.ReadAll(r.Body)
				if parsed, err := url.ParseQuery(string(raw)); err == nil {
					cap.body = parsed
				}
			}
			fmt.Fprint(w, "ok")
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(h))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	client, err := NewClient(host, WithUsername("admin"), WithPassword("test"), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return client
}

func TestSetPortVLANEnabledBuildsExpectedQuery(t *testing.T) {
	cap := &requestCapture{}
	client := newMutationTestClient(t, cap)

	if err := client.SetPortVLANEnabled(true); err != nil {
		t.Fatalf("SetPortVLANEnabled(true): %v", err)
	}
	if cap.path != "/pvlanSet.cgi" {
		t.Fatalf("path=%q", cap.path)
	}
	if cap.query.Get("pvlan_en") != "1" || cap.query.Get("pvlan_mode") != "Apply" {
		t.Fatalf("unexpected query: %v", cap.query)
	}

	if err := client.SetPortVLANEnabled(false); err != nil {
		t.Fatalf("SetPortVLANEnabled(false): %v", err)
	}
	if cap.query.Get("pvlan_en") != "0" || cap.query.Get("pvlan_mode") != "Apply" {
		t.Fatalf("unexpected query: %v", cap.query)
	}
}

func TestAddAndDeleteDot1QVLANBuildExpectedQueries(t *testing.T) {
	cap := &requestCapture{}
	client := newMutationTestClient(t, cap)

	if err := client.AddDot1QVLAN(100, "users", []int{2, 1}, []int{3}); err != nil {
		t.Fatalf("AddDot1QVLAN: %v", err)
	}
	if cap.path != "/qvlanSet.cgi" {
		t.Fatalf("path=%q", cap.path)
	}
	if cap.query.Get("vid") != "100" || cap.query.Get("vname") != "users" || cap.query.Get("qvlan_add") != "Add/Modify" {
		t.Fatalf("unexpected base query: %v", cap.query)
	}
	if cap.query.Get("selType_1") != "1" || cap.query.Get("selType_2") != "1" || cap.query.Get("selType_3") != "0" {
		t.Fatalf("unexpected membership query: %v", cap.query)
	}
	for i := 4; i <= 8; i++ {
		key := fmt.Sprintf("selType_%d", i)
		if cap.query.Get(key) != "2" {
			t.Fatalf("%s=%q", key, cap.query.Get(key))
		}
	}

	if err := client.DeleteDot1QVLAN(100); err != nil {
		t.Fatalf("DeleteDot1QVLAN: %v", err)
	}
	if cap.path != "/qvlanSet.cgi" {
		t.Fatalf("path=%q", cap.path)
	}
	if cap.query.Get("selVlans") != "100" || cap.query.Get("qvlan_del") != "Delete" {
		t.Fatalf("unexpected delete query: %v", cap.query)
	}
}

func TestAddDot1QVLANRejectsOverlap(t *testing.T) {
	cap := &requestCapture{}
	client := newMutationTestClient(t, cap)

	err := client.AddDot1QVLAN(100, "bad", []int{2}, []int{2})
	if err == nil {
		t.Fatal("expected overlap error")
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChangePasswordBuildsExpectedQuery(t *testing.T) {
	cap := &requestCapture{}
	client := newMutationTestClient(t, cap)

	if err := client.ChangePassword("old123", "new123", ""); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if cap.path != "/usr_account_set.cgi" {
		t.Fatalf("path=%q", cap.path)
	}
	if cap.query.Get("txt_username") != "admin" {
		t.Fatalf("txt_username=%q", cap.query.Get("txt_username"))
	}
	if cap.query.Get("txt_oldpwd") != "old123" || cap.query.Get("txt_userpwd") != "new123" || cap.query.Get("txt_confirmpwd") != "new123" {
		t.Fatalf("unexpected password query: %v", cap.query)
	}
}
