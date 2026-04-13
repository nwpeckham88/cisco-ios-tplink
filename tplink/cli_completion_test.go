package tplink

import (
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestResolveKeyword(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		options   []string
		want      string
		wantError string
	}{
		{
			name:    "exact match",
			token:   "show",
			options: []string{"show", "switchport", "speed"},
			want:    "show",
		},
		{
			name:    "shortest unique prefix",
			token:   "sho",
			options: []string{"show", "switchport", "speed"},
			want:    "show",
		},
		{
			name:      "ambiguous prefix",
			token:     "s",
			options:   []string{"show", "switchport", "speed"},
			wantError: "ambiguous",
		},
		{
			name:      "unknown token",
			token:     "xyz",
			options:   []string{"show", "switchport", "speed"},
			wantError: "unknown",
		},
		{
			name:    "underscore matches hyphen",
			token:   "spanning_tree",
			options: []string{"spanning-tree", "show"},
			want:    "spanning-tree",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveKeyword(tt.token, tt.options)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.wantError) {
					t.Fatalf("expected error containing %q, got %v", tt.wantError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestCompletionCandidates(t *testing.T) {
	c := &CLI{}

	if got := c.completionCandidates(ModeExec, false, nil, "sh"); !reflect.DeepEqual(got, []string{"show"}) {
		t.Fatalf("exec top-level completion got=%v", got)
	}

	if got := c.completionCandidates(ModeExec, false, []string{"show"}, "v"); !reflect.DeepEqual(got, []string{"version", "vlan", "vlan-health"}) {
		t.Fatalf("show completion got=%v", got)
	}

	if got := c.completionCandidates(ModeExec, false, []string{"show", "interfaces"}, ""); !reflect.DeepEqual(got, []string{"brief", "counters", "port"}) {
		t.Fatalf("show interfaces completion got=%v", got)
	}

	if got := c.completionCandidates(ModeConfig, true, nil, "sp"); !reflect.DeepEqual(got, []string{"spanning-tree"}) {
		t.Fatalf("no-form completion got=%v", got)
	}
}

func TestExecLineAcceptsAbbreviations(t *testing.T) {
	c := &CLI{hostname: "switch", mode: ModeExec}

	quit, err := c.execLine("conf t")
	if err != nil || quit {
		t.Fatalf("conf t failed: quit=%v err=%v", quit, err)
	}
	if c.mode != ModeConfig {
		t.Fatalf("mode=%s want=%s", c.mode, ModeConfig)
	}

	quit, err = c.execLine("int gi1-2")
	if err != nil || quit {
		t.Fatalf("int gi1-2 failed: quit=%v err=%v", quit, err)
	}
	if c.mode != ModeConfigIF {
		t.Fatalf("mode=%s want=%s", c.mode, ModeConfigIF)
	}

	_, err = c.execLine("s")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "ambiguous") {
		t.Fatalf("expected ambiguous error, got %v", err)
	}
}

func TestShowAmbiguousSubcommand(t *testing.T) {
	c := &CLI{}
	if err := c.cmdShow("v"); err == nil || !strings.Contains(strings.ToLower(err.Error()), "ambiguous") {
		t.Fatalf("expected ambiguous show subcommand error, got %v", err)
	}
}

func TestHandleQuestionSupportsNoAndDoContexts(t *testing.T) {
	c := &CLI{mode: ModeConfig}

	out := captureStdout(t, func() {
		handled, err := c.handleQuestion("no ?")
		if !handled || err != nil {
			t.Fatalf("expected handled nil error, got handled=%v err=%v", handled, err)
		}
	})
	if !strings.Contains(out, "spanning-tree") {
		t.Fatalf("expected no-form completions, got: %q", out)
	}

	out = captureStdout(t, func() {
		handled, err := c.handleQuestion("do ?")
		if !handled || err != nil {
			t.Fatalf("expected handled nil error, got handled=%v err=%v", handled, err)
		}
	})
	if !strings.Contains(out, "show") {
		t.Fatalf("expected exec-mode completions, got: %q", out)
	}
}

func TestHandleQuestionRejectsMidLineQuestionMark(t *testing.T) {
	c := &CLI{mode: ModeExec}
	handled, err := c.handleQuestion("sh ? ver")
	if !handled {
		t.Fatal("expected handled=true")
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "place ? at the end") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = original

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(out)
}
