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

	if got := c.completionCandidates(ModeExec, false, []string{"configure", "terminal"}, ""); got != nil {
		t.Fatalf("expected no completion candidates for completed non-show subcommand, got=%v", got)
	}
}

func TestCompletionContextForLine(t *testing.T) {
	c := &CLI{mode: ModeConfig}

	tests := []struct {
		name       string
		line       string
		wantMode   CLIMode
		wantNoForm bool
		wantTokens []string
		wantPart   string
	}{
		{
			name:       "plain partial",
			line:       "show v",
			wantMode:   ModeConfig,
			wantNoForm: false,
			wantTokens: []string{"show"},
			wantPart:   "v",
		},
		{
			name:       "trailing space means next token",
			line:       "show ",
			wantMode:   ModeConfig,
			wantNoForm: false,
			wantTokens: []string{"show"},
			wantPart:   "",
		},
		{
			name:       "do prefix switches to exec mode",
			line:       "do sh",
			wantMode:   ModeExec,
			wantNoForm: false,
			wantTokens: []string{},
			wantPart:   "sh",
		},
		{
			name:       "no prefix enables no-form",
			line:       "no sp",
			wantMode:   ModeConfig,
			wantNoForm: true,
			wantTokens: []string{},
			wantPart:   "sp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := c.completionContextForLine(tt.line)
			if ctx.mode != tt.wantMode {
				t.Fatalf("mode=%s want=%s", ctx.mode, tt.wantMode)
			}
			if ctx.noForm != tt.wantNoForm {
				t.Fatalf("noForm=%v want=%v", ctx.noForm, tt.wantNoForm)
			}
			if !reflect.DeepEqual(ctx.tokens, tt.wantTokens) {
				t.Fatalf("tokens=%v want=%v", ctx.tokens, tt.wantTokens)
			}
			if ctx.partial != tt.wantPart {
				t.Fatalf("partial=%q want=%q", ctx.partial, tt.wantPart)
			}
		})
	}
}

func TestApplyTabCompletion(t *testing.T) {
	c := &CLI{mode: ModeExec}

	tests := []struct {
		name        string
		line        string
		mode        CLIMode
		wantLine    string
		wantChanged bool
	}{
		{
			name:        "unique top-level completion",
			line:        "sh",
			mode:        ModeExec,
			wantLine:    "show ",
			wantChanged: true,
		},
		{
			name:        "unique nested completion",
			line:        "show interf",
			mode:        ModeExec,
			wantLine:    "show interfaces ",
			wantChanged: true,
		},
		{
			name:        "ambiguous with longest-common-prefix growth",
			line:        "show vl",
			mode:        ModeExec,
			wantLine:    "show vlan",
			wantChanged: true,
		},
		{
			name:        "ambiguous without growth stays unchanged",
			line:        "show v",
			mode:        ModeExec,
			wantLine:    "show v",
			wantChanged: false,
		},
		{
			name:        "no-form completion uses config no commands",
			line:        "no sp",
			mode:        ModeConfig,
			wantLine:    "no spanning-tree ",
			wantChanged: true,
		},
		{
			name:        "unknown token unchanged",
			line:        "zzz",
			mode:        ModeExec,
			wantLine:    "zzz",
			wantChanged: false,
		},
		{
			name:        "completed non-show subcommand is not duplicated",
			line:        "configure terminal ",
			mode:        ModeExec,
			wantLine:    "configure terminal ",
			wantChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c.mode = tt.mode
			got, changed := c.applyTabCompletion(tt.line)
			if got != tt.wantLine {
				t.Fatalf("line=%q want=%q", got, tt.wantLine)
			}
			if changed != tt.wantChanged {
				t.Fatalf("changed=%v want=%v", changed, tt.wantChanged)
			}
		})
	}
}

func TestProcessInteractiveByteEscPrefixThenPrintable(t *testing.T) {
	c := &CLI{mode: ModeExec}
	state := interactiveInputState{}

	res := c.processInteractiveByte(state, 27)
	if !res.state.escPrefix || res.state.inEscapeSequence {
		t.Fatalf("unexpected esc state: %+v", res.state)
	}
	if res.echo != "" || res.shouldExecute || res.shouldQuestion || res.shouldQuit || res.shouldRedraw {
		t.Fatalf("unexpected side effects after esc: %+v", res)
	}

	res = c.processInteractiveByte(res.state, 'x')
	if res.state.escPrefix || res.state.inEscapeSequence {
		t.Fatalf("expected esc state cleared: %+v", res.state)
	}
	if res.state.line != "x" {
		t.Fatalf("line=%q want=%q", res.state.line, "x")
	}
	if res.echo != "x" {
		t.Fatalf("echo=%q want=%q", res.echo, "x")
	}
}

func TestProcessInteractiveByteConsumesEscapeSequence(t *testing.T) {
	c := &CLI{mode: ModeExec}
	state := interactiveInputState{}

	res := c.processInteractiveByte(state, 27)
	res = c.processInteractiveByte(res.state, '[')
	if !res.state.inEscapeSequence {
		t.Fatalf("expected to enter escape sequence: %+v", res.state)
	}

	res = c.processInteractiveByte(res.state, 'A')
	if res.state.inEscapeSequence {
		t.Fatalf("expected escape sequence to finish: %+v", res.state)
	}
	if res.state.line != "" || res.echo != "" {
		t.Fatalf("expected no line update while consuming escape sequence: %+v", res)
	}

	res = c.processInteractiveByte(res.state, 'z')
	if res.state.line != "z" || res.echo != "z" {
		t.Fatalf("expected printable char after escape sequence, got %+v", res)
	}
}

func TestProcessInteractiveByteQuestionAndTab(t *testing.T) {
	c := &CLI{mode: ModeExec}
	state := interactiveInputState{line: "sh"}

	res := c.processInteractiveByte(state, '?')
	if !res.shouldQuestion || !res.shouldRedraw {
		t.Fatalf("expected question + redraw, got %+v", res)
	}
	if res.state.line != "sh" {
		t.Fatalf("line=%q want=%q", res.state.line, "sh")
	}

	res = c.processInteractiveByte(state, '\t')
	if !res.shouldRedraw {
		t.Fatalf("expected redraw after tab completion, got %+v", res)
	}
	if res.state.line != "show " {
		t.Fatalf("line=%q want=%q", res.state.line, "show ")
	}
}

func TestProcessInteractiveByteControlAndEnter(t *testing.T) {
	c := &CLI{mode: ModeExec}

	res := c.processInteractiveByte(interactiveInputState{line: "abc"}, 3)
	if res.state.line != "" || res.echo != "^C\r\n" || !res.shouldRedraw {
		t.Fatalf("unexpected ctrl+c result: %+v", res)
	}

	res = c.processInteractiveByte(interactiveInputState{}, 4)
	if !res.shouldQuit || res.echo != "\r\n" {
		t.Fatalf("unexpected ctrl+d empty-line result: %+v", res)
	}

	res = c.processInteractiveByte(interactiveInputState{line: "x"}, 4)
	if res.shouldQuit {
		t.Fatalf("ctrl+d should not quit with buffered input: %+v", res)
	}
	if res.state.line != "x" {
		t.Fatalf("line=%q want=%q", res.state.line, "x")
	}

	res = c.processInteractiveByte(interactiveInputState{line: "show version"}, '\r')
	if !res.shouldExecute || res.executeLine != "show version" {
		t.Fatalf("expected execute line result, got %+v", res)
	}
	if res.state.line != "" || res.echo != "\r\n" {
		t.Fatalf("unexpected enter side effects: %+v", res)
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

func TestCmdHelpIsModeAwareAndCurrent(t *testing.T) {
	c := &CLI{mode: ModeConfigIF}
	out := captureStdout(t, func() {
		c.cmdHelp()
	})
	if !strings.Contains(out, "switchport access vlan <id>") {
		t.Fatalf("missing switchport help entry: %q", out)
	}
	if !strings.Contains(out, "qos port-priority <1-4>") {
		t.Fatalf("missing qos help entry: %q", out)
	}
	if strings.Contains(out, "conf t") {
		t.Fatalf("conf t should not be suggested in config-if mode: %q", out)
	}
	if !strings.Contains(out, "do <exec-command>") {
		t.Fatalf("missing do tip for config mode: %q", out)
	}
	if !strings.Contains(out, "show <subcommand>") {
		t.Fatalf("missing direct show help entry: %q", out)
	}
}

func TestCmdConfigureAcceptsTerminalAbbreviation(t *testing.T) {
	c := &CLI{mode: ModeExec}
	if err := c.cmdConfigure("t"); err != nil {
		t.Fatalf("cmdConfigure(t) failed: %v", err)
	}
	if c.mode != ModeConfig {
		t.Fatalf("mode=%s want=%s", c.mode, ModeConfig)
	}
}

func TestCmdConfigureRejectedOutsideExec(t *testing.T) {
	c := &CLI{mode: ModeConfigIF}
	if err := c.cmdConfigure("t"); err == nil {
		t.Fatal("expected configure terminal to be rejected outside exec mode")
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
