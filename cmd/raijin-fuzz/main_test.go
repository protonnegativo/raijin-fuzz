package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-fuzz"
)

// testedFfuf is the ffuf version in engines.json, so fake engines answer with it and a bump does not
// break the tests.
func testedFfuf(t *testing.T) (string, [3]int) {
	t.Helper()
	tested, err := engines.Tested()
	if err != nil {
		t.Fatal(err)
	}
	v := tested["ffuf"].Version
	p, ok := engines.Parse(v)
	if !ok {
		t.Fatalf("tested ffuf %q does not parse", v)
	}
	return v, p
}

func TestBuildVersion(t *testing.T) {
	cases := []struct {
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{nil, false, "dev"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, true, "v0.1.3"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, "dev"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123"}, {Key: "vcs.modified", Value: "true"}}}, true, "dev-0123456789ab+dirty"},
		{&debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc"}, {Key: "vcs.modified", Value: "false"}}}, true, "dev-abc"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261025032211-072939d7ec47+dirty"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "072939d7ec47aaaa"}, {Key: "vcs.modified", Value: "true"}}}, true, "dev-072939d7ec47+dirty"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "072939d7ec47aaaa"}}}, true, "v0.1.3"},
	}
	for _, c := range cases {
		if got := buildVersion(c.info, c.ok); got != c.want {
			t.Errorf("buildVersion(%+v) = %q, want %q", c.info, got, c.want)
		}
	}
}

func TestReleaseVersionWins(t *testing.T) {
	releaseVersion = "v9.9.9"
	defer func() { releaseVersion = "" }()
	info := &debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}
	if got := buildVersion(info, true); got != "v9.9.9" {
		t.Errorf("buildVersion = %q, want the release version", got)
	}
}

func TestVersionLine(t *testing.T) {
	tested, _ := testedFfuf(t)
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	want := "raijin-fuzz " + version + " (tested with ffuf " + tested + ")\n"
	if out.String() != want {
		t.Errorf("--version = %q, want %q", out.String(), want)
	}
}

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-fuzz v"+strings.TrimPrefix(version, "v")) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
}

func TestMissingEngineExitsTwoWithHint(t *testing.T) {
	var out, errb bytes.Buffer
	w := filepath.Join(t.TempDir(), "w.txt")
	os.WriteFile(w, []byte("a\n"), 0o600)
	code := run([]string{"--scope", scopeFile(t), "-u", "https://a.example.com/FUZZ", "-w", w, "--ffuf", "/nonexistent/ffuf"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var v struct {
		Errors []struct{ Kind, Hint string }
		Raw    string
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || len(v.Errors) != 1 || v.Errors[0].Kind != "missing_engine" || !strings.Contains(v.Errors[0].Hint, "--ffuf") || v.Raw != "" {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--input", "../../testdata/sample.json"}, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "https://out.of-scope.net/FUZZ", "-w", "w.txt"}, &out, &errb); code != 1 {
		t.Errorf("target out of scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "https://a.example.com/FUZZ"}, &out, &errb); code != 1 {
		t.Errorf("no wordlist: exit %d, want 1", code)
	}
}

func TestSummaryAndURL(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	s := out.String()
	if !strings.Contains(s, `"summary":"19 results, 9 shapes: 7 findings (1 high, 2 medium, 3 low, 1 info), 2 groups (11 noise results)","url":"https://app.example.com/FUZZ","findings"`) {
		t.Errorf("summary, url, and no default matcher: %s", s)
	}
	if !strings.Contains(s, `"omitted":{"duplicates":1,"out_of_scope":1}`) {
		t.Errorf("omitted: %s", s)
	}
}

func TestMatchersAreWrittenWhenNotDefault(t *testing.T) {
	b, _ := os.ReadFile("../../testdata/sample.json")
	b = bytes.Replace(b, []byte(`"Filters": {}`), []byte(`"Filters": {"size": {"value": "42"}}`), 1)
	p := filepath.Join(t.TempDir(), "f.json")
	os.WriteFile(p, b, 0o600)
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", p}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), `"match":"status 200-299,301,302,307,401,403,405,500","filter":"size 42"`) {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestTableFormat(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--format", "table", "--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{
		"HIGH     file 200 size=68 words=1 lines=4 text/plain: .env",
		"MEDIUM   401 size=25 words=2 lines=1 application/json: api",
		"LOW      admin,dir 301 size=0 words=1 lines=1 none -> /FUZZ/: admin backup",
		"group    200 size=140+input words=11 lines=6 (6 inputs)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("table should contain %q:\n%s", want, out.String())
		}
	}
}

func TestBudgetIsCountedAndPointsToRaw(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--max-bytes", "900", "--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if out.Len() > 901 {
		t.Errorf("output is %d bytes", out.Len())
	}
	var v struct {
		Omitted map[string]int
		Next    []string
		Budget  struct{ Truncated bool }
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || !v.Budget.Truncated || v.Omitted["groups"] == 0 || len(v.Next) != 1 || !strings.Contains(v.Next[0], "sample.json") {
		t.Errorf("stdout = %s", out.String())
	}
}

// With only --scope, every host the scope names is fuzzed in one ffuf run, with the default wordlist,
// and wildcards get a next step.
func TestScopeAloneFuzzesWhatTheScopeNames(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("example.com\n*.example.com\n10.0.0.0/30\n!10.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gotHosts, gotArgs := filepath.Join(dir, "hosts.txt"), filepath.Join(dir, "args.txt")
	fake := filepath.Join(dir, "ffuf")
	script := "#!/bin/sh\necho \"$@\" > " + gotArgs + "\nwhile [ $# -gt 0 ]; do\n" +
		"  case \"$2\" in *:HOST) cp \"${2%:HOST}\" " + gotHosts + ";; esac\n" +
		"  [ \"$1\" = -o ] && echo '{\"results\":[],\"config\":{\"url\":\"https://HOST/FUZZ\"}}' > \"$2\"\n  shift\ndone\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopePath, "--ffuf", fake, "--raw", filepath.Join(dir, "raw.json")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	b, err := os.ReadFile(gotHosts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(strings.Fields(string(b)), ",") != "example.com,10.0.0.0,10.0.0.2,10.0.0.3" {
		t.Errorf("ffuf got hosts %q", b)
	}
	a, _ := os.ReadFile(gotArgs)
	if !strings.HasPrefix(string(a), "-u https://HOST/FUZZ -w ") || !strings.Contains(string(a), ":FUZZ ") {
		t.Errorf("ffuf args = %q", a)
	}
	var res struct{ Next []string }
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Next) != 1 || !strings.Contains(res.Next[0], "raijin-subs --scope "+scopePath+" -d example.com") {
		t.Errorf("next = %v", res.Next)
	}
}

func TestEngineVersionWarnsAndDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("h.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tested, p := testedFfuf(t)
	older := fmt.Sprintf("%d.%d.%d", p[0], p[1], p[2]-1)
	if p[2] == 0 {
		older = fmt.Sprintf("%d.%d.%d", p[0]-1, 9, 9)
	}
	cases := map[string]bool{
		older:                                    true,
		fmt.Sprintf("%d.0.0", p[0]+1):            true,
		tested:                                   false,
		fmt.Sprintf("%d.%d.1-dev", p[0], p[1]+1): false,
		"dev":                                    false,
	}
	for version, warn := range cases {
		fake := filepath.Join(dir, "ffuf")
		script := "#!/bin/sh\n[ \"$1\" = -V ] && { echo 'ffuf version: " + version + "'; exit 0; }\nwhile [ $# -gt 0 ]; do\n" +
			"  [ \"$1\" = -o ] && echo '{\"results\":[],\"config\":{\"url\":\"http://h.test/FUZZ\"}}' > \"$2\"\n  shift\ndone\n"
		if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		code := run([]string{"--scope", scopePath, "--ffuf", fake, "-u", "http://h.test/FUZZ", "-w", fake, "--raw", filepath.Join(dir, "raw.json")}, &out, &errb)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", version, code, errb.String())
		}
		got := strings.Contains(out.String(), `"kind":"engine_version"`)
		if got != warn || (warn && !strings.Contains(out.String(), "go install github.com/ffuf/ffuf/v2@v"+tested)) {
			t.Errorf("%s: warned %v, want %v: %s", version, got, warn, out.String())
		}
	}
}

func TestEngineFormatIsCounted(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../internal/ffuf/testdata/renamed_status.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var res struct {
		Omitted map[string]int
		Errors  []struct{ Kind, Hint string }
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Omitted["unparsed"] != 21 || len(res.Errors) != 1 || res.Errors[0].Kind != "engine_format" ||
		!strings.HasPrefix(res.Errors[0].Hint, "21 of 21 ffuf results had no url or status") {
		t.Errorf("omitted %v, errors %v", res.Omitted, res.Errors)
	}
}

func TestSchemaVersionIsTheFirstField(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.json"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), `{"schema_version":1,"tool":"raijin-fuzz",`) {
		t.Errorf("output must start with schema_version: %.80s", out.String())
	}
}

func TestInvalidScopeIsStructuredAndRunsNothing(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ffuf-ran")
	fake := filepath.Join(dir, "ffuf")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ file, reason string }{
		"port in rule":        {"example.com:443\n", "port in rule"},
		"CIDR with host bits": {"10.0.0.7/24\n", "CIDR has host bits set"},
		"two bad lines":       {"example.com:443\n*example.com\n", "line 2"},
	}
	for name, c := range cases {
		p := filepath.Join(dir, "scope.txt")
		if err := os.WriteFile(p, []byte(c.file), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"--scope", p, "-u", "https://example.com/FUZZ", "-w", "w.txt", "--ffuf", fake},
			{"--scope", p, "--ffuf", fake},
		} {
			var out, errb bytes.Buffer
			if code := run(args, &out, &errb); code != 2 {
				t.Errorf("%s: exit %d, want 2", name, code)
			}
			if !strings.HasPrefix(out.String(), `{"schema_version":1,`) {
				t.Errorf("%s: stdout must start with the schema_version: %.60s", name, out.String())
			}
			// --format table must not turn the structured error into text
			var tab, tabErr bytes.Buffer
			if code := run(append([]string{"--format", "table"}, args...), &tab, &tabErr); code != 2 || !strings.HasPrefix(tab.String(), `{"schema_version":1,`) {
				t.Errorf("%s: --format table: exit %d, stdout %.60s", name, code, tab.String())
			}
			var v struct {
				SchemaVersion int `json:"schema_version"`
				Summary       string
				Errors        []struct{ Kind, Hint string }
			}
			if err := json.Unmarshal(out.Bytes(), &v); err != nil {
				t.Fatalf("%s: stdout is not JSON: %v: %q", name, err, out.String())
			}
			if v.SchemaVersion != 1 || len(v.Errors) == 0 || v.Errors[0].Kind != "scope" || !strings.Contains(out.String(), c.reason) {
				t.Errorf("%s: want kind scope mentioning %q, got %s", name, c.reason, out.String())
			}
			if !strings.Contains(v.Summary, "nothing fuzzed") {
				t.Errorf("%s: summary %q", name, v.Summary)
			}
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("ffuf ran with an invalid scope")
	}
	// a scope file that cannot be read is also a structured error
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", filepath.Join(dir, "missing.txt")}, &out, &errb); code != 2 || !strings.Contains(out.String(), `"kind":"scope"`) {
		t.Errorf("missing scope file: exit %d: %s", code, out.String())
	}
}

func TestStateMarksNewOnlyOnce(t *testing.T) {
	st := filepath.Join(t.TempDir(), "state.json")
	args := []string{"--scope", scopeFile(t), "--input", "../../testdata/sample.json", "--state", st}
	var first, second, errb bytes.Buffer
	if code := run(args, &first, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(first.String(), `"new":true`) {
		t.Errorf("first run should mark findings as new: %s", first.String())
	}
	if code := run(args, &second, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if strings.Contains(second.String(), `"new":true`) {
		t.Errorf("second run should not mark anything as new: %s", second.String())
	}
}

func TestScopeWithoutHostsIsStructuredExitTwo(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--scope", p}, {"--format", "table", "--scope", p}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		s := out.String()
		if !strings.HasPrefix(s, `{"schema_version":1,`) || !strings.Contains(s, `"kind":"no_targets"`) || !strings.Contains(s, "raijin-subs") {
			t.Errorf("%v: stdout %.200s", args, s)
		}
	}
}
