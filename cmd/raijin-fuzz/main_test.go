package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-fuzz v"+version) {
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
