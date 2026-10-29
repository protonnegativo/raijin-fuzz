package reduce

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-core/scope"
	"github.com/protonnegativo/raijin-fuzz/internal/ffuf"
	"github.com/protonnegativo/raijin-fuzz/internal/schema"
)

const tmpl = "http://h.test/FUZZ"

func load(t *testing.T) *ffuf.Run {
	t.Helper()
	f, err := os.Open("../../testdata/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	run, err := ffuf.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

// res is a result for input w on tmpl, with an HTML body.
func res(pos int, w string, status, length, words, lines int) ffuf.Result {
	return ffuf.Result{Input: map[string]string{"FUZZ": w}, Position: pos, Status: status, Length: length, Words: words,
		Lines: lines, ContentType: "text/html", Duration: 3e6, URL: "http://h.test/" + w}
}

func runOf(results ...ffuf.Result) *ffuf.Run {
	return &ffuf.Run{URL: tmpl, Results: results}
}

// listed maps each written input to the shapes that list it.
func listed(out Output) map[string][]schema.Shape {
	m := map[string][]schema.Shape{}
	for _, f := range out.Findings {
		for _, i := range f.Inputs {
			m[i] = append(m[i], f.Shape)
		}
	}
	for _, g := range out.Groups {
		for _, i := range g.Inputs {
			m[i] = append(m[i], g.Shape)
		}
	}
	return m
}

func TestReduce(t *testing.T) {
	run := load(t)
	if len(run.Results) != 21 || run.URL != "https://app.example.com/FUZZ" || run.Match != "status "+ffuf.DefaultMatch || run.Filter != "" {
		t.Fatalf("parsed %d results, url %q, match %q, filter %q", len(run.Results), run.URL, run.Match, run.Filter)
	}
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	out := Reduce(run, opt)

	if out.Omitted["duplicates"] != 1 || out.Omitted["out_of_scope"] != 1 {
		t.Errorf("omitted = %v", out.Omitted)
	}
	if out.Stats.Results != 19 || out.Stats.Noise != 11 || out.Stats.Shapes != 9 {
		t.Errorf("stats = %+v", out.Stats)
	}
	var got []string
	for _, f := range out.Findings {
		got = append(got, fmt.Sprint(f.Severity, " ", f.Status, " ", strings.Join(f.Tags, ","), " ", strings.Join(f.Inputs, ",")))
	}
	want := []string{
		"high 200 file .env",
		"medium 403 file .htpasswd",
		"medium 401  api",
		"low 301 admin,dir admin,backup",
		"low 200 slow report",
		"low 302 admin dashboard",
		"info 200  robots.txt",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if d := out.Findings[3]; d.Redirect != "/FUZZ/" || d.Type != "none" {
		t.Errorf("a directory redirect is written with the keyword: %+v", d)
	}
	if s := out.Findings[4]; s.MS != 1500 {
		t.Errorf("a slow finding keeps its time: %+v", s)
	}
	if g := out.Groups[0]; !g.Reflected || g.Length != 140 || g.N != 6 {
		t.Errorf("a soft-404 that echoes the input is one group: %+v", g)
	}
	if g := out.Groups[1]; g.Reflected || g.Status != 403 || g.Length != 104 || strings.Join(g.Inputs, ",") != "index.php,login.php,info.php,test.php,shell.php" {
		t.Errorf("a constant block page is one group, in wordlist order: %+v", g)
	}
}

// Lossless rule: every result ffuf reported is listed exactly once, with its own status, length, words,
// lines, type and redirect.
func TestEveryResultIsListedWithItsShape(t *testing.T) {
	var results []ffuf.Result
	for i := 0; i < 40; i++ {
		results = append(results, res(i, fmt.Sprintf("w%d", i), 200, 500, 20, 9))
	}
	results = append(results, res(50, "real", 200, 812, 40, 12), res(51, "secret", 403, 30, 2, 1))
	j := res(52, "data", 200, 77, 3, 1)
	j.ContentType = "application/json; charset=utf-8"
	results = append(results, j)
	out := Reduce(runOf(results...), Defaults())
	m := listed(out)
	if len(m) != len(results) {
		t.Fatalf("%d inputs listed, want %d", len(m), len(results))
	}
	for _, r := range results {
		shapes := m[r.Input["FUZZ"]]
		if len(shapes) != 1 {
			t.Fatalf("%s listed %d times", r.Input["FUZZ"], len(shapes))
		}
		s := shapes[0]
		if s.Status != r.Status || s.Length != r.Length || s.Words != r.Words || s.Lines != r.Lines {
			t.Errorf("%s: shape %+v, want %+v", r.Input["FUZZ"], s, r)
		}
	}
	if m["data"][0].Type != "application/json" {
		t.Errorf("type without parameters: %+v", m["data"])
	}
}

// Lossless rule: a reflected group keeps every length: each is the group's length plus the input's.
func TestReflectedLengthIsExact(t *testing.T) {
	var results []ffuf.Result
	words := []string{"a", "bb", "ccc", "dddd", "eeeee", "ff"}
	for i, w := range words {
		results = append(results, res(i, w, 200, 100+len(w), 9, 4))
	}
	// same words and lines but a length that is not 100 plus the input: not part of the group
	results = append(results, res(9, "zz", 200, 150, 9, 4))
	out := Reduce(runOf(results...), Defaults())
	if len(out.Groups) != 1 || !out.Groups[0].Reflected || out.Groups[0].Length != 100 || out.Groups[0].N != 6 {
		t.Fatalf("groups = %+v", out.Groups)
	}
	if len(out.Findings) != 1 || out.Findings[0].Length != 150 || out.Findings[0].Inputs[0] != "zz" {
		t.Errorf("findings = %+v", out.Findings)
	}
	// the same length for every input is an exact shape, not a reflected one
	out = Reduce(runOf(res(1, "aa", 200, 50, 1, 1), res(2, "bb", 200, 50, 1, 1), res(3, "cc", 200, 50, 1, 1), res(4, "dd", 200, 50, 1, 1), res(5, "ee", 200, 50, 1, 1)), Defaults())
	if len(out.Groups) != 1 || out.Groups[0].Reflected {
		t.Errorf("groups = %+v", out.Groups)
	}
}

// Lossless rule: only exact repeats of an input and its response collapse, and they are counted.
func TestOnlyExactDuplicatesCollapse(t *testing.T) {
	a, b := res(1, "x", 200, 10, 1, 1), res(2, "x", 200, 10, 1, 1)
	c := res(3, "x", 500, 10, 1, 1) // the same input answered differently: kept
	out := Reduce(runOf(a, b, c), Defaults())
	if out.Omitted["duplicates"] != 1 || out.Stats.Results != 2 || len(listed(out)["x"]) != 2 {
		t.Errorf("omitted = %v, stats = %+v, listed = %v", out.Omitted, out.Stats, listed(out))
	}
}

// Lossless rule: a redirect is written with the input as its keyword only when putting the input back
// gives the Location ffuf saw.
func TestRedirectTemplate(t *testing.T) {
	r := res(1, "admin", 301, 0, 1, 1)
	for loc, want := range map[string]string{
		"/admin/":                     "/FUZZ/",
		"http://h.test/admin/":        "http://h.test/FUZZ/",
		"/login?next=/admin":          "/login?next=/FUZZ",
		"/login":                      "/login",
		"https://other.test/FUZZ/x":   "https://other.test/FUZZ/x", // already holds the keyword
		"/administrator?from=/admin2": "/administrator?from=/admin2",
	} {
		r.Redirect = loc
		got := RedirectTemplate(r, tmpl)
		if got != want {
			t.Errorf("%s: %s, want %s", loc, got, want)
		}
		if ffuf.Substitute(got, r.Input) != loc && !strings.Contains(loc, "FUZZ") {
			t.Errorf("%s does not give the header back: %s", loc, got)
		}
	}
}

// Lossless rule: a result whose URL is not the fuzzed URL with its input (recursion) keeps its URL.
func TestOtherURLIsWritten(t *testing.T) {
	r := res(1, "x", 200, 10, 1, 1)
	r.URL = "http://h.test/admin/x"
	out := Reduce(runOf(r, res(2, "y", 200, 11, 1, 1)), Defaults())
	m := listed(out)
	if len(m["x @ http://h.test/admin/x"]) != 1 || len(m["y"]) != 1 {
		t.Errorf("listed = %v", m)
	}
}

func TestSeveralKeywords(t *testing.T) {
	r := ffuf.Result{Input: map[string]string{"FUZZ": "admin", "EXT": "bak"}, Status: 200, Length: 5, Words: 1, Lines: 1, URL: "http://h.test/admin.bak"}
	out := Reduce(&ffuf.Run{URL: "http://h.test/FUZZ.EXT", Results: []ffuf.Result{r}}, Defaults())
	f := out.Findings[0]
	if f.Inputs[0] != "EXT=bak FUZZ=admin" || f.Severity != "high" || strings.Join(f.Tags, ",") != "file,admin" {
		t.Errorf("got %+v", f)
	}
}

// A redirect that adds a slash is a directory and stays a finding however many there are, unless the
// server does it for more than half of the inputs.
func TestDirectoriesAreNotNoise(t *testing.T) {
	var results []ffuf.Result
	for i, w := range []string{"css", "js", "img", "media", "static", "fonts"} {
		r := res(i, w, 301, 0, 1, 1)
		r.Redirect = "/" + w + "/"
		results = append(results, r)
	}
	for i := 0; i < 10; i++ {
		results = append(results, res(10+i, fmt.Sprint("p", i), 200, 100+i, 5, 2))
	}
	out := Reduce(runOf(results...), Defaults())
	if len(out.Groups) != 0 || out.Findings[0].N != 6 || strings.Join(out.Findings[0].Tags, ",") != "dir" {
		t.Errorf("findings = %+v, groups = %+v", out.Findings, out.Groups)
	}
	out = Reduce(runOf(results[:6]...), Defaults())
	if len(out.Groups) != 1 {
		t.Errorf("a slash added to everything is noise: %+v", out.Groups)
	}
}

// A catch-all hides the name rules: a .env in the soft-404 group is noise, not a finding.
func TestNoiseWinsOverNames(t *testing.T) {
	var results []ffuf.Result
	for i, w := range []string{".env", "backup.sql", "admin", "a", "b"} {
		results = append(results, res(i, w, 200, 42, 3, 1))
	}
	out := Reduce(runOf(results...), Defaults())
	if len(out.Findings) != 0 || len(out.Groups) != 1 {
		t.Errorf("findings = %+v", out.Findings)
	}
	opt := Defaults()
	opt.Noise = 10
	out = Reduce(runOf(results...), opt)
	if len(out.Groups) != 0 || len(out.Findings) != 4 || out.Findings[0].Severity != "high" || out.Findings[3].N != 2 {
		t.Errorf("below --noise the same shape splits by name: %+v", out.Findings)
	}
}

func TestSlowIsAnOutlier(t *testing.T) {
	var results []ffuf.Result
	for i := 0; i < 8; i++ {
		results = append(results, res(i, fmt.Sprint("w", i), 200, 42, 3, 1))
	}
	results[3].Duration = 2e9
	out := Reduce(runOf(results...), Defaults())
	if len(out.Groups) != 1 || out.Groups[0].N != 7 || len(out.Findings) != 1 || out.Findings[0].Inputs[0] != "w3" || out.Findings[0].MS != 2000 {
		t.Errorf("findings = %+v, groups = %+v", out.Findings, out.Groups)
	}
}

func TestSeverityRules(t *testing.T) {
	cases := []struct {
		input  string
		status int
		sev    string
		tags   string
	}{
		{".git/HEAD", 200, "high", "file"},
		{"backup.zip", 200, "high", "file,admin"},
		{"phpinfo.php", 200, "high", "admin"},
		{"site.tar.gz", 200, "high", "file"},
		{".htpasswd", 403, "medium", "file"},
		{"api", 401, "medium", ""},
		{"admin", 302, "low", "admin"},
		{"crash", 500, "low", ""},
		{"about", 200, "info", ""},
		{"method", 405, "info", ""},
	}
	for _, c := range cases {
		out := Reduce(runOf(res(1, c.input, c.status, 10, 1, 1)), Defaults())
		f := out.Findings[0]
		if f.Severity != c.sev || strings.Join(f.Tags, ",") != c.tags {
			t.Errorf("%s %d: %s %v, want %s %s", c.input, c.status, f.Severity, f.Tags, c.sev, c.tags)
		}
	}
}

func TestOutOfScopeIsDropped(t *testing.T) {
	sc, _ := scope.Parse([]string{"h.test"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	other := res(2, "x", 200, 1, 1, 1)
	other.URL = "http://other.test/x"
	out := Reduce(runOf(res(1, "a", 200, 1, 1, 1), other), opt)
	if out.Omitted["out_of_scope"] != 1 || out.Stats.Results != 1 {
		t.Errorf("omitted = %v, stats = %+v", out.Omitted, out.Stats)
	}
}

func TestOrderIsStable(t *testing.T) {
	a := Reduce(load(t), Defaults())
	for i := 0; i < 5; i++ {
		b := Reduce(load(t), Defaults())
		x, _ := schema.Marshal(a.Findings)
		y, _ := schema.Marshal(b.Findings)
		g1, _ := schema.Marshal(a.Groups)
		g2, _ := schema.Marshal(b.Groups)
		if string(x) != string(y) || string(g1) != string(g2) {
			t.Fatal("the same input must give the same output")
		}
	}
}

func TestMaxItemsCountsCuts(t *testing.T) {
	opt := Defaults()
	opt.MaxItems = 2
	out := Reduce(load(t), opt)
	if len(out.Findings) != 2 || out.Omitted["findings"] != 6 {
		t.Errorf("findings = %d, omitted = %v", len(out.Findings), out.Omitted)
	}
}

func TestFitCutsLeastImportantFirst(t *testing.T) {
	var results []ffuf.Result
	for i := 0; i < 300; i++ {
		results = append(results, res(i, fmt.Sprintf("word-%04d", i), 200, 42, 3, 1))
	}
	results = append(results, res(400, ".env", 200, 90, 4, 3))
	out := Reduce(runOf(results...), Defaults())
	r := schema.Result{Tool: "raijin-fuzz", Findings: out.Findings, Groups: out.Groups, Omitted: map[string]int{}, Budget: schema.Budget{MaxBytes: 1000}}
	Fit(&r, 1000)
	b, _ := schema.Marshal(r)
	if len(b) > 1000 {
		t.Errorf("output is %d bytes, over the budget", len(b))
	}
	if !r.Budget.Truncated || r.Omitted["inputs"] != 300 || len(r.Findings) != 1 {
		t.Errorf("budget = %+v, omitted = %v, findings = %d", r.Budget, r.Omitted, len(r.Findings))
	}
	if g := r.Groups[0]; g.Inputs != nil || g.Count != 300 || !strings.Contains(string(b), `"count":300`) {
		t.Errorf("a cut group keeps its count: %+v", g)
	}
}
