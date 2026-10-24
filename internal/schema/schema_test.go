package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-fuzz",
		Findings: []Finding{{ID: "401-ab12cd34", Severity: "medium", Shape: Shape{Status: 401, Length: 25, Words: 2, Lines: 1}, Inputs: []string{"api"}, N: 1, Fingerprint: "fp"}},
		Groups:   []Group{{ID: "200-ef56ab78", Shape: Shape{Status: 200, Length: 140, Words: 11, Lines: 6}, Inputs: []string{"a", "b"}, N: 2}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "n", "confidence", "tags", "type", "redirect", "reflected", "ms", "new", "url", "match", "filter", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestZeroShapeValuesAreWritten(t *testing.T) {
	f := Finding{ID: "301-x", Severity: "low", Tags: []string{"dir"}, Shape: Shape{Status: 301, Length: 0, Words: 1, Lines: 1, Type: "none", Redirect: "/FUZZ/"}, Inputs: []string{"css", "js"}, N: 2}
	b, _ := Marshal(f)
	want := `{"id":"301-x","severity":"low","tags":["dir"],"status":301,"length":0,"words":1,"lines":1,"type":"none","redirect":"/FUZZ/","inputs":["css","js"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "200-x", Inputs: []string{"a&b"}, Count: 7, N: 7}},
		Groups:   []Group{{ID: "200-y", Count: 4, N: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"inputs":["a&b"],"count":7`) || !strings.Contains(s, `{"id":"200-y","status":0,"length":0,"words":0,"lines":0,"count":4}`) {
		t.Errorf("count must be written when inputs were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
	if strings.Contains(s, `\u0026`) {
		t.Errorf("& must not be escaped: %s", s)
	}
}
