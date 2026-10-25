package engines

import "testing"

func TestTested(t *testing.T) {
	m, err := Tested()
	if err != nil {
		t.Fatal(err)
	}
	// every engine raijin-fuzz runs has an entry
	for _, name := range []string{"ffuf"} {
		e, ok := m[name]
		if !ok || e.Go == "" {
			t.Fatalf("no entry for %s: %+v", name, m)
		}
		if _, ok := Parse(e.Version); !ok {
			t.Errorf("%s version %q does not parse", name, e.Version)
		}
	}
}

func TestParse(t *testing.T) {
	for out, want := range map[string][3]int{
		"ffuf version: 2.1.0\n":                 {2, 1, 0},
		"ffuf version: 2.1.0-dev\n":             {2, 1, 0},
		"ffuf version: v1.5.0-git\n":            {1, 5, 0},
		"ffuf version: 2.0.0-dev (abc123)\n":    {2, 0, 0},
		"\x1b[2Kffuf version: 12.10.3\nextra\n": {12, 10, 3},
	} {
		got, ok := Parse(out)
		if !ok || got != want {
			t.Errorf("Parse(%q) = %v %v, want %v", out, got, ok, want)
		}
	}
	if _, ok := Parse("ffuf version: dev\n"); ok {
		t.Error("no version should not parse")
	}
}

func TestUntested(t *testing.T) {
	tested := [3]int{2, 1, 0}
	for v, want := range map[[3]int]bool{
		{2, 1, 0}: false,
		{2, 1, 1}: false,
		{2, 3, 0}: false,
		{2, 0, 9}: true,
		{1, 9, 9}: true,
		{3, 0, 0}: true,
	} {
		if got := Untested(v, tested); got != want {
			t.Errorf("Untested(%v) = %v, want %v", v, got, want)
		}
	}
}
