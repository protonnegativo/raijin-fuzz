// Package engines holds the engine versions raijin-fuzz is tested with (engines.json), embedded in the
// binary so a run can tell when the installed engine differs.
package engines

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
)

//go:embed engines.json
var data []byte

// Engine is one tested engine: its version and where it installs from (one of Go, Pip, System).
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	Pip     string `json:"pip,omitempty"`
	System  string `json:"system,omitempty"`
}

// Tested parses the embedded engines.json.
func Tested() (map[string]Engine, error) {
	var m map[string]Engine
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("engines.json: %w", err)
	}
	return m, nil
}

// Install is the command that installs version v of the engine.
func (e Engine) Install(v string) string {
	switch {
	case e.Go != "":
		return "go install " + e.Go + "@v" + v
	case e.Pip != "":
		return "pipx install " + e.Pip + "==" + v
	default:
		return "install the " + e.System + " package, version " + v
	}
}

var versionRe = regexp.MustCompile(`v?([0-9]+)\.([0-9]+)\.([0-9]+)`)

// Parse finds the first X.Y.Z (or vX.Y.Z) in a version command's output.
func Parse(out string) ([3]int, bool) {
	var v [3]int
	m := versionRe.FindStringSubmatch(out)
	if m == nil {
		return v, false
	}
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

// Untested is true when installed has another major version than tested, or is older. A newer minor or
// patch of the same major is fine: the weekly drift job tests those.
func Untested(installed, tested [3]int) bool {
	if installed[0] != tested[0] {
		return true
	}
	for i := 1; i < 3; i++ {
		if installed[i] != tested[i] {
			return installed[i] < tested[i]
		}
	}
	return false
}
