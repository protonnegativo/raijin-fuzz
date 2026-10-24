// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engine found is dropped silently: every ffuf result is listed, in a finding or in a group,
// and anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the JSON to
// save tokens: empty lists, the budget when nothing was cut, a count equal to the inputs listed, and
// fields at their documented default.
//
// raijin-fuzz adds the response shape (status, length, words, lines, type, redirect) to findings and
// groups, and the fuzzed URL and ffuf's matchers to the result: they are what an agent reads to pick its
// next requests.
package schema

import (
	"bytes"
	"encoding/json"
)

// Marshal is json.Marshal without HTML escaping: "&" in a URL stays "&" instead of "&", which costs
// tokens and nothing else.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Result is the top-level object a Raijin tool writes to stdout.
type Result struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Target  string `json:"target"`
	Summary string `json:"summary"`
	// URL is the URL ffuf fuzzed, with its keywords (FUZZ): an input is put in place of the keyword to
	// get the URL of a result. It is left out when it is the target.
	URL string `json:"url,omitempty"`
	// Match and Filter are ffuf's matchers and filters ("status 200-299,301"), left out when ffuf ran
	// with its default matcher and no filter.
	Match    string         `json:"match,omitempty"`
	Filter   string         `json:"filter,omitempty"`
	Findings []Finding      `json:"findings"`
	Groups   []Group        `json:"groups"`
	Omitted  map[string]int `json:"omitted,omitempty"`
	Errors   []Error        `json:"errors,omitempty"`
	Next     []string       `json:"next,omitempty"`
	// Raw is the file with the engine's full output, for details the result leaves out.
	Raw    string `json:"raw,omitempty"`
	Budget Budget `json:"budget"`
}

// MarshalJSON writes the budget only when something was cut.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	out := struct {
		plain
		Budget *Budget `json:"budget,omitempty"`
	}{plain: plain(r)}
	if r.Budget.Truncated {
		out.Budget = &r.Budget
	}
	return Marshal(out)
}

// Shape is what a set of inputs answered: every input of a finding or group got this exact response
// shape. Status, length, words and lines are always written (0 is a real value).
type Shape struct {
	Status int `json:"status"`
	// Length is the body size in bytes. When Reflected is set, the body echoes the input: each response
	// is Length plus the length of its input in bytes.
	Length    int  `json:"length"`
	Reflected bool `json:"reflected,omitempty"`
	Words     int  `json:"words"`
	Lines     int  `json:"lines"`
	// Type is the content type without parameters; left out when text/html, "none" when the server sent
	// none.
	Type string `json:"type,omitempty"`
	// Redirect is the Location header, with each input written as its keyword (FUZZ): "/FUZZ/" is a
	// directory, "/login?next=/FUZZ" a catch-all redirect.
	Redirect string `json:"redirect,omitempty"`
	// MS is the slowest response time in milliseconds; it is written only for timing outliers.
	MS int `json:"ms,omitempty"`
}

// Finding is one response shape that differs from the noise (a real file, a 403, a redirect, a slow
// answer) with every input that got it. The same tool and ID in two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Tags are the rules beyond the status that the finding matches: file, admin, dir, slow. Left out
	// when there are none.
	Tags []string `json:"tags,omitempty"`
	Shape
	// Inputs are the inputs (wordlist entries) that got this shape, in wordlist order.
	Inputs []string `json:"inputs"`
	// Count is the number of inputs; it is set only when the budget cut Inputs.
	Count int `json:"count,omitempty"`
	// N is the number of inputs, for ranking, the summary and Count; it is not written.
	N int `json:"-"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// Group is one response shape that many inputs got: a soft-404, a catch-all page or redirect, a WAF
// block. It is the baseline the findings differ from, with every input of it.
type Group struct {
	ID string `json:"id"`
	Shape
	Inputs []string `json:"inputs,omitempty"`
	// Count is the number of inputs; it is set only when the budget cut Inputs.
	Count int `json:"count,omitempty"`
	N     int `json:"-"`
}

// Error is a problem during the run, with a hint about what to try next.
type Error struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// Budget reports the output limits that were applied.
type Budget struct {
	MaxItems  int  `json:"max_items"`
	MaxBytes  int  `json:"max_bytes"`
	Truncated bool `json:"truncated"`
}

// SeverityRank orders severities from most to least important.
var SeverityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"unknown":  0,
}

// ConfidenceRank orders confidence values: a verified finding before a matched one before a heuristic one.
var ConfidenceRank = map[string]int{
	"verified":  2,
	"":          1,
	"heuristic": 0,
}
