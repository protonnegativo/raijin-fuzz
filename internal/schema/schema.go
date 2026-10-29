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

import core "github.com/protonnegativo/raijin-core/schema"

// The envelope (the Result object, Error, Budget, Marshal and the rank tables) is in raijin-core, shared
// by every Raijin tool. Findings and groups stay here: their fields are what this tool tells an agent.
type (
	// Result is the top-level object raijin-fuzz writes to stdout. URL is the URL ffuf fuzzed, with its
	// keywords (FUZZ), left out when it is the target; Match and Filter are ffuf's matchers and filters
	// ("status 200-299,301"), left out when ffuf ran with its default matcher and no filter.
	Result = core.Result[Finding, Group]
	Error  = core.Error
	Budget = core.Budget
)

var (
	// Marshal is json.Marshal without HTML escaping.
	Marshal = core.Marshal
	// SeverityRank orders severities from most to least important.
	SeverityRank = core.SeverityRank
	// ConfidenceRank orders confidence values: verified, then matched, then heuristic.
	ConfidenceRank = core.ConfidenceRank
)

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
