// Package ffuf runs the ffuf web fuzzer and parses its JSON output.
package ffuf

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrNotFound is returned when the ffuf binary is not on PATH.
var ErrNotFound = errors.New("ffuf binary not found")

// DefaultMatch is ffuf's default status matcher (-mc), used when no matcher or filter is given.
const DefaultMatch = "200-299,301,302,307,401,403,405,500"

// Result is one response ffuf reported: the input it sent and the shape of what came back.
type Result struct {
	// Input maps each keyword (FUZZ) to the value sent. ffuf's own FFUFHASH is dropped.
	Input       map[string]string `json:"input"`
	Position    int               `json:"position"`
	Status      int               `json:"status"`
	Length      int               `json:"length"`
	Words       int               `json:"words"`
	Lines       int               `json:"lines"`
	ContentType string            `json:"content-type"`
	Redirect    string            `json:"redirectlocation"`
	// Duration is the response time in nanoseconds.
	Duration int64  `json:"duration"`
	URL      string `json:"url"`
	Host     string `json:"host"`
}

// Run is a parsed ffuf output: the fuzzed URL, the matchers and filters it applied, and every result.
type Run struct {
	// URL is the fuzzed URL with its keywords. ffuf's -json stream has no config, so it is rebuilt from
	// the results there (see Template).
	URL string
	// Match and Filter are the matchers and filters, "status 200-299,301" style, sorted by name.
	Match, Filter string
	Results       []Result
	// Errors is the number of requests that failed (timeouts, refused connections), from ffuf's last
	// progress line. Those inputs have no result. It is only known when Raijin ran ffuf.
	Errors int
	// Lines is the number of results (or, in the -json stream, non-empty lines) ffuf wrote, and
	// Unparsed how many of them had no url or status (or were not JSON): they are not in Results.
	Lines, Unparsed int
}

// essential is what a result needs to be one: Parse counts results without these fields in Unparsed.
type essential struct {
	URL    string `json:"url"`
	Status *int   `json:"status"`
}

func (e essential) ok() bool { return e.URL != "" && e.Status != nil }

type file struct {
	Results []Result `json:"results"`
	Config  *struct {
		URL             string `json:"url"`
		AutoCalibration bool   `json:"autocalibration"`
		Matchers        struct {
			Matchers map[string]struct {
				Value string `json:"value"`
			} `json:"Matchers"`
			Filters map[string]struct {
				Value string `json:"value"`
			} `json:"Filters"`
		} `json:"matchers"`
	} `json:"config"`
}

// Parse reads ffuf output: the JSON file of -of json -o (one object with results and config), or the
// JSON lines of -json, where ffuf writes the input values in base64. Lines that are not results are
// skipped and counted in Unparsed.
func Parse(r io.Reader) (*Run, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	run := &Run{}
	var f file
	var raw struct {
		Results []essential `json:"results"`
	}
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && json.Unmarshal(trimmed, &f) == nil && (f.Config != nil || f.Results != nil) {
		_ = json.Unmarshal(trimmed, &raw)
		for i, res := range f.Results {
			run.Lines++
			if i < len(raw.Results) && !raw.Results[i].ok() {
				run.Unparsed++
				continue
			}
			run.Results = append(run.Results, clean(res, false))
		}
		if c := f.Config; c != nil {
			run.URL = c.URL
			var m, fl []string
			for name, v := range c.Matchers.Matchers {
				m = append(m, name+" "+v.Value)
			}
			for name, v := range c.Matchers.Filters {
				fl = append(fl, name+" "+v.Value)
			}
			if c.AutoCalibration {
				fl = append(fl, "autocalibration")
			}
			sort.Strings(m)
			sort.Strings(fl)
			run.Match, run.Filter = strings.Join(m, ", "), strings.Join(fl, ", ")
		}
	} else {
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			run.Lines++
			var res Result
			var e essential
			if json.Unmarshal(line, &res) != nil || json.Unmarshal(line, &e) != nil || !e.ok() {
				run.Unparsed++
				continue
			}
			run.Results = append(run.Results, clean(res, true))
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	if run.URL == "" {
		run.URL = Template(run.Results)
	}
	return run, nil
}

// clean drops FFUFHASH and decodes base64 input values (the -json stream).
func clean(r Result, b64 bool) Result {
	in := map[string]string{}
	for k, v := range r.Input {
		if k == "FFUFHASH" {
			continue
		}
		if b64 {
			if d, err := base64.StdEncoding.DecodeString(v); err == nil {
				v = string(d)
			}
		}
		in[k] = v
	}
	r.Input = in
	return r
}

// Template rebuilds the fuzzed URL from results: the URL they all share (the keyword was not in the
// URL), or the first result's URL with the last occurrence of its input written as the keyword.
func Template(results []Result) string {
	if len(results) == 0 {
		return ""
	}
	same := true
	for _, r := range results {
		same = same && r.URL == results[0].URL
	}
	if same {
		return results[0].URL
	}
	for _, r := range results {
		if len(r.Input) != 1 {
			continue
		}
		for k, v := range r.Input {
			if i := strings.LastIndex(r.URL, v); v != "" && i >= 0 {
				return r.URL[:i] + k + r.URL[i+len(v):]
			}
		}
	}
	return ""
}

// Substitute writes each input value in place of its keyword.
func Substitute(s string, input map[string]string) string {
	keys := make([]string, 0, len(input))
	for k := range input {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s = strings.ReplaceAll(s, k, input[k])
	}
	return s
}

// Options are the ffuf settings Raijin passes through.
type Options struct {
	Binary   string
	URL      string
	Wordlist string
	Rate     int
	Threads  int
	Timeout  int
	Extra    []string
	// RawPath receives ffuf's JSON output (-o). It is required.
	RawPath string
}

// Fuzz runs ffuf and returns its parsed output, plus the last stderr lines if ffuf failed.
func Fuzz(ctx context.Context, opt Options) (*Run, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "ffuf"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, "", ErrNotFound
	}
	// ffuf reads its wordlist from stdin with -w -; Stdin stays nil (/dev/null) so a caller's pipe is
	// never read, and -noninteractive keeps ffuf from waiting for keys.
	os.Remove(opt.RawPath) // a stale file must not be read as this run's output
	cmd := exec.CommandContext(ctx, path, Args(opt)...)
	stderr := &tailBuffer{max: 64 * 1024}
	cmd.Stderr = stderr
	cmd.Stdout = io.Discard
	waitErr := cmd.Run()
	f, err := os.Open(opt.RawPath)
	if err != nil {
		if waitErr != nil {
			return &Run{}, tail(stderr.String(), 3), fmt.Errorf("ffuf exited: %w", waitErr)
		}
		return &Run{}, "", err
	}
	defer f.Close()
	run, parseErr := Parse(f)
	if run != nil {
		run.Errors = Errors(stderr.String())
	}
	if parseErr != nil {
		return run, tail(stderr.String(), 3), parseErr
	}
	if waitErr != nil {
		return run, tail(stderr.String(), 3), fmt.Errorf("ffuf exited: %w", waitErr)
	}
	return run, "", nil
}

// Args builds the ffuf command line. The JSON file (-of json -o) holds every result and the config.
// ffuf's text output is discarded, but not silenced (-s): its progress line on stderr is the only place
// it counts failed requests.
func Args(opt Options) []string {
	args := []string{"-u", opt.URL, "-w", opt.Wordlist, "-of", "json", "-o", opt.RawPath, "-noninteractive"}
	if opt.Rate > 0 {
		args = append(args, "-rate", fmt.Sprint(opt.Rate))
	}
	if opt.Threads > 0 {
		args = append(args, "-t", fmt.Sprint(opt.Threads))
	}
	if opt.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprint(opt.Timeout))
	}
	return append(args, opt.Extra...)
}

var errorsRe = regexp.MustCompile(`:: Errors: ([0-9]+) ::`)

// Errors is the error count of ffuf's last progress line, or 0.
func Errors(stderr string) int {
	m := errorsRe.FindAllStringSubmatch(stderr, -1)
	if len(m) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(m[len(m)-1][1])
	return n
}

// Version runs ffuf -V (it prints "ffuf version: 2.1.0") and returns its output, or "" when it fails
// or takes longer than 3 seconds.
func Version(ctx context.Context, bin string) string {
	if bin == "" {
		bin = "ffuf"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "-V").CombinedOutput()
	return string(out)
}

// tailBuffer keeps the last max bytes written to it: ffuf rewrites its progress line many times a
// second, and only the end matters.
type tailBuffer struct {
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 2*t.max {
		t.b = append([]byte{}, t.b[len(t.b)-t.max:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	if len(t.b) > t.max {
		return string(t.b[len(t.b)-t.max:])
	}
	return string(t.b)
}

// tail is the last n non-empty lines of ffuf's stderr, without its progress lines and colors.
func tail(s string, n int) string {
	var lines []string
	for _, l := range regexp.MustCompile(`[\r\n]+`).Split(s, -1) {
		l = strings.TrimSpace(strings.TrimPrefix(l, "\x1b[2K"))
		if l != "" && !strings.HasPrefix(l, ":: Progress:") {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// commonPaths is the wordlist used when no -w is given and SecLists' common.txt is not on the machine:
// about a hundred common paths, directories and files (common.txt in this package).
//
//go:embed common.txt
var commonPaths []byte

// SecListsCommon are the places SecLists' Discovery/Web-Content/common.txt is looked for, in order.
var SecListsCommon = []string{
	"/usr/share/seclists/Discovery/Web-Content/common.txt",
	"/usr/share/SecLists/Discovery/Web-Content/common.txt",
	"/opt/SecLists/Discovery/Web-Content/common.txt",
	"~/SecLists/Discovery/Web-Content/common.txt",
	"~/tools/SecLists/Discovery/Web-Content/common.txt",
}

// DefaultWordlist is the wordlist for a run with no -w: SecLists' common.txt when it is found at one of
// SecListsCommon, or else the embedded list written to a new file in dir. temp is true for that file,
// which the caller removes.
func DefaultWordlist(dir string) (path string, temp bool, err error) {
	home, _ := os.UserHomeDir()
	for _, p := range SecListsCommon {
		if strings.HasPrefix(p, "~/") {
			if home == "" {
				continue
			}
			p = home + p[1:]
		}
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, false, nil
		}
	}
	f, err := os.CreateTemp(dir, "raijin-fuzz-words-*.txt")
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	if _, err := f.Write(commonPaths); err != nil {
		os.Remove(f.Name())
		return "", false, err
	}
	return f.Name(), true, nil
}
