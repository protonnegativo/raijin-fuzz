// Command raijin-fuzz runs ffuf and returns a small, shape-collapsed, ranked result for AI agents.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/protonnegativo/raijin-fuzz/internal/banner"
	"github.com/protonnegativo/raijin-fuzz/internal/ffuf"
	"github.com/protonnegativo/raijin-fuzz/internal/reduce"
	"github.com/protonnegativo/raijin-fuzz/internal/schema"
	"github.com/protonnegativo/raijin-fuzz/internal/scope"
	"github.com/protonnegativo/raijin-fuzz/internal/state"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-fuzz", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("u", "", "URL to fuzz, with the FUZZ keyword (ffuf -u; default: https://<host>/FUZZ for every host the scope names)")
	wordlist := fs.String("w", "", "wordlist (ffuf -w); more wordlists and keywords go after -- (default with no -u: SecLists common.txt if found, else a built-in list of 100 common paths)")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	noise := fs.Int("noise", reduce.Defaults().Noise, "inputs with the same response shape that make it noise (a group)")
	rate := fs.Int("rate", 0, "requests per second (ffuf -rate)")
	threads := fs.Int("threads", 0, "concurrent requests (ffuf -t)")
	timeout := fs.Int("timeout", 0, "request timeout in seconds (ffuf -timeout)")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for ffuf's full JSON output (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	input := fs.String("input", "", "read an existing ffuf JSON file (-of json -o) or -json stream instead of running ffuf")
	bin := fs.String("ffuf", "ffuf", "path to the ffuf binary")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-fuzz --scope scope.txt [-u url/FUZZ -w words.txt | --input ffuf.json] [flags] [-- extra ffuf args]\n\nWith no targets it fuzzes every host the scope names.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-fuzz", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, "raijin-fuzz", version)
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-fuzz: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintln(stderr, "raijin-fuzz: scope:", err)
		return 1
	}

	res := schema.Result{
		Tool:     "raijin-fuzz",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}

	var fr *ffuf.Run
	if *input != "" {
		f, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-fuzz:", err)
			return 1
		}
		fr, err = ffuf.Parse(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(stderr, "raijin-fuzz:", err)
			return 1
		}
		res.Target = *input
	} else {
		url, words, extra := *target, *wordlist, fs.Args()
		if *target == "" {
			// no target given: fuzz https://<host>/FUZZ for every host the scope names, in one ffuf
			// run with a second keyword (HOST) for the host
			hosts, wildcards, ranges := sc.Targets()
			for _, w := range wildcards {
				res.Next = append(res.Next, "raijin-subs --scope "+*scopeFile+" -d "+strings.TrimPrefix(w, "*.")+", then raijin-fuzz -u <live host>/FUZZ to cover "+w)
			}
			for _, r := range ranges {
				res.Next = append(res.Next, "raijin-ports --scope "+*scopeFile+" -host "+r+", then raijin-fuzz -u <open web port>/FUZZ to cover "+r)
			}
			if len(hosts) == 0 {
				res.Summary = "the scope names no single host to fuzz"
				res.Target = *scopeFile
				write(stdout, &res, *format, *pretty)
				return 1
			}
			hostList, err := os.CreateTemp("", "raijin-fuzz-hosts-*.txt")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-fuzz:", err)
				return 1
			}
			_, err = hostList.WriteString(strings.Join(hosts, "\n") + "\n")
			hostList.Close()
			defer os.Remove(hostList.Name())
			if err != nil {
				fmt.Fprintln(stderr, "raijin-fuzz:", err)
				return 1
			}
			if words == "" {
				p, temp, err := ffuf.DefaultWordlist("")
				if err != nil {
					fmt.Fprintln(stderr, "raijin-fuzz:", err)
					return 1
				}
				if temp {
					defer os.Remove(p)
				}
				words = p
			}
			url = "https://HOST/FUZZ"
			words += ":FUZZ"
			extra = append([]string{"-w", hostList.Name() + ":HOST"}, extra...)
			res.Target = *scopeFile
		} else {
			if words == "" {
				fmt.Fprintln(stderr, "raijin-fuzz: -w is required with -u (or --input)")
				return 1
			}
			if !sc.Allowed(url) {
				fmt.Fprintln(stderr, "raijin-fuzz: target is not in scope:", url)
				return 1
			}
			res.Target = url
		}

		tempRaw := *rawPath == ""
		if tempRaw {
			f, err := os.CreateTemp("", "raijin-fuzz-*.json")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-fuzz:", err)
				return 1
			}
			f.Close()
			*rawPath = f.Name()
		}
		res.Raw = *rawPath

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		var stderrTail string
		fr, stderrTail, err = ffuf.Fuzz(ctx, ffuf.Options{
			Binary: *bin, URL: url, Wordlist: words, Rate: *rate, Threads: *threads, Timeout: *timeout,
			Extra: extra, RawPath: *rawPath,
		})
		switch {
		case errors.Is(err, ffuf.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install ffuf (go install github.com/ffuf/ffuf/v2@latest) or pass --ffuf <path>"})
			res.Summary = "ffuf not found, nothing fuzzed"
			res.Raw = ""
			if tempRaw {
				os.Remove(*rawPath)
			}
			write(stdout, &res, *format, *pretty)
			return 2
		case err != nil:
			hint := err.Error()
			if stderrTail != "" {
				hint += ": " + stderrTail
			}
			res.Errors = append(res.Errors, schema.Error{Kind: "engine_error", Hint: hint})
		}
	}

	if fr.Errors > 0 {
		res.Errors = append(res.Errors, schema.Error{Kind: "request_errors", Hint: fmt.Sprintf("ffuf counted %d failed requests (timeouts, refused connections); those inputs have no result: lower --rate or --threads, or raise --timeout, and run again", fr.Errors)})
	}
	if fr.URL != res.Target {
		res.URL = fr.URL
	}
	// ffuf's default matcher with no filter is documented and left out.
	if fr.Match != "status "+ffuf.DefaultMatch || fr.Filter != "" {
		res.Match, res.Filter = fr.Match, fr.Filter
	}

	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.Noise = *noise
	opt.InScope = sc.Allowed
	out := reduce.Reduce(fr, opt)
	res.Findings, res.Groups = out.Findings, out.Groups
	for k, v := range out.Omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = st.Mark(res.Findings, out.Inputs)
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(res, out.Stats, newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		if src := res.Raw + *input; src != "" {
			hint += " or read " + src + " for what was cut"
		}
		res.Next = append(res.Next, hint)
		reduce.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return 0
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, st reduce.Stats, newCount int) string {
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d results, %d shapes: %d findings", st.Results, st.Shapes, len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d groups", len(res.Groups))
	if st.Noise > 0 {
		s += fmt.Sprintf(" (%d noise results)", st.Noise)
	}
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		if res.URL != "" {
			fmt.Fprintln(w, "url     ", res.URL)
		}
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			tags := strings.Join(f.Tags, ",")
			if tags != "" {
				tags += " "
			}
			fmt.Fprintf(w, "%-8s %s%s: %s%s\n", strings.ToUpper(f.Severity), tags, describe(f.Shape), strings.Join(f.Inputs, " "), mark)
		}
		for _, g := range res.Groups {
			fmt.Fprintf(w, "group    %s (%d inputs)\n", describe(g.Shape), g.N)
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(res)
}

// describe is a one-line view of a shape for the table: status, size, words, lines, type, redirect.
func describe(s schema.Shape) string {
	size := fmt.Sprint(s.Length)
	if s.Reflected {
		size += "+input"
	}
	out := fmt.Sprintf("%d size=%s words=%d lines=%d", s.Status, size, s.Words, s.Lines)
	if s.Type != "" {
		out += " " + s.Type
	}
	if s.Redirect != "" {
		out += " -> " + s.Redirect
	}
	if s.MS > 0 {
		out += fmt.Sprintf(" %dms", s.MS)
	}
	return out
}
