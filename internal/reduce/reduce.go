// Package reduce turns raw ffuf results into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every result ffuf reported is kept, with its input, URL,
// status, length, words, lines, content type and redirect. Results with the same response shape share
// one entry that lists every input of it. A shape many inputs got (a soft-404, a catch-all page, a WAF
// block) is noise and becomes a group; the shapes that differ from it are findings. Only exact duplicates
// are dropped. A byte budget can cut, but every cut is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/protonnegativo/raijin-fuzz/internal/ffuf"
	"github.com/protonnegativo/raijin-fuzz/internal/schema"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems int // 0 keeps every finding
	MaxBytes int
	// Noise is the number of inputs that makes a response shape noise (a group).
	Noise   int
	InScope func(target string) bool
}

// Defaults keep every finding, call a shape noise from 5 inputs, and cap the JSON at a size that fits
// comfortably in an agent's context.
func Defaults() Options {
	return Options{MaxBytes: 16000, Noise: 5}
}

// Stats are the counts of the run, before any budget, for the summary.
type Stats struct {
	Results int // distinct results ffuf reported
	Noise   int // results in groups
	Shapes  int // findings and groups
}

// Output is what Reduce returns.
type Output struct {
	Findings []schema.Finding
	Groups   []schema.Group
	Omitted  map[string]int
	// Inputs are every input per finding fingerprint, before any budget, for --state.
	Inputs map[string][]string
	Stats  Stats
}

// A response is slow when it took at least slowMin and slowFactor times the median of the run.
const (
	slowMin    = time.Second
	slowFactor = 5
)

var (
	// adminWords are names (without extension) of admin, debug, internal, config and backup areas.
	adminWords = regexp.MustCompile(`^(admin\w*|administrator|wp-admin|_?debug\w*|internal|private|actuator|console|manage|management|manager|phpmyadmin|config|configuration|settings|backups?|setup|install|server-status|server-info|metrics|env|staff|dashboard|jmx|heapdump|trace|swagger|swagger-ui|api-docs|graphiql|_profiler|phpinfo|elmah|cgi-bin|test|dev|staging|old)$`)
)

// fileExt are extensions of backups, dumps, configs, archives, keys and logs.
var fileExt = set("bak", "old", "orig", "backup", "bkp", "swp", "save", "tmp", "sql", "db", "sqlite", "sqlite3",
	"dump", "mdb", "env", "ini", "conf", "cfg", "config", "yml", "yaml", "toml", "properties", "log", "zip", "tar",
	"gz", "tgz", "bz2", "xz", "7z", "rar", "war", "jar", "pem", "key", "p12", "pfx", "kdbx", "htpasswd", "git", "svn")

// item is one result ffuf reported, with what the reducer derives from it.
type item struct {
	r        ffuf.Result
	input    string // the written input: the value, "K=v K2=v2" for several keywords, plus " @ url"
	ctype    string
	redirect string // the Location header with the input written as its keyword
	slow     bool
	names    []string // file, admin
	size     int      // bytes of the input values
}

type entry struct {
	key       string
	shape     schema.Shape
	names     []string
	dir, slow bool
	items     []*item
}

// Reduce collapses ffuf results into findings and groups: one entry per response shape, listing every
// input of it.
func Reduce(run *ffuf.Run, opt Options) Output {
	out := Output{Omitted: map[string]int{}, Inputs: map[string][]string{}}
	if opt.Noise <= 0 {
		opt.Noise = Defaults().Noise
	}
	var results []ffuf.Result
	for _, r := range run.Results {
		if opt.InScope != nil && !opt.InScope(r.URL) {
			out.Omitted["out_of_scope"]++
			continue
		}
		results = append(results, r)
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].Position < results[j].Position })
	median := medianDuration(results)
	base := pathOf(run.URL)

	// the last segment of the URL is the input's name when it holds a keyword
	nameInURL := false
	for _, r := range results {
		for k := range r.Input {
			nameInURL = nameInURL || strings.Contains(lastSegment(run.URL), k)
		}
	}

	var items []*item
	seen := map[string]bool{}
	for _, r := range results {
		it := &item{r: r, input: Input(r.Input), ctype: contentType(r.ContentType), slow: slow(r.Duration, median)}
		if run.URL == "" || ffuf.Substitute(run.URL, r.Input) != r.URL {
			it.input += " @ " + r.URL
		}
		it.redirect = RedirectTemplate(r, run.URL)
		for _, v := range r.Input {
			it.size += len(v)
		}
		values := make([]string, 0, len(r.Input)+1)
		for _, v := range r.Input {
			values = append(values, v)
		}
		if nameInURL {
			values = append(values, lastSegment(r.URL)) // FUZZ.EXT: the name is admin.bak, not admin and bak
		}
		it.names = Names(values)
		dup := strings.Join([]string{it.input, fmt.Sprint(r.Status, r.Length, r.Words, r.Lines), it.ctype, r.Redirect}, "\x00")
		if seen[dup] {
			out.Omitted["duplicates"]++
			continue
		}
		seen[dup] = true
		items = append(items, it)
	}
	out.Stats.Results = len(items)

	isDir := func(it *item) bool {
		// the template differs from the header only when it holds the keyword
		return it.redirect != it.r.Redirect && (it.redirect == base+"/" || it.redirect == run.URL+"/")
	}

	// Reflected noise: a soft-404 that echoes the input has a different length per input, but the same
	// length once the input is taken out.
	assigned := map[*item]bool{}
	var groups, findings []*entry
	alt := map[string][]*item{}
	var altKeys []string
	for _, it := range items {
		k := fmt.Sprint(it.r.Status, it.r.Words, it.r.Lines, it.r.Length-it.size, it.slow) + "\x00" + it.ctype + "\x00" + it.redirect
		if _, ok := alt[k]; !ok {
			altKeys = append(altKeys, k)
		}
		alt[k] = append(alt[k], it)
	}
	for _, k := range altKeys {
		its := alt[k]
		lengths := map[int]bool{}
		for _, it := range its {
			lengths[it.r.Length] = true
		}
		if len(its) < opt.Noise || len(lengths) < 2 || isDir(its[0]) {
			continue
		}
		e := newEntry("reflected\x00"+k, its[0], nil)
		e.shape.Length, e.shape.Reflected = its[0].r.Length-its[0].size, true
		for _, it := range its {
			e.add(it)
			assigned[it] = true
		}
		groups = append(groups, e)
	}

	exact := map[string][]*item{}
	var exactKeys []string
	for _, it := range items {
		if assigned[it] {
			continue
		}
		k := fmt.Sprint(it.r.Status, it.r.Length, it.r.Words, it.r.Lines, it.slow) + "\x00" + it.ctype + "\x00" + it.redirect
		if _, ok := exact[k]; !ok {
			exactKeys = append(exactKeys, k)
		}
		exact[k] = append(exact[k], it)
	}
	for _, k := range exactKeys {
		its := exact[k]
		dir := isDir(its[0])
		// A redirect that adds a slash is a directory, not noise, unless the server does it for more
		// than half of all inputs.
		if len(its) >= opt.Noise && (!dir || 2*len(its) > len(items)) {
			e := newEntry(k, its[0], nil)
			for _, it := range its {
				e.add(it)
			}
			groups = append(groups, e)
			continue
		}
		// The same shape splits by name, so a .env is never in the same finding as a plain page.
		byName := map[string]*entry{}
		var order []string
		for _, it := range its {
			nk := strings.Join(it.names, ",")
			e, ok := byName[nk]
			if !ok {
				e = newEntry(k+"\x00"+nk, it, it.names)
				e.dir = dir
				byName[nk] = e
				order = append(order, nk)
			}
			e.add(it)
		}
		for _, nk := range order {
			findings = append(findings, byName[nk])
		}
	}

	for _, e := range groups {
		out.Stats.Noise += len(e.items)
		out.Groups = append(out.Groups, schema.Group{ID: ID(e.shape.Status, e.key), Shape: e.shape, Inputs: e.inputs(), N: len(e.items)})
	}
	for _, e := range findings {
		id := ID(e.shape.Status, e.key)
		f := schema.Finding{ID: id, Tags: e.tags(), Shape: e.shape, Inputs: e.inputs(), N: len(e.items), Fingerprint: fingerprint(id)}
		f.Severity = severity(f.Status, f.Tags)
		out.Inputs[f.Fingerprint] = f.Inputs
		out.Findings = append(out.Findings, f)
	}
	out.Stats.Shapes = len(groups) + len(findings)
	if out.Findings == nil {
		out.Findings = []schema.Finding{}
	}
	if out.Groups == nil {
		out.Groups = []schema.Group{}
	}

	first := map[string]int{}
	for _, e := range append(append([]*entry{}, groups...), findings...) {
		first[ID(e.shape.Status, e.key)] = e.items[0].r.Position
	}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if len(a.Tags) != len(b.Tags) {
			return len(a.Tags) > len(b.Tags)
		}
		if a.N != b.N {
			return a.N > b.N
		}
		if first[a.ID] != first[b.ID] {
			return first[a.ID] < first[b.ID]
		}
		return a.ID < b.ID
	})
	sort.SliceStable(out.Groups, func(i, j int) bool {
		a, b := out.Groups[i], out.Groups[j]
		if a.N != b.N {
			return a.N > b.N
		}
		if first[a.ID] != first[b.ID] {
			return first[a.ID] < first[b.ID]
		}
		return a.ID < b.ID
	})

	if opt.MaxItems > 0 && len(out.Findings) > opt.MaxItems {
		out.Omitted["findings"] += len(out.Findings) - opt.MaxItems
		out.Findings = out.Findings[:opt.MaxItems]
	}
	return out
}

func newEntry(key string, it *item, names []string) *entry {
	r := it.r
	return &entry{key: key, names: names, slow: it.slow, shape: schema.Shape{
		Status: r.Status, Length: r.Length, Words: r.Words, Lines: r.Lines, Type: it.ctype, Redirect: it.redirect,
	}}
}

func (e *entry) add(it *item) {
	e.items = append(e.items, it)
	if it.slow {
		e.shape.MS = max(e.shape.MS, int(it.r.Duration/int64(time.Millisecond)))
	}
}

// inputs are the written inputs of the entry, in wordlist order.
func (e *entry) inputs() []string {
	out := make([]string, len(e.items))
	for i, it := range e.items {
		out[i] = it.input
	}
	return out
}

// tags are the rules a finding matches beyond its status, in a fixed order. The status class (2xx, 3xx,
// 401/403, 5xx) is not a tag: the status is written.
//
//	file   a backup, dump, config, archive, key or log extension (.bak .sql .env .zip ...), or a dotfile
//	admin  an admin, debug, internal, config or backup name
//	dir    a redirect that adds a slash to the URL: a directory
//	slow   a response at least 1s and 5 times the median response time of the run
func (e *entry) tags() []string {
	tags := append([]string{}, e.names...)
	if e.dir {
		tags = append(tags, "dir")
	}
	if e.slow {
		tags = append(tags, "slow")
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}

// severity ranks a finding by its status and tags:
//
//	high    2xx with a file or admin name
//	medium  401, 403 or 407
//	low     3xx, 5xx, or slow
//	info    anything else: a plain 2xx, another 4xx
func severity(status int, tags []string) string {
	has := map[string]bool{}
	for _, t := range tags {
		has[t] = true
	}
	switch {
	case status/100 == 2 && (has["file"] || has["admin"]):
		return "high"
	case status == 401 || status == 403 || status == 407:
		return "medium"
	case status/100 == 3 || status/100 == 5 || has["slow"]:
		return "low"
	}
	return "info"
}

// Names are the name rules the input values (and the URL's last segment) match: file (a backup, config, dump, archive, key or log extension,
// a trailing ~, or a dotfile segment such as .git/HEAD) and admin (an admin, debug, internal, config or
// backup segment).
func Names(values []string) []string {
	file, admin := false, false
	for _, v := range values {
		for _, seg := range strings.Split(strings.ToLower(v), "/") {
			if seg == "" {
				continue
			}
			if fileExt[ext(seg)] || strings.HasSuffix(seg, "~") || (len(seg) > 1 && seg[0] == '.' && seg != "..") {
				file = true
			}
			word := seg
			if i := strings.Index(seg, "."); i > 0 {
				word = seg[:i]
			}
			admin = admin || adminWords.MatchString(word)
		}
	}
	var out []string
	if file {
		out = append(out, "file")
	}
	if admin {
		out = append(out, "admin")
	}
	return out
}

// Input is how an input is written: its value, or "K=v K2=v2" (sorted by keyword) when ffuf fuzzed
// several keywords.
func Input(in map[string]string) string {
	if len(in) == 1 {
		for _, v := range in {
			return v
		}
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + in[k]
	}
	return strings.Join(parts, " ")
}

// RedirectTemplate is the Location header with the result's URL (or its path) written as the fuzzed URL
// (or its path), so the keyword stands for the input: "/admin/" for input admin is "/FUZZ/". It is kept
// as it is when putting the input back would not give the header ffuf saw.
func RedirectTemplate(r ffuf.Result, template string) string {
	loc := r.Redirect
	if loc == "" || template == "" || ffuf.Substitute(template, r.Input) != r.URL {
		return loc
	}
	for k := range r.Input {
		if strings.Contains(loc, k) {
			return loc
		}
	}
	for _, pair := range [][2]string{{r.URL, template}, {pathOf(r.URL), pathOf(template)}} {
		if pair[0] == "" || pair[0] == pair[1] || !strings.Contains(loc, pair[0]) {
			continue
		}
		t := replaceWhole(loc, pair[0], pair[1])
		if t != loc && ffuf.Substitute(t, r.Input) == loc {
			return t
		}
	}
	return loc
}

// replaceWhole replaces old with new where old is not followed by more of a name: "/admin" in
// "/admin/" and "/login?next=/admin", not in "/administrator".
func replaceWhole(s, old, new string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, old)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		end := i + len(old)
		b.WriteString(s[:i])
		if end == len(s) || strings.IndexByte("/?#&;\"' ", s[end]) >= 0 {
			b.WriteString(new)
		} else {
			b.WriteString(old)
		}
		s = s[end:]
	}
}

// lastSegment is the last path segment of a URL.
func lastSegment(raw string) string {
	p := pathOf(raw)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return p[strings.LastIndex(p, "/")+1:]
}

// pathOf is the path and query of a URL: what follows the scheme and host.
func pathOf(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		return rest[j:]
	}
	return ""
}

func medianDuration(results []ffuf.Result) int64 {
	if len(results) == 0 {
		return 0
	}
	d := make([]int64, len(results))
	for i, r := range results {
		d[i] = r.Duration
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[len(d)/2]
}

func slow(d, median int64) bool {
	return d >= int64(slowMin) && d >= slowFactor*median
}

// ID is stable across runs while the response shape does not change: the status and a short hash of
// the entry key.
func ID(status int, key string) string {
	return fmt.Sprint(status) + "-" + fingerprint(key)[:8]
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group inputs, then groups, then the inputs of the lowest-ranked findings (each keeps one, and its
// count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		if len(g.Inputs) == 0 {
			continue
		}
		before := size(g)
		res.Omitted["inputs"] += len(g.Inputs)
		g.Inputs, g.Count = nil, g.N
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Inputs) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["inputs"] += len(f.Inputs) - 1
		f.Inputs, f.Count = f.Inputs[:1], f.N
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

// contentType is the media type without parameters. text/html is left out (the documented default), and
// "none" means the server answered without a Content-Type.
func contentType(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch ct {
	case "text/html":
		return ""
	case "":
		return "none"
	}
	return ct
}

// ext is the lowercase extension of a name, or "".
func ext(seg string) string {
	i := strings.LastIndex(seg, ".")
	if i <= 0 || i == len(seg)-1 {
		if i == 0 {
			return strings.ToLower(seg[1:]) // a dotfile: ".env" has extension "env"
		}
		return ""
	}
	return strings.ToLower(seg[i+1:])
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func set(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range items {
		m[s] = true
	}
	return m
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}
