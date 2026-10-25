package ffuf

import (
	"os"
	"strings"
	"testing"
)

func TestParseFile(t *testing.T) {
	f, err := os.Open("../../testdata/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	run, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Results) != 21 || run.URL != "https://app.example.com/FUZZ" || run.Match != "status "+DefaultMatch {
		t.Fatalf("run = %+v", run)
	}
	r := run.Results[0]
	if len(r.Input) != 1 || r.Input["FUZZ"] != "about" || r.Status != 200 || r.Length != 145 || r.Words != 11 || r.Lines != 6 {
		t.Errorf("first result = %+v (FFUFHASH is dropped)", r)
	}
}

func TestParseStream(t *testing.T) {
	// ffuf -json writes one line per result, with the input values in base64
	in := ` :: Progress: [1/2]
{"input":{"FFUFHASH":"ZmZkMDAx","FUZZ":"YWRtaW4="},"position":1,"status":301,"length":0,"words":1,"lines":1,"content-type":"","redirectlocation":"/admin/","url":"http://h.test/admin","duration":2146964}
{"input":{"FFUFHASH":"ZmZkMDAy","FUZZ":"LmVudg=="},"position":2,"status":200,"length":3,"words":1,"lines":2,"content-type":"text/plain","redirectlocation":"","url":"http://h.test/.env","duration":3007822}
not json
`
	run, err := Parse(strings.NewReader(in))
	if err != nil || len(run.Results) != 2 {
		t.Fatalf("got %+v, err %v", run, err)
	}
	if run.Results[0].Input["FUZZ"] != "admin" || run.Results[1].Input["FUZZ"] != ".env" || run.Results[0].Redirect != "/admin/" {
		t.Errorf("results = %+v", run.Results)
	}
	if run.URL != "http://h.test/FUZZ" || run.Match != "" {
		t.Errorf("the fuzzed URL is rebuilt from the results: %+v", run)
	}
}

func TestTemplate(t *testing.T) {
	same := []Result{{Input: map[string]string{"FUZZ": "a"}, URL: "http://h.test/"}, {Input: map[string]string{"FUZZ": "b"}, URL: "http://h.test/"}}
	if got := Template(same); got != "http://h.test/" {
		t.Errorf("a keyword outside the URL (a header): %q", got)
	}
	path := []Result{{Input: map[string]string{"FUZZ": "test"}, URL: "http://test.h.test/test"}, {Input: map[string]string{"FUZZ": "b"}, URL: "http://test.h.test/b"}}
	if got := Template(path); got != "http://test.h.test/FUZZ" {
		t.Errorf("the last occurrence is the keyword: %q", got)
	}
}

func TestArgs(t *testing.T) {
	args := strings.Join(Args(Options{URL: "http://h.test/FUZZ", Wordlist: "w.txt", RawPath: "raw.json", Rate: 50, Threads: 5, Timeout: 7, Extra: []string{"-mc", "all"}}), " ")
	for _, want := range []string{"-u http://h.test/FUZZ -w w.txt -of json -o raw.json -noninteractive", "-rate 50", "-t 5", "-timeout 7", "-mc all"} {
		if !strings.Contains(args, want) {
			t.Errorf("args %q should contain %q", args, want)
		}
	}
	if strings.Contains(args, " -s ") {
		t.Errorf("-s hides the error count: %q", args)
	}
	if strings.Contains(args, "-ac") || strings.Contains(args, "-mc 200") {
		t.Errorf("no matcher, filter or calibration is added: %q", args)
	}
}

func TestErrorsFromProgress(t *testing.T) {
	stderr := "\r\x1b[2K:: Progress: [10/242] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::" +
		"\r\x1b[2K:: Progress: [242/242] :: Job [1/1] :: 100 req/sec :: Duration: [0:00:02] :: Errors: 14 ::\n"
	if n := Errors(stderr); n != 14 {
		t.Errorf("errors = %d, want the last count, 14", n)
	}
	if n := Errors("no progress"); n != 0 {
		t.Errorf("errors = %d", n)
	}
	if got := tail(stderr+"Encountered error(s): 1 errors occured.\n", 2); got != "Encountered error(s): 1 errors occured." {
		t.Errorf("tail skips progress lines: %q", got)
	}
	b := &tailBuffer{max: 4}
	b.Write([]byte("abcdefghij"))
	b.Write([]byte("kl"))
	if b.String() != "ijkl" {
		t.Errorf("tail buffer = %q", b.String())
	}
}

func TestDefaultWordlistEmbedded(t *testing.T) {
	saved := SecListsCommon
	SecListsCommon = nil
	defer func() { SecListsCommon = saved }()
	p, temp, err := DefaultWordlist(t.TempDir())
	if err != nil || !temp {
		t.Fatal(err, temp)
	}
	b, _ := os.ReadFile(p)
	if n := strings.Count(string(b), "\n"); n != 100 || !strings.Contains(string(b), "\nadmin\n") {
		t.Errorf("embedded wordlist has %d lines", n)
	}
}

func TestParseRenamedField(t *testing.T) {
	// sample.json with status renamed to status_code: an output format change must be counted
	f, err := os.Open("testdata/renamed_status.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	run, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if run.Lines != 21 || run.Unparsed != 21 || len(run.Results) != 0 {
		t.Errorf("lines %d, unparsed %d, results %d", run.Lines, run.Unparsed, len(run.Results))
	}
	f2, _ := os.Open("../../testdata/sample.json")
	defer f2.Close()
	if run, _ := Parse(f2); run.Lines != 21 || run.Unparsed != 0 {
		t.Errorf("sample: lines %d, unparsed %d", run.Lines, run.Unparsed)
	}
	stream := `{"input":{"FUZZ":"YQ=="},"status_code":200,"url":"http://h.test/a"}
{"input":{"FUZZ":"Yg=="},"status":200,"url":"http://h.test/b"}
not json
`
	if run, _ := Parse(strings.NewReader(stream)); run.Lines != 3 || run.Unparsed != 2 || len(run.Results) != 1 {
		t.Errorf("stream: lines %d, unparsed %d, results %d", run.Lines, run.Unparsed, len(run.Results))
	}
}
