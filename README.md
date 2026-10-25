# ⚡ Raijin Fuzz

**ffuf for AI agents: only responses that differ from the baseline (status, size, words, timing), with every input still listed and soft-404s collapsed into one group.**

`raijin-fuzz` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It runs [ffuf](https://github.com/ffuf/ffuf) underneath and returns the **Raijin Schema**: one compact JSON where results with the same response shape (status, size, words, lines) share one entry that lists every input, the shapes many inputs got (a soft-404, a catch-all page, a WAF block) are groups, and the shapes that differ from them are ranked findings: a `.git/HEAD` or a backup that answered 200 first, then 401/403, then redirects, errors and slow answers. Anything it had to cut is counted.

## Why not just run ffuf?

ffuf is built for people and pipelines. An agent pays for every byte it reads. Against a site that answers 200 to everything, ffuf's default matcher reports every word of the wordlist: its JSON repeats the URL, the host, the input, a hash, the duration and ten field names for each one, and its text output is one line per word, wrapped in terminal escape codes, after a banner, the config and a progress line rewritten many times a second. Filtering the noise with `-fs` does not work when the soft-404 echoes the path (each size is different), and `-ac` hides it without saying which inputs it hid.

Here is the same run, with the same results, read by an agent (tokens, `o200k_base`):

```
Noisy run: a catch-all soft-404, 242 words, 242 results
  raijin-fuzz          ▊                         962 tokens
  ffuf text            ███████▍                9,234 tokens
  ffuf text + stderr   ███████████████▉       20,004 tokens
  ffuf -of json        ██████████████████▋    23,477 tokens
  ffuf -json           ████████████████████   25,154 tokens

Findings run: a normal site, 27 results, 20 findings (7 high, 3 medium, 5 low, 5 info)
  raijin-fuzz          ██████                    969 tokens
  ffuf text            ██████▌                 1,043 tokens
  ffuf text + stderr   ████████████████████    3,213 tokens
  ffuf -of json        ██████████████████▊     3,013 tokens
  ffuf -json           █████████████████▏      2,746 tokens
```

raijin-fuzz reads **24×** fewer tokens than ffuf's JSON file (`-of json`) on the noisy run and **3.1×** fewer on the findings run. Each run's bars are drawn to scale against its largest output.

- **Nothing is lost.** Every result ffuf reported is in the output with its input, status, size, words, lines, content type and redirect. `bench/verify.py` checked all 269 ffuf results of both runs, and none were missing.
- **The noise is one entry.** 223 soft-404s that each have a different size are one group: `"length":145,"reflected":true`, each response is 145 bytes plus its input. 11 `.php` words blocked by the same 403 page are another. Every input is still listed.
- **The real targets come first.** A `.git/HEAD` and a `backup.zip` that answered 200 are high, a 401 API and a `server-status` 403 are medium, and redirects, 5xx and slow answers are low. Plain pages are info.
- **Output is bounded.** On a huge run, `--max-bytes` cuts the least important data first and counts every cut. ffuf's output grows with every result.
- **Details are one file away.** ffuf's full JSON file is saved to disk, and its path is in `raw`. It holds the config, the full URL of each result, the durations and ffuf's hashes, costs no tokens until the agent opens it, and replays with `--input`.

Against ffuf's text output (stdout only, what an agent gets with `2>/dev/null`), raijin-fuzz is **9.6×** smaller on the noisy run and **7%** smaller on the findings run: when every response is different there is little to collapse, and the IDs, severities and tags cost about what the escape codes and padding of the text lines cost. In exchange the agent gets the content type and redirect of each result (the text has neither), the findings ranked, and the soft-404s already separated from the real paths. Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-fuzz/cmd/raijin-fuzz@latest
```

You also need `ffuf` on `PATH`, or pass `--ffuf <path>`.

## Usage

```bash
raijin-fuzz --scope scope.txt                                  # fuzz every host the scope names
raijin-fuzz --scope scope.txt -u https://app.example.com/FUZZ -w words.txt
raijin-fuzz --scope scope.txt -u https://app.example.com/FUZZ -w words.txt --rate 50 --threads 10
raijin-fuzz --scope scope.txt --input ffuf-results.json          # reduce output you already have (-of json or -json)
raijin-fuzz --scope scope.txt -u https://app.example.com/FUZZ -w words.txt --state run.json   # mark findings that are new since last run
raijin-fuzz ... -- -e .php,.bak -H 'Cookie: session=...' -mc all  # anything after -- goes to ffuf
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!admin.example.com
```

With no `-u` or `--input`, raijin-fuzz fuzzes `https://<host>/FUZZ` for what the scope names: every domain, every IP, and every address of ranges up to a /24, minus exclusions, in one ffuf run with a second keyword (inputs read `FUZZ=admin HOST=example.com`). With no `-w` either, the wordlist is SecLists' `Discovery/Web-Content/common.txt` when it is found (`/usr/share/seclists`, `/usr/share/SecLists`, `/opt/SecLists`, `~/SecLists` or `~/tools/SecLists`), or else a built-in list of 100 common paths ([internal/ffuf/common.txt](internal/ffuf/common.txt)). A wildcard names no host and a larger range is too big to sweep blindly, so for each one `next` gives the command that enumerates it first (`raijin-subs` or `raijin-ports`).

A URL outside the scope is refused before ffuf runs (exit 1). Results outside the scope (a recursion that left the host) are dropped from the output and counted in `omitted.out_of_scope`.

**Matchers.** raijin-fuzz adds no matcher, filter or calibration of its own: without `--` options, ffuf runs with its default matcher, `-mc 200-299,301,302,307,401,403,405,500`, and every result it matched is in the output. A 404 that ffuf did not match is not a result, as in ffuf. When ffuf ran with any other matcher or a filter (`-- -mc all`, `-- -fs 42`, `-- -ac`), the result says so in `match` and `filter`, because those decide what ffuf reported. raijin-fuzz does not need `-ac` to separate the noise, and it does not hide which inputs got it.

**Failed requests.** ffuf's JSON has no record of the requests that failed (timeouts, refused connections). raijin-fuzz reads ffuf's error count from its progress line, and when it is not 0 the result has a `request_errors` error with the count: those inputs have no result.

## Output

```json
{
  "tool": "raijin-fuzz",
  "version": "0.1.0",
  "target": "bench/fixtures/noisy/raw.json",
  "summary": "241 results, 9 shapes: 7 findings (2 high, 2 medium, 1 low, 2 info), 2 groups (234 noise results)",
  "url": "http://127.0.0.1:19200/FUZZ",
  "findings": [
    {"id": "200-65b6cb8b", "severity": "high", "tags": ["file", "admin"], "status": 200, "length": 304, "words": 1, "lines": 1, "type": "application/zip", "inputs": ["backup.zip"]},
    {"id": "200-574007ba", "severity": "high", "tags": ["file"], "status": 200, "length": 21, "words": 2, "lines": 2, "type": "text/plain", "inputs": [".git/HEAD"]},
    {"id": "403-08bcd3ad", "severity": "medium", "tags": ["admin"], "status": 403, "length": 102, "words": 8, "lines": 2, "inputs": ["server-status"]},
    {"id": "401-e1ddb32f", "severity": "medium", "status": 401, "length": 24, "words": 1, "lines": 1, "type": "application/json", "inputs": ["api"]},
    {"id": "302-afc8700a", "severity": "low", "tags": ["admin"], "status": 302, "length": 0, "words": 1, "lines": 1, "type": "none", "redirect": "/login?next=/FUZZ", "inputs": ["admin"]},
    {"id": "200-7b67e176", "severity": "info", "status": 200, "length": 241, "words": 11, "lines": 7, "inputs": ["login"]},
    {"id": "200-dd3ba243", "severity": "info", "status": 200, "length": 31, "words": 3, "lines": 3, "type": "text/plain", "inputs": ["robots.txt"]}
  ],
  "groups": [
    {"id": "200-22d5174a", "status": 200, "length": 145, "reflected": true, "words": 11, "lines": 6, "inputs": [".env", ".git/config", ".htaccess", ".htpasswd", ".svn/entries", ".DS_Store", "..."]},
    {"id": "403-d6799e80", "status": 403, "length": 104, "words": 8, "lines": 2, "inputs": ["phpinfo.php", "index.php", "login.php", "admin.php", "config.php", "wp-login.php", "..."]}
  ],
  "omitted": {"duplicates": 1}
}
```

That is the real noisy run from the benchmark, replayed from its fixture and pretty-printed here. Two things are shortened: each entry is written on one line, and the groups list 6 of their 223 and 11 inputs (`"..."` is not in the output). The tool writes it all as one line. A live run also has `raw`, the path of ffuf's JSON file. Note the `.env` in the first group: on this site it is a soft-404 like the others, 149 bytes, and a finding only on a site where it answers something else.

`--format table` prints the same result for a person:

```
241 results, 9 shapes: 7 findings (2 high, 2 medium, 1 low, 2 info), 2 groups (234 noise results)
url      http://127.0.0.1:19200/FUZZ
HIGH     file,admin 200 size=304 words=1 lines=1 application/zip: backup.zip
HIGH     file 200 size=21 words=2 lines=2 text/plain: .git/HEAD
MEDIUM   admin 403 size=102 words=8 lines=2: server-status
MEDIUM   401 size=24 words=1 lines=1 application/json: api
LOW      admin 302 size=0 words=1 lines=1 none -> /login?next=/FUZZ: admin
INFO     200 size=241 words=11 lines=7: login
INFO     200 size=31 words=3 lines=3 text/plain: robots.txt
group    200 size=145+input words=11 lines=6 (223 inputs)
group    403 size=104 words=8 lines=2 (11 inputs)
```

**Nothing ffuf reported is dropped silently.** Every result is in exactly one finding or group. Only exact repeats (the same input with the same response, from a wordlist that lists a word twice) collapse, and they are counted in `omitted.duplicates`.

What the reducer does:

- **One entry per response shape.** A shape is the status, the size, the words, the lines, the content type and the redirect. Every input that got the same shape is in the same entry's `inputs`, in wordlist order. An input is the value ffuf put in place of `FUZZ`; the result's URL is `url` with the input in place of the keyword. With several keywords (`-w a.txt:FUZZ -w b.txt:EXT`) an input is `EXT=bak FUZZ=admin`, and a result whose URL is not `url` with its input (ffuf's recursion) is written `input @ <its URL>`.
- **Redirects** are written with the input as its keyword when the `Location` holds the result's URL or path: `admin` → `/admin/` is `"redirect":"/FUZZ/"`, and a catch-all that sends every path to `/login?next=/<path>` is one shape, `/login?next=/FUZZ`. Putting the input back gives the header ffuf saw; when it would not, the header is written as it is.
- **Reflected soft-404s.** A not-found page that echoes the path has a different size for each input. When at least `--noise` inputs (5 by default) have the same status, words, lines, type and redirect, and the same size once the length of the input (in bytes) is taken out, with at least two different sizes, they are one group with `"reflected":true`: each response is `length` plus the length of its input.
- **Noise.** A shape that at least `--noise` inputs got is a group: the baseline of the run (a soft-404, a catch-all page or redirect, a WAF block). A `.env` in that group is noise too: it got the same page as everything else. Every other shape is a finding. A redirect that adds a slash to the URL (`/FUZZ/`) is a directory, and stays a finding however many there are, unless the server does it for more than half of the inputs.
- **Slow** answers are timing outliers: a response that took at least 1 second and 5 times the median response time of the run is its own entry, tagged `slow`, with `ms`, the slowest time of the entry, even when it otherwise has the noise's shape.
- **Findings** are ranked by severity, then the number of tags, then the number of inputs, then the wordlist order, then `id`:

  | Severity | Rule |
  |---|---|
  | high | 2xx and the input is a `file` or `admin` name |
  | medium | 401, 403 or 407 |
  | low | 3xx, 5xx, or `slow` |
  | info | anything else: a plain 2xx, another 4xx (400, 405...) |

  Tags say what besides the status made it a finding. The status class is not a tag; the status is written.

  | Tag | Rule |
  |---|---|
  | `file` | A segment of the input has a backup, dump, config, archive, key or log extension (`.bak .old .orig .swp .sql .db .sqlite .dump .env .ini .conf .cfg .config .yml .yaml .toml .properties .log .zip .tar .gz .tgz .7z .rar .war .jar .pem .key .p12 .pfx ...`), ends in `~`, or is a dotfile (`.env`, `.git/HEAD`). |
  | `admin` | A segment of the input (without extension) is an admin, debug, internal, config or backup name: `admin*`, `wp-admin`, `debug`, `internal`, `private`, `actuator`, `console`, `manage`, `phpmyadmin`, `config`, `settings`, `backup`, `setup`, `install`, `server-status`, `metrics`, `env`, `dashboard`, `swagger`, `api-docs`, `graphiql`, `phpinfo`, `cgi-bin`, `test`, `dev`, `staging`, `old` and similar. |
  | `dir` | A redirect that adds a slash to the URL. |
  | `slow` | At least 1 second and 5 times the median response time. |

  The same shape splits by tags, so a `.env` and a plain page that happen to have the same size are never in the same finding.
- **Groups** are ranked by the number of inputs, then the wordlist order, then `id`.
- **`id`** is the status and a short hash of the shape and the tags, so the same shape has the same `id` in the next run.
- **`raw`** is ffuf's JSON file (`-of json`), saved to disk: the config, the full URL, host and duration of each result. `--raw <file>` picks the path. `--input` reads it, or ffuf's `-json` stream.
- **Budget:** `--max-bytes` (16,000 by default) keeps the output bounded on huge runs. It cuts in this order until the JSON fits:
  1. group inputs (each keeps its `count`);
  2. groups;
  3. the inputs of the lowest-ranked findings, each keeping one input plus its `count`;
  4. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **Errors** say what to try next. If ffuf is missing, the exit code is 2.

Fields an agent can rebuild are left out to save tokens:

- `type` (the content type, without `; charset=...`) is left out when it is `text/html`, and is `none` when the server sent none.
- `status`, `length`, `words` and `lines` are always written, because 0 is a real value.
- `tags`, `redirect`, `reflected` and `ms` are left out when empty.
- `count` appears only when the budget cut `inputs`.
- `confidence` appears only when it is not `matched`; no fuzz rule sets it.
- `url` is left out when it is the `target`; `match` and `filter` are left out when ffuf ran with its default matcher and no filter.
- `omitted`, `errors` and `next` appear only when they are not empty, and `budget` only when something was cut.

The JSON is compact (one line) by default because indentation costs 76% to 81% more tokens in the benchmark; `--pretty` indents it. `--format table` prints a short human view of the same result; it lists finding inputs but only counts group inputs.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-u` / `-w` / `--input` | `https://<host>/FUZZ` for every host the scope names / SecLists `common.txt`, else a built-in list | URL with `FUZZ` / wordlist / existing ffuf JSON file or `-json` stream |
| `--noise` | 5 | inputs with the same shape that make it noise (a group) |
| `--rate`, `--threads`, `--timeout` | | ffuf `-rate` / `-t` / `-timeout` |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 16000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save ffuf's JSON file |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--ffuf` | ffuf | path to the binary |
| `--banner` | false | print the banner to stderr |

## Engine versions

The ffuf version raijin-fuzz is tested with is in [engines.json](engines.json), built into the binary. When the installed ffuf has another major version or an older one, the output says so in `errors` (`engine_version`, with the install command); when ffuf's results lack the fields raijin-fuzz reads (`url`, `status`), it reports `engine_format` and counts them in `omitted.unparsed`. Neither changes the exit code. A weekly GitHub Actions job runs the live benchmark with the latest ffuf and opens a PR to bump engines.json when it passes, or an `engine-drift` issue when it breaks.

## Development

```bash
go test ./...
go vet ./...
bench/run.sh            # replay bench/fixtures and count tokens
LIVE=1 bench/run.sh     # start the local lab, fuzz it again, refresh the fixtures
```

Standard library only. ffuf runs as a subprocess with `-of json -o <raw> -noninteractive`, so the binary stays small and ffuf can be updated on its own. Its text output is discarded; its stdin is `/dev/null`.

## Responsible use

Only fuzz what you are authorized to test, and keep the rate low enough for the target.
