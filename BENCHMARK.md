# Token benchmark: ffuf vs raijin-fuzz

How many tokens does an AI agent spend reading the result of a fuzzing run, and does it lose anything? This benchmark fuzzes a local lab with ffuf, counts the tokens in each output shape, and checks that every ffuf result is in the raijin-fuzz output.

Reproduce: `bench/run.sh` replays the saved runs in `bench/fixtures`. `LIVE=1 bench/run.sh` starts the lab, fuzzes it again and refreshes the fixtures first (about 20 seconds; set `FFUF=<path>` if ffuf is not on `PATH`). A live run gives the same results; the durations, ffuf's hashes and the number of progress lines on stderr change from run to run, so the token counts move by a few dozen.

## Setup

- **Lab:** `bench/lab.py`, one Python process serving two sites on `127.0.0.1`.
  - **noisy** (`catchall`, port 19200): answers 200 to every path it does not know, with a "not found" page that echoes the path, so each soft-404 has a different size (145 bytes plus the input). Every unknown `.php` gets the same 403 block page. Real paths: `/.git/HEAD`, `/backup.zip`, `/robots.txt`, `/login`, `/admin` (302 to `/login?next=/admin`), `/api` (401) and `/server-status` (its own 403).
  - **findings** (`app`, port 19201): a normal site, unknown paths are 404. Real paths: 7 directories that redirect to add a slash, `/.env`, `/.git/config`, `/backup.sql`, `/backup.tar.gz`, `/config.php.bak`, `/phpinfo.php`, `/swagger.json`, `/api` (401), `/.htaccess`, `/.htpasswd` and `/server-status` (403), `/dashboard` (302 to `/login`), `/debug` (500), `/report` (200 after 1.5 s) and plain pages.
- **Wordlist:** `bench/wordlist.txt`, 242 lines: 41 sensitive or real names and 200 common directory names, and `admin` a second time at the end, as wordlists often repeat a word.
- **ffuf:** v2.1.0, `-rate 100 -t 5`, default matcher (`-mc 200-299,301,302,307,401,403,405,500`), no filter, no calibration.
- **raijin-fuzz:** runs ffuf itself (`-u <url> -w bench/wordlist.txt -of json -o <raw> -noninteractive -rate 100 -t 5`) and saves its JSON file as `raw`: that file is the fixture (`raw.json`). ffuf writes the wordlist as an absolute path in the file's config and in its stderr banner; `bench/run.sh` rewrites it relative to the repo, so the fixtures hold no local paths. Results are untouched. Defaults apply: no limit on findings, `--noise 5`, and `--max-bytes 16000`, which was not reached. All raijin-fuzz rows replay `raw.json` with `--input`, so they see the same run.
- **Baselines**, as an agent would run ffuf, with the same options:
  - `ffuf -of json`: ffuf's JSON file, the `raw` fixture.
  - `ffuf -json`: ffuf's JSON stream on stdout, one line per result, input values in base64. A separate live run, saved as `ffuf.jsonl`; it found the same results (`bench/run.sh` verifies it too).
  - Text: ffuf's default output, one line per result on stdout (with `\r`, an erase-line escape code and a color reset on each line), and the banner, the config and the progress line on stderr. A separate live run, saved as `text.txt` and `text_stderr.txt`; it found the same number of results. Both stdout alone (`2>/dev/null`) and stdout plus stderr are counted.
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy

242 results, one of them the repeated `admin`. raijin-fuzz returned 241 results in 9 shapes: 7 findings and 2 groups.

- high: `backup.zip` (200, application/zip) and `.git/HEAD` (200, text/plain);
- medium: `server-status` (403, not the WAF page) and `api` (401);
- low: `admin` (302 to `/login?next=/FUZZ`);
- info: `login` and `robots.txt`;
- groups: the soft-404, 223 inputs in one entry with `"length":145,"reflected":true` (each response is 145 bytes plus its input), and the WAF 403, 11 `.php` inputs. `.env`, `.git/config`, `backup.sql` and the other sensitive names are in the soft-404 group: on this site they got the same page as everything else.

| Output | Bytes | Tokens | vs. ffuf -of json |
|---|---:|---:|---:|
| ffuf `-json` | 70,842 | 25,154 | 0.9× |
| ffuf `-of json` | 70,586 | 23,477 | 1× |
| ffuf text (stdout+stderr) | 47,769 | 20,004 | 1.2× |
| ffuf text (stdout) | 22,723 | 9,234 | 2.5× |
| **raijin-fuzz JSON (default)** | 3,539 | **962** | **24×** |
| raijin-fuzz `--pretty` | 6,558 | 1,744 | 13× |
| raijin-fuzz `--format table` | 683 | 232 | 101× |

## Scenario 2: findings

27 results, one of them the repeated `admin`. raijin-fuzz returned 26 results in 20 shapes: 20 findings and no groups (no shape reached `--noise`).

- high: `.git/config`, `backup.sql`, `backup.tar.gz`, `config.php.bak`, `.env`, `phpinfo.php` and `swagger.json`, all 200;
- medium: `.htaccess` and `.htpasswd` (one entry, same 403), `server-status` (403) and `api` (401);
- low: the directories `admin` and `backup`, the directories `uploads`, `images`, `css`, `js` and `static` (both `"redirect":"/FUZZ/"`, split by the `admin` name tag), `dashboard` (302), `debug` (500) and `report` (slow, 1,502 ms);
- info: `login`, `robots.txt`, `about`, `contact` and `index.html`.

| Output | Bytes | Tokens | vs. ffuf -of json |
|---|---:|---:|---:|
| ffuf text (stdout+stderr) | 7,686 | 3,213 | 0.9× |
| ffuf `-of json` | 9,225 | 3,013 | 1× |
| ffuf `-json` | 7,667 | 2,746 | 1.1× |
| ffuf text (stdout) | 2,492 | 1,043 | 2.9× |
| **raijin-fuzz JSON (default)** | 3,037 | **969** | **3.1×** |
| raijin-fuzz `--pretty` | 5,277 | 1,701 | 1.8× |
| raijin-fuzz `--format table` | 1,380 | 455 | 6.6× |

In a live run (not a replay) the raijin-fuzz JSON also has `raw`, the path of ffuf's saved JSON file, and its `target` is the URL (so `url` is left out): a few tokens either way.

## Nothing is lost

For each scenario, `bench/verify.py` checks every ffuf result (an entry of `results` in the `-of json` file, or a line of the `-json` stream) against the raijin-fuzz output. A result is its input, its URL, and what it answered: status, length, words, lines, content type (without parameters) and redirect location. A result is present when a finding or group lists its input, and has the same status, words, lines and type, the same length (for a `reflected` entry, its `length` plus the input's length in bytes), and a `redirect` that gives the result's `Location` once `FUZZ` is replaced by the input. The URL is checked too: the output's `url` with the input in place of `FUZZ` must be the result's URL, or the input is written `input @ <url>`.

- Scenario 1: 242 results (`-of json`) and 242 (`-json`), **0 missing**.
- Scenario 2: 27 results (`-of json`) and 27 (`-json`), **0 missing**.

The repeated `admin` is one of those results: it is present because the first `admin` is, with the same response, and it is counted in `omitted.duplicates`.

The check fails when it should: with `cart` taken out of the soft-404 group's inputs, it reports `http://127.0.0.1:19200/cart` missing; with the group's `length` changed from 145 to 146, it reports all 223 of its results missing.

What the JSON leaves out stays in ffuf's JSON file, which raijin-fuzz saves to disk and points to in `raw`: the config, the host and full URL of each result, the response times (except for slow outliers), ffuf's per-request hashes and the scraper and result-file fields.

## Reading the numbers

- **Against ffuf's JSON** (`-of json` or `-json`), the structured output an agent would parse, raijin-fuzz uses **24×** (`-json`: 26×) fewer tokens on the noisy run and **3.1×** (`-json`: 2.8×) fewer on the findings run. The gap grows with noise: 223 soft-404s cost one entry and one word each.
- **Against ffuf's text output**, the result depends on the run and on stderr:
  - noisy: **9.6× smaller** than stdout alone (9,234 → 962) and **21× smaller** than stdout plus stderr;
  - findings: **7% smaller** than stdout alone (1,043 → 969) and **3.3× smaller** than stdout plus stderr.

  When every response is different there is little to collapse, and raijin-fuzz's IDs, severities and tags cost about what the escape codes and column padding of the text lines cost. In exchange the agent gets what the text does not have at all: the content type and the redirect of each result (`/admin` → `/FUZZ/` is a directory, `/dashboard` → `/login` is behind a login), the findings ranked, and on the noisy run the soft-404s already separated from the real paths. The text reports `.env`, `.git/HEAD` and `backup.zip` the same way: one line each with a status 200 and a size.
- **The output stays bounded.** On a run too big for `--max-bytes`, raijin-fuzz cuts the least important data first: group inputs, then groups, then extra inputs of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. Raw ffuf output has no upper bound.

## How the default output got here

One change before the numbers above, measured on the same fixtures (o200k tokens):

| Tags | Scenario 1 | Scenario 2 |
|---|---:|---:|
| Status class as a tag too (`ok`, `redirect`, `auth`, `client`, `error`) | 985 | 1,027 |
| **Only what the status does not say** (`file`, `admin`, `dir`, `slow`; current) | **962** | **969** |

The status class is derivable from `status`, so it was dropped from `tags`.
