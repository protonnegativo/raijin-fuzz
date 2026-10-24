#!/usr/bin/env bash
# Reproducible token benchmark: ffuf output vs raijin-fuzz output on the same run.
#
# usage: bench/run.sh [workdir]
#        LIVE=1 bench/run.sh [workdir]   start the local lab, fuzz it again and refresh bench/fixtures first
# needs: go, python3 with tiktoken (pip install tiktoken); LIVE=1 also needs ffuf
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>, FFUF=<path>
#
# Safety: LIVE=1 fuzzes only the lab it starts itself (bench/lab.py) on 127.0.0.1, ports 19200 and
# 19201, with the 242-line bench/wordlist.txt at 100 requests per second and 5 threads. It stops the lab
# when it exits. A live run takes about 20 seconds.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
FFUF=${FFUF:-ffuf}
mkdir -p "$W"
echo "workdir: $W"

# Lab: one python process with two sites (see lab.py).
# noisy:    a catch-all that answers 200 with a soft-404 page echoing the path, and the same 403 page
#           to every unknown .php; a few real paths (.git/HEAD, backup.zip, /admin, /login, a 401, a 403).
# findings: a normal site (unknown paths are 404) with directories, an .env, .git/config, backups, a
#           config .bak, phpinfo, swagger.json, a 401, three 403s, a 302, a 500 and a slow page.
declare -A port=([noisy]=19200 [findings]=19201)
printf '127.0.0.1\n' > "$W/scope.txt"

(cd "$ROOT" && go build -o "$W/raijin-fuzz" ./cmd/raijin-fuzz)

if [ "${LIVE:-}" = 1 ]; then
  for p in "${port[@]}"; do
    if ss -ltn | grep -q ":$p "; then echo "port $p is busy; free it first" >&2; exit 1; fi
  done
  python3 "$HERE/lab.py" "${port[noisy]}=catchall" "${port[findings]}=app" > "$W/lab.log" 2>&1 &
  echo $! > "$W/pids"
  trap '[ -f "$W/pids" ] && xargs kill < "$W/pids" 2>/dev/null || true' EXIT
  # wait until both sites listen: a request sent before that is a failed request, not a result
  for _ in $(seq 50); do
    up=0
    for p in "${port[@]}"; do ss -ltn | grep -q "127.0.0.1:$p " && up=$((up + 1)); done
    [ "$up" = "${#port[@]}" ] && break
    sleep 0.2
  done
  for name in noisy findings; do
    f=bench/fixtures/$name
    u=http://127.0.0.1:${port[$name]}/FUZZ
    mkdir -p "$ROOT/$f"
    # raijin-fuzz runs ffuf (-of json -o <raw> -s -noninteractive) and keeps its JSON file as raw: that
    # file is the fixture. Paths are relative to the repo so the fixture holds no local paths.
    (cd "$ROOT" && "$W/raijin-fuzz" --ffuf "$FFUF" --scope "$W/scope.txt" -u "$u" -w bench/wordlist.txt \
      --rate 100 --threads 5 --raw "$f/raw.json" > "$W/$name.live.json")
    # ffuf as an agent would run it, with the same options: the -json stream (one JSON line per result,
    # input values in base64) and the default text (one line per result on stdout; banner, config and
    # progress on stderr).
    run=(-u "$u" -w bench/wordlist.txt -rate 100 -t 5 -noninteractive)
    (cd "$ROOT" && "$FFUF" "${run[@]}" -json > "$f/ffuf.jsonl" 2> /dev/null)
    (cd "$ROOT" && "$FFUF" "${run[@]}" > "$f/text.txt" 2> "$f/text_stderr.txt")
    # ffuf writes the wordlist as an absolute path in its config and banner; keep the fixtures free of
    # local paths. Results are untouched.
    sed -i "s#$ROOT/##g" "$ROOT/$f/raw.json" "$ROOT/$f/text_stderr.txt"
  done
fi

scenario() {
  local name=$1
  local f=$HERE/fixtures/$name o=$W/$name
  mkdir -p "$o"
  # raijin-fuzz replays raw with --input, so every row sees the same run.
  (cd "$ROOT" && "$W/raijin-fuzz" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.json") > "$o/raijin.json"
  (cd "$ROOT" && "$W/raijin-fuzz" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.json" --pretty) > "$o/raijin_pretty.json"
  (cd "$ROOT" && "$W/raijin-fuzz" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.json" --format table) > "$o/raijin_table.txt"
  (cd "$ROOT" && "$W/raijin-fuzz" --scope "$W/scope.txt" --input "bench/fixtures/$name/ffuf.jsonl") > "$o/raijin_jsonl.json"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  python3 "$HERE/verify.py" "$f/raw.json" "$o/raijin.json"
  printf 'separate ffuf runs: -json '; python3 "$HERE/verify.py" "$f/ffuf.jsonl" "$o/raijin_jsonl.json"
  echo "text: $(grep -c 'Status:' "$f/text.txt") result lines"
  "$PY" "$HERE/count_tokens.py" \
    "ffuf -of json=$f/raw.json" \
    "ffuf -json=$f/ffuf.jsonl" \
    "ffuf text (stdout+stderr)=$f/text.txt+$f/text_stderr.txt" \
    "ffuf text (stdout)=$f/text.txt" \
    "raijin-fuzz JSON (default)=$o/raijin.json" \
    "raijin-fuzz --pretty=$o/raijin_pretty.json" \
    "raijin-fuzz --format table=$o/raijin_table.txt"
}

scenario noisy
scenario findings
