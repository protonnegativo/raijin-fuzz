"""Checks that every ffuf result is in a raijin-fuzz result.

A result is one entry of ffuf's "results" (the -of json file) or one line of its -json stream (input
values in base64): its input, its URL, and what it answered: status, length, words, lines, content type
(without parameters; left out when text/html, "none" when empty) and redirect location.

A result is present when a finding or group lists its input (the value, or "K=v K2=v2" sorted by
keyword when ffuf fuzzed several keywords; followed by " @ <url>" when the output's "url" with the input
put in place of each keyword is not the result's URL) and has the same status, words, lines and type, the
same length (for a "reflected" entry: its length plus the input's length in bytes), and a redirect that
gives the result's Location once each keyword is replaced by the input. With no " @ <url>", the URL is
checked too: the output's "url" (or "target") with the input put in place of each keyword.

usage: python verify.py <ffuf.json> <raijin.json>
"""
import base64
import json
import sys

raw, out = sys.argv[1], sys.argv[2]
o = json.load(open(out))
template = o.get("url") or o.get("target", "")


def load(path):
    text = open(path, encoding="utf-8").read()
    try:
        doc = json.loads(text)
        if isinstance(doc, dict) and ("results" in doc or "config" in doc):
            return [clean(r, False) for r in doc.get("results") or []]
    except ValueError:
        pass
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        r = json.loads(line)
        if r.get("url"):
            results.append(clean(r, True))
    return results


def clean(r, b64):
    inp = {}
    for k, v in (r.get("input") or {}).items():
        if k == "FFUFHASH":
            continue
        if b64:
            try:
                v = base64.b64decode(v, validate=True).decode()
            except ValueError:
                pass
        inp[k] = v
    r["input"] = inp
    return r


def substitute(s, inp):
    for k in sorted(inp):
        s = s.replace(k, inp[k])
    return s


def written(inp):
    if len(inp) == 1:
        return next(iter(inp.values()))
    return " ".join(f"{k}={inp[k]}" for k in sorted(inp))


def ctype(ct):
    ct = (ct or "").split(";", 1)[0].strip().lower()
    if ct == "text/html":
        return ""
    return ct or "none"


index = {}
for kind in ("findings", "groups"):
    for x in o[kind]:
        for i in x.get("inputs", []):
            index.setdefault(i, []).append(x)


def present(r):
    inp = r["input"]
    key = written(inp)
    if not template or substitute(template, inp) != r["url"]:
        key += " @ " + r["url"]
    size = sum(len(v.encode()) for v in inp.values())
    for x in index.get(key, []):
        if (x["status"], x["words"], x["lines"], x.get("type", "")) != (r["status"], r["words"], r["lines"], ctype(r.get("content-type"))):
            continue
        if x["length"] + (size if x.get("reflected") else 0) != r["length"]:
            continue
        if substitute(x.get("redirect", ""), inp) != (r.get("redirectlocation") or ""):
            continue
        return True
    return False


results = load(raw)
miss = [r for r in results if not present(r)]
print(f"{len(results)} ffuf results, {len(miss)} missing from output", "truncated" if o.get("budget") else "")
for r in miss[:5]:
    print("  MISSING", r["url"], r["input"], r["status"], r["length"])
sys.exit(1 if miss else 0)
