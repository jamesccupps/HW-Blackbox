"""VirusTotal's verdict on a release's files, for .github/workflows/virustotal.yml. Standard library only.

  scan FILE... [--line OUT]   each file looked up by its SHA-256 (a re-run, or a release already out, uploads
                              nothing); one VirusTotal hasn't seen is uploaded and its analysis waited for. The report
                              goes to the run's summary ($GITHUB_STEP_SUMMARY) and the log; with --line, one line for
                              the release notes, written only when every file was scanned and no major engine flags it.
                              Exit 1 when a major engine (MAJOR) calls a file malicious or suspicious: don't publish it.
                              Other engines' flags are warnings: a few small ones flag new, clean programs now and then.
  notes NOTES LINE            puts LINE into the notes file under "Check the download" (replacing an earlier one),
                              and makes sure the updater still reads the same "SHA-256: `...`" from them.

The key is $VT_API_KEY, never printed. A free key allows 4 requests a minute and 500 a day: requests here are at least
16 s apart. Files sent are shared with VirusTotal's subscribers: send only release files, which are public anyway."""
import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui/file/"
SMALL = 32 << 20        # bigger files go to an upload URL from /files/upload_url (up to 650 MB)
GAP = 16                # seconds between requests: under the free key's 4 a minute
WAIT = 25 * 60          # how long to wait for an analysis
# The engines most of the people who download it run (Windows' own first): one of them flagging a file means users
# would see it blocked or quarantined.
MAJOR = ("Microsoft", "ESET-NOD32", "Kaspersky", "BitDefender", "Avast", "AVG", "Sophos", "Symantec", "TrendMicro",
         "Malwarebytes")
FLAGS = ("malicious", "suspicious")
SCANNED = FLAGS + ("undetected", "harmless")
MARK = "VirusTotal, "   # the notes line starts with it
UPDATER_SHA = re.compile(r"SHA-256:\s*`([0-9a-fA-F]{64})`")   # as hwblackbox/update.py reads the notes

_last = [0.0]


def call(method, url, data=None, ctype=None, missing_ok=False):
    """One request, spaced GAP apart; a 429 or a server error waits a minute and tries again (5 times)."""
    headers = {"x-apikey": os.environ["VT_API_KEY"], "accept": "application/json"}
    if ctype:
        headers["content-type"] = ctype
    for attempt in range(6):
        pause = _last[0] + GAP - time.monotonic()
        if pause > 0:
            time.sleep(pause)
        _last[0] = time.monotonic()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=data, method=method, headers=headers),
                                        timeout=600) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            if e.code == 404 and missing_ok:
                return None
            if e.code in (429, 500, 502, 503, 504) and attempt < 5:
                print("VirusTotal: HTTP %d, trying again in a minute" % e.code, flush=True)
                time.sleep(60)
                continue
            # (the path only: an upload URL carries a token in its query)
            raise SystemExit("VirusTotal: %s %s: HTTP %d %s" % (method, url.split("?")[0], e.code,
                                                               e.read()[:300].decode("utf-8", "replace")))


def multipart(name, blob):
    b = uuid.uuid4().hex
    head = ('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n' % (b, name)).encode()
    return head + blob + ("\r\n--%s--\r\n" % b).encode(), "multipart/form-data; boundary=" + b


def verdict(path):
    """{name, sha, results (engine: {category, result}) or None if the analysis didn't finish, uploaded}."""
    with open(path, "rb") as f:
        blob = f.read()
    sha = hashlib.sha256(blob).hexdigest()
    v = {"name": os.path.basename(path), "sha": sha, "results": None, "uploaded": False}
    known = call("GET", API + "/files/" + sha, missing_ok=True)
    if known and known["data"]["attributes"].get("last_analysis_results"):
        v["results"] = known["data"]["attributes"]["last_analysis_results"]
        return v
    url = call("GET", API + "/files/upload_url")["data"] if len(blob) > SMALL else API + "/files"
    body, ctype = multipart(v["name"], blob)
    aid = call("POST", url, body, ctype)["data"]["id"]
    v["uploaded"] = True
    print("%s: uploaded, waiting for the analysis" % v["name"], flush=True)
    deadline = time.monotonic() + WAIT
    while time.monotonic() < deadline:
        a = call("GET", API + "/analyses/" + aid)["data"]["attributes"]
        if a.get("status") == "completed":
            v["results"] = a.get("results") or {}
            return v
        time.sleep(30)
    return v


def tally(results):
    """(engines that scanned it, [(engine, category, result)] flagging it, [the major ones among them])."""
    scanned = sum(1 for r in results.values() if r.get("category") in SCANNED)
    flagged = sorted((name, r.get("category"), r.get("result") or "") for name, r in results.items()
                     if r.get("category") in FLAGS)
    major = [f for f in flagged if f[0].lower() in {m.lower() for m in MAJOR}]
    return scanned, flagged, major


def scan(files, line_path):
    report = ["## VirusTotal", "", "| File | Engines flagging it | SHA-256 |", "|---|---|---|"]
    details, parts, failed, unfinished = [], [], False, False
    for path in files:
        v = verdict(path)
        link = GUI + v["sha"]
        if v["results"] is None:
            unfinished = True
            print("::warning::%s: VirusTotal's analysis didn't finish in %d minutes; see %s" % (v["name"], WAIT // 60, link))
            report.append("| [%s](%s) | not finished | `%s` |" % (v["name"], link, v["sha"]))
            continue
        scanned, flagged, major = tally(v["results"])
        print("%s: %d of %d engines flag it (%s) %s" % (v["name"], len(flagged), scanned,
                                                       "uploaded" if v["uploaded"] else "known already", link))
        report.append("| [%s](%s) | %d of %d | `%s` |" % (v["name"], link, len(flagged), scanned, v["sha"]))
        parts.append("[%s: %d of %d engines flag it](%s)" % (v["name"], len(flagged), scanned, link))
        if flagged:
            details += ["", "### %s" % v["name"], "", "| Engine | Says | Detection |", "|---|---|---|"]
            details += ["| %s%s | %s | `%s` |" % (n, " (major)" if (n, c, d) in major else "", c, d) for n, c, d in flagged]
        for n, c, d in flagged:
            if (n, c, d) in major:
                failed = True
                print("::error::%s: %s says %s (%s). Don't publish it: see %s" % (v["name"], n, c, d, link))
            else:
                print("::warning::%s: %s says %s (%s), a small engine; see %s" % (v["name"], n, c, d, link))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("\n".join(report + details) + "\n")
    if line_path and not failed and not unfinished:
        with open(line_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(MARK + "scanned when this was released: " + ", ".join(parts) + ".\n")
    return 1 if failed else 0


def into_notes(text, line):
    """The notes with line under "### Check the download" (at its end), an earlier VirusTotal line taken out; at the
    end of the notes if there's no such heading. ValueError if the updater would then read another SHA-256."""
    out = []
    for ln in text.split("\n"):
        if ln.startswith(MARK):
            if out and not out[-1].strip():
                out.pop()
            continue
        out.append(ln)
    heads, fenced = [], False
    for i, ln in enumerate(out):
        if ln.lstrip().startswith("```"):
            fenced = not fenced
        elif ln.startswith("#") and not fenced:
            heads.append(i)
    start = next((i for i in heads if out[i].lstrip("#").strip().lower() == "check the download"), None)
    end = next((i for i in heads if start is not None and i > start), len(out))
    while end > 0 and not out[end - 1].strip():
        end -= 1
    out[end:end] = ["", line.strip()]
    if end + 2 < len(out) and out[end + 2].strip():
        out.insert(end + 2, "")
    new = "\n".join(out)
    if not new.endswith("\n"):
        new += "\n"
    before, after = UPDATER_SHA.search(text), UPDATER_SHA.search(new)
    if (before and before.group(1)) != (after and after.group(1)):
        raise ValueError("the notes' SHA-256 for the updater would change")
    return new


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("files", nargs="+")
    s.add_argument("--line")
    n = sub.add_parser("notes")
    n.add_argument("notes")
    n.add_argument("line")
    a = ap.parse_args(argv)
    if a.cmd == "scan":
        if not os.environ.get("VT_API_KEY"):
            raise SystemExit("VT_API_KEY isn't set (the repository secret)")
        return scan(a.files, a.line)
    with open(a.notes, encoding="utf-8") as f:
        text = f.read()
    with open(a.line, encoding="utf-8") as f:
        line = f.read()
    with open(a.notes, "w", encoding="utf-8", newline="\n") as f:
        f.write(into_notes(text, line))
    return 0


if __name__ == "__main__":
    sys.exit(main())
