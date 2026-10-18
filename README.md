# dmarc-report-reader

A small command-line tool, written in Python, that turns DMARC aggregate reports into a plain-language summary, says whether a domain looks ready for a stricter policy, and checks the domain's SPF, DKIM and DMARC records. Written and tested on macOS. Version 3 needs one third-party package, `defusedxml` (see Setup).

## Why
Mail providers send DMARC aggregate reports every day. They are XML, built for machines, and easy to ignore. This tool makes them readable so the early warning they carry is not wasted.

## What it does
**Version 1: read reports.** Accepts .xml, .zip or .gz files and prints the reporting period in UTC and Pacific time, each sending server with its DKIM and SPF results (using the receiver's own DMARC evaluation), an optional forward-confirmed reverse-DNS check (`--rdns`), and a pass/fail total.

**Version 2: check records.** `--dns DOMAIN[:SELECTOR]` checks for exactly one SPF record ending in `~all` or `-all`, a published DKIM key at the selector (with a rough key size), and exactly one DMARC record. The selector defaults to `google`.

**Version 3: readiness verdict.**
- `--summary` rolls every report into one view: each sending server once, with message counts, how many passed, and whether it is on your known-senders list.
- The verdict is NOT READY if any message failed DMARC or any sender is unknown. If everything passes but there are fewer than 14 days of reports, it says NOT READY YET. Only after 14 clean days does it say the domain is ready to move to `p=quarantine`, starting at `pct=25`.
- `--dns DOMAIN --authoritative` asks the domain's own name servers instead of a resolver, so you see what the authoritative servers publish.
- Proper command-line handling (`argparse`, `--help`, `--version`) and exit codes: 0 everything passed, 1 something needs attention, 2 usage error.
- Reports are parsed with `defusedxml`, a hardened XML parser, because report files come from outside.
- Reverse-DNS lookups run in parallel with an overall 8-second limit.

## Setup
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
Keep your known senders in `known_senders.txt` beside the script (one domain per line). Check each sender before adding it.

## Usage
```
python3 dmarc_read_v3.py --summary FILE [FILE ...]
python3 dmarc_read_v3.py [--rdns] FILE [FILE ...]
python3 dmarc_read_v3.py --dns DOMAIN[:SELECTOR] [--authoritative]
```
`dmarc_read_v1.py` is the original version 1 and `dmarc_read_v2.py` is version 2 (standard library only), both kept for reference. `dmarc_read_v3.py` is the current version.

## Sample output
Made-up report, placeholder values only (`sample_report.xml`):
```
$ python3 dmarc_read_v3.py sample_report.xml
============================================================
File:     sample_report.xml
Reporter: receiver.example.net  ID [redacted]
From:     2026-10-13 00:00 UTC (2026-10-12 17:00 PT)
To:       2026-10-13 23:59 UTC (2026-10-13 16:59 PT)
Policy:   example.com  p=none  pct=100

  Source 192.0.2.10  messages=2  DMARC=PASS  (dkim=pass, spf=pass, action=none)
    Header From: example.com
    DKIM example.com: pass  selector=[redacted]
    SPF  example.com: pass

  Source 192.0.2.77  messages=1  DMARC=PASS  (dkim=pass, spf=fail, action=none)
    Header From: example.com
    DKIM example.com: pass  selector=[redacted]
    SPF  example.com: fail

Total: 3 message(s), 3 passed DMARC, 0 failed
```
The second source shows the common case that looks alarming but is not: SPF fails after a forwarding service re-sends a message, while DKIM survives and DMARC still passes.

## Security design
- Files over 10 MB are refused (zip-bomb guard); a bad file gives a one-line error, not a crash.
- Report XML is parsed with `defusedxml` 0.7.1 so crafted XML (entity expansion and similar) is rejected.
- Domain and selector must match a strict pattern, and name servers are checked against it before use, so something like `evil.com;rm` is refused before anything runs.
- `dig` is called with separate arguments, never through a shell, and its output is only parsed, never executed.

## How it was tested
- Run on three real daily reports (identifying details not published); output checked field by field against the raw XML, and timestamps checked with macOS `date`.
- Version 3 adds six tested parts (parsing, reverse DNS, known senders, summary and verdict, DNS check, command-line handling).
- On my real domain's reports so far: 6 days, 4 messages, 100% passed, verdict NOT READY YET because it needs 14 days.
- Two real bugs were caught during the version 2 build: a top-level line pasted with an indent (Python accepted it; it would only have failed when `--dns` ran, so a clean syntax check is not proof of correct logic), and two lines joined by a paste followed by an auto-indent slip that Python reported as an IndentationError naming the exact line.

## Limits
- `--dns` needs macOS's built-in `dig`; `--rdns` and `--summary` need network access for reverse DNS.
- The SPF check looks for exactly one record ending in `~all` or `-all`; it does not follow `include:` or `redirect=` or count DNS lookups.
- The DKIM key size is an estimate from the key's length.
- Only the first .xml file inside a zip is read.
- The readiness verdict is a guide, not a guarantee: check each unknown sender yourself before changing policy.

## AI-use disclosure
I built this with help from an AI assistant, which drafted the code. I set up the environment, typed and ran the script, tested it, and checked its output against my own reading of the raw XML.

## License
MIT. See [LICENSE](LICENSE).
