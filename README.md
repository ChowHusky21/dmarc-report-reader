# dmarc-report-reader

A small command-line tool, written in Python with only the standard library, that turns DMARC aggregate reports into a plain-language summary and checks a domain's SPF, DKIM and DMARC records before a policy change. Written and tested on macOS.

## Why
Mail providers send DMARC aggregate reports every day. They are XML, built for machines, and easy to ignore. This tool makes them readable so the early warning they carry is not wasted.

## What it does
**Version 1: read reports.** Accepts .xml, .zip or .gz files and prints: the reporting period in UTC and Pacific time; each sending server with its DKIM and SPF results (using the receiver's own DMARC evaluation); an optional forward-confirmed reverse-DNS check for each server (`--rdns`); and a pass/fail total.

**Version 2: check records.** `--dns DOMAIN[:SELECTOR]` checks that there is exactly one SPF record ending in `~all` or `-all`, that a DKIM key is published at the selector (with a rough key size), and that there is exactly one DMARC record, showing its policy and report address. The selector defaults to `google`.

## Usage
```
python3 dmarc_read_v2.py [--rdns] FILE [FILE ...]
python3 dmarc_read_v2.py --dns DOMAIN[:SELECTOR]
```
`dmarc_read_v1.py` is the original version 1 (report reader only), kept for reference. `dmarc_read_v2.py` is the current version.

## Sample output
Made-up report, placeholder values only (`sample_report.xml`):
```
$ python3 dmarc_read_v2.py sample_report.xml
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
- Domain and selector must match a strict pattern, so something like `evil.com;rm` is refused before anything runs.
- `dig` is called with separate arguments, never through a shell, and its output is only parsed, never executed.

## How it was tested
- Run on three real daily reports (identifying details not published); output checked field by field against the raw XML, and timestamps checked with macOS `date`.
- The DNS check was run on a real domain; an injection-style name was refused; version 1 features were re-tested after version 2 was added.
- Two real bugs were caught during the build: a top-level line pasted with an indent (Python accepted it; it would only have failed when `--dns` ran, so a clean syntax check is not proof of correct logic), and two lines joined by a paste followed by an auto-indent slip that Python reported as an IndentationError naming the exact line.

## Limits
- `--dns` needs macOS's built-in `dig`; `--rdns` needs network access.
- The SPF check looks for exactly one record ending in `~all` or `-all`; it does not follow `include:` or `redirect=` or count DNS lookups.
- The DKIM key size is an estimate from the key's length.
- Only the first .xml file inside a zip is read.

## AI-use disclosure
I built this with help from an AI assistant, which drafted the code. I set up the environment, typed and ran the script, tested it, and checked its output against my own reading of the raw XML.

## License
MIT. See [LICENSE](LICENSE).
