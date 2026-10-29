#!/usr/bin/env python3
"""dmarc_read_v4.py - read DMARC aggregate reports, decide whether a domain
is ready for its next, stricter DMARC policy step, and check its SPF, DKIM and
DMARC records.
Version 4.0 (2026-10-28): files new reports from a folder (--file, dry run
unless --yes), keeps a history file, and flags senders never seen before.
Version 3.1: skips duplicate reports, shows which days have reports, and gives
a verdict for the next step after the policy now published.
Needs defusedxml 0.7.1 for reading reports;
the DNS check uses macOS's built-in dig.
Exit codes: 0 = everything passed, 1 = something needs attention, 2 = usage error.
"""
import argparse
import base64
import gzip
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree.ElementTree import ParseError
from zoneinfo import ZoneInfo


try:
    import defusedxml.ElementTree as SafeET  # hardened parser for untrusted XML
except ImportError:
    SafeET = None

PT = ZoneInfo("America/Los_Angeles")
MAX_BYTES = 10 * 1024 * 1024    # refuse anything over 10 MB unpacked
LOOKUP_TIMEOUT = 8              # seconds to wait for all reverse-DNS lookups
MIN_DAYS = 14                   # days of clean reports before tightening policy
NAME_OK = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
DEFAULT_KNOWN = Path(__file__).with_name("known_senders.txt")


REPORT_NAME = re.compile(r"[^!/]+![^!/]+!\d+!\d+(\s*\(\d+\))?(\.xml)?\.(zip|gz|xml)")
SAFE_TEXT = re.compile(r"[^A-Za-z0-9 .-]")
# Everything a damaged or hostile report file can raise while being read (4.0).
READ_ERRORS = (OSError, EOFError, ValueError, ParseError, AttributeError, TypeError,
               zipfile.BadZipFile)


# ---------------------------------------------------------------- Part B
def load_xml(path):
    """Return the report's XML text, never reading more than MAX_BYTES."""
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.filename.endswith(".xml"):
                    with zf.open(info) as f:
                        data = f.read(MAX_BYTES + 1)
                    break
            else:
                raise ValueError("no .xml file inside the zip")
    elif path.endswith(".gz"):
        with gzip.open(path) as gz:
            data = gz.read(MAX_BYTES + 1)
    else:
        with open(path, "rb") as f:
            data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("file is too large")
    return data.decode("utf-8")


def parse_report(path):
    """Turn one report into plain data: no printing here."""
    if SafeET is None:
        raise ValueError("defusedxml is not installed (pip install defusedxml==0.7.1)")
    root = SafeET.fromstring(load_xml(path))
    meta = root.find("report_metadata")
    rng = meta.find("date_range")
    pol = root.find("policy_published")
    records = []
    for rec in root.findall("record"):
        row = rec.find("row")
        ev = row.find("policy_evaluated")
        auth = rec.find("auth_results")
        records.append({
            "ip": row.findtext("source_ip"),
            "count": int(row.findtext("count")),
            "dkim": ev.findtext("dkim"),
            "spf": ev.findtext("spf"),
            "action": ev.findtext("disposition"),
            "header_from": rec.find("identifiers").findtext("header_from"),
            "results": [(r.tag, r.findtext("domain"), r.findtext("result"),
                         r.findtext("selector")) for r in (auth if auth is not None else [])],
        })
    return {
        "path": path,
        "org": meta.findtext("org_name"),
        "id": meta.findtext("report_id"),
        "begin": int(rng.findtext("begin")),
        "end": int(rng.findtext("end")),
        "domain": pol.findtext("domain"),
        "p": pol.findtext("p"),
        "pct": pol.findtext("pct") or "100",
        "records": records,
    }


def passed(rec):
    """DMARC passes if aligned DKIM or aligned SPF passed."""
    return "pass" in (rec["dkim"], rec["spf"])


def when(epoch):
    """Turn a Unix timestamp into UTC and Pacific time."""
    t = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return f"{t:%Y-%m-%d %H:%M} UTC ({t.astimezone(PT):%Y-%m-%d %H:%M} PT)"


# ---------------------------------------------------------------- Part C
def fcrdns(ip):
    """Forward-confirmed reverse DNS: returns (name, confirmed)."""
    try:
        name = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0]
    except OSError:
        return "no PTR record", False
    try:
        forward = {ipaddress.ip_address(a[4][0].split("%")[0])
                   for a in socket.getaddrinfo(name, None)}
    except (OSError, ValueError):
        forward = set()
    return name, ipaddress.ip_address(ip) in forward


def lookup_all(ips):
    """Look up each distinct IP once, in parallel, with an overall time limit."""
    ips = set(ips)
    results = {}

    def work(ip):
        results[ip] = fcrdns(ip)

    # Daemon threads: a lookup that hangs can't stop the script from exiting.
    threads = [threading.Thread(target=work, args=(ip,), daemon=True)
               for ip in sorted(ips)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + LOOKUP_TIMEOUT
    for t in threads:
        t.join(max(0, deadline - time.monotonic()))
    return {ip: results.get(ip, ("lookup timed out", False)) for ip in ips}


def load_known(path):
    """Read the known-senders list: one domain per line, # for comments."""
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return []
    return [ln.split("#")[0].strip().lower().rstrip(".") for ln in lines
            if ln.split("#")[0].strip()]


def is_known(lookup, known):
    """Known only if the reverse-DNS name is confirmed and ends in a listed domain."""
    name, confirmed = lookup
    name = name.lower().rstrip(".")
    return confirmed and any(name == d or name.endswith("." + d) for d in known)


# ---------------------------------------------------------------- Part D
def print_report(rep, lookups):
    """Version 1 style: one block per report."""
    print("=" * 60)
    print("File:    ", rep["path"])
    print("Reporter:", rep["org"], " ID", rep["id"])
    print("From:    ", when(rep["begin"]))
    print("To:      ", when(rep["end"]))
    print(f"Policy:   {rep['domain']}  p={rep['p']}  pct={rep['pct']}")
    total = ok = 0
    for rec in rep["records"]:
        good = passed(rec)
        total += rec["count"]
        ok += rec["count"] if good else 0
        print()
        print(f"  Source {rec['ip']}  messages={rec['count']}  DMARC={'PASS' if good else 'FAIL'}"
              f"  (dkim={rec['dkim']}, spf={rec['spf']}, action={rec['action']})")
        print("    Header From:", rec["header_from"])
        for tag, domain, result, sel in rec["results"]:
            extra = f"  selector={sel}" if sel else ""
            print(f"    {tag.upper():4} {domain}: {result}{extra}")
        if lookups:
            name, confirmed = lookups[rec["ip"]]
            print(f"    rDNS: {name} ({'confirmed' if confirmed else 'NOT confirmed'})")
    print()
    print(f"Total: {total} message(s), {ok} passed DMARC, {total - ok} failed")
    return total - ok


# ---------------------------------------------------------------- Part D2 (new in 3.1)
RANK = {"none": 0, "quarantine": 1, "reject": 2}


def policy_of(rep):
    """The published policy as (p, pct), with pct as a number."""
    pct = int(rep["pct"]) if str(rep["pct"]).isdigit() else 100
    return rep["p"], pct


def strictness(policy):
    """Higher is stricter: none < quarantine at 25% < quarantine < reject."""
    p, pct = policy
    return RANK.get(p, 0), pct


def next_step(policy):
    """The next DMARC step after this policy, or None at full enforcement."""
    p, pct = policy
    if RANK.get(p, 0) == 0:
        return "move to p=quarantine (start with pct=25)"
    if pct < 100:
        return f"remove pct for full p={p} (RFC 9989 dropped the pct tag)"
    if p == "quarantine":
        return "move to p=reject"
    return None


def report_day(rep):
    """The UTC day a daily report covers (taken at the middle of its range)."""
    mid = (rep["begin"] + rep["end"]) // 2
    return datetime.fromtimestamp(mid, tz=timezone.utc).date()


def drop_duplicates(reports):
    """Keep one copy of each report: same reporter and same report ID."""
    seen, kept = {}, []
    for rep in reports:
        key = (rep["org"], rep["id"])
        if key in seen:
            print(f"Skipped duplicate: {rep['path']} (same report as {seen[key]})")
            continue
        seen[key] = rep["path"]
        kept.append(rep)
    return kept


def summarize(reports, lookups, known):
    """Roll up every report by source and give a verdict for the next policy step."""
    sources = {}
    for rep in reports:
        for rec in rep["records"]:
            s = sources.setdefault(rec["ip"], {"msgs": 0, "pass": 0})
            s["msgs"] += rec["count"]
            s["pass"] += rec["count"] if passed(rec) else 0
    start = min(r["begin"] for r in reports)
    end = max(r["end"] for r in reports)
    days = round((end - start) / 86400)
    total = sum(s["msgs"] for s in sources.values())
    good = sum(s["pass"] for s in sources.values())
    unknown = 0

    covered = sorted({report_day(r) for r in reports})
    span = (covered[-1] - covered[0]).days + 1
    gaps = [covered[0] + timedelta(days=d) for d in range(span)
            if covered[0] + timedelta(days=d) not in covered]

    by_policy = {}
    for rep in reports:
        b = by_policy.setdefault(policy_of(rep), {"reports": 0, "msgs": 0,
                                                  "begin": rep["begin"], "end": rep["end"]})
        b["reports"] += 1
        b["msgs"] += sum(rec["count"] for rec in rep["records"])
        b["begin"] = min(b["begin"], rep["begin"])
        b["end"] = max(b["end"], rep["end"])
    latest = max(reports, key=lambda r: (r["end"], strictness(policy_of(r))))
    now = policy_of(latest)
    days_now = round((end - by_policy[now]["begin"]) / 86400)

    print("=" * 60)
    print(f"Summary: {len(reports)} report(s), {days} day(s), "
          f"{len(covered)} day(s) with a report")
    print("From:", when(start))
    print("To:  ", when(end))
    print("Domain:", ", ".join(sorted({r["domain"] for r in reports})))
    if gaps:
        print("No report for:", ", ".join(f"{d:%m-%d}" for d in gaps))
        print("  (usually days with no mail; check that none are missing)")
    print("Policy in the reports:")
    for pol in sorted(by_policy, key=strictness):
        b = by_policy[pol]
        first = datetime.fromtimestamp(b["begin"], tz=timezone.utc)
        last = datetime.fromtimestamp(b["end"], tz=timezone.utc)
        print(f"  p={pol[0]} pct={pol[1]}: {b['reports']} report(s), {b['msgs']} message(s), "
              f"{first:%Y-%m-%d} to {last:%Y-%m-%d}")
    print(f"Policy now: p={now[0]} pct={now[1]} (latest report)")
    print()
    for ip in sorted(sources, key=lambda i: -sources[i]["msgs"]):
        s = sources[ip]
        name, confirmed = lookups[ip]
        tag = "known" if is_known(lookups[ip], known) else "UNKNOWN"
        unknown += tag == "UNKNOWN"
        print(f"  {tag:7}  {ip}  {name}{'' if confirmed else ' (not confirmed)'}")
        print(f"           {s['msgs']} message(s): {s['pass']} passed, "
              f"{s['msgs'] - s['pass']} failed")
    print()
    pct = 100 * good / total if total else 0
    print(f"Messages: {total}, passed DMARC: {good} ({pct:.0f}%), failed: {total - good}")
    print(f"Unknown senders: {unknown}")
    if not known:
        print("Note: no known-senders list found, so every sender counts as unknown.")
    issues = []
    if total - good:
        issues.append(f"{total - good} message(s) failed DMARC: find and fix those senders first")
    if unknown:
        issues.append(f"{unknown} unknown sender(s): check each one, then add real ones "
                      "to the known-senders list")
    step = next_step(now)
    if issues:
        print("Verdict: NOT READY.")
        for i in issues:
            print("  -", i)
    elif step is None:
        print("Verdict: AT FULL ENFORCEMENT (p=reject). Keep reading reports for new "
              "or failing senders.")
    elif days_now < MIN_DAYS:
        print(f"Verdict: NOT READY YET for the next step. Everything passed, but there "
              f"are only {days_now} day(s) of reports at p={now[0]} pct={now[1]}; "
              f"wait for at least {MIN_DAYS}, then {step}.")
    else:
        print(f"Verdict: READY to {step}.")
    return len(issues)


# ---------------------------------------------------------------- Part G (new in 4.0)
def org_label(org):
    """A short, safe name for the reporter: 'google.com' -> 'Google'."""
    parts = [p for p in str(org or "unknown").lower().split(".") if p]
    word = parts[-2] if len(parts) > 1 else parts[0] if parts else "unknown"
    return SAFE_TEXT.sub("", word).capitalize() or "Unknown"


def load_history(path):
    """Read the history file, or start an empty one."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        data = {}
    data.setdefault("reports", {})
    data.setdefault("senders", {})
    return data


def save_history(path, data):
    """Write the history file safely: write a temporary copy, then swap it in."""
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True))
    os.replace(tmp, path)


def remember(history, reports, filed_as=None):
    """Record reports and senders in the history; return senders not seen before."""
    new = {}
    for rep in reports:
        key = f"{rep['org']}|{rep['id']}"
        entry = history["reports"].setdefault(key, {
            "domain": rep["domain"], "day": str(report_day(rep)),
            "policy": f"p={rep['p']} pct={rep['pct']}"})
        if filed_as and rep["path"] in filed_as:
            entry["file"] = filed_as[rep["path"]]
        for rec in rep["records"]:
            if rec["ip"] not in history["senders"]:
                day = str(report_day(rep))
                new[rec["ip"]] = min(day, new.get(rec["ip"], day))
    for ip, day in new.items():
        history["senders"][ip] = {"first_seen": day}
    return new


def file_reports(src, dest, prefix, act):
    """Plan (and with act=True, do) the filing of new reports from src into dest.
    New reports go to dest/Reports with a dated name; copies of reports already
    filed go to dest/_Archive. Nothing is ever deleted or overwritten."""
    reports_dir, archive_dir = Path(dest) / "Reports", Path(dest) / "_Archive"
    if not reports_dir.is_dir():
        print(f"Not a records folder (no Reports folder inside): {dest}")
        return 1, []
    filed = {}
    for path in sorted(reports_dir.iterdir()):
        if path.suffix.lower() in (".zip", ".gz", ".xml"):
            try:
                rep = parse_report(str(path))
                filed[(rep["org"], rep["id"])] = rep
            except READ_ERRORS:
                print(f"Note: could not read Reports/{path.name}; left out of the duplicate check")
    found = []
    for path in sorted(Path(src).iterdir()):
        if path.is_file() and REPORT_NAME.fullmatch(path.name):
            try:
                found.append(parse_report(str(path)))
            except READ_ERRORS as err:
                print(f"Could not read {path.name}: {err}")
    stamp = datetime.now(PT).strftime("%Y-%m-%d %H%M") + "PT"
    known_ids = set(filed)
    plan, new_reports = [], []
    for rep in found:
        key = (rep["org"], rep["id"])
        if key in known_ids:
            plan.append(("archive", rep, archive_dir / Path(rep["path"]).name))
            continue
        known_ids.add(key)
        new_reports.append(rep)
    days = {}
    for rep in list(filed.values()) + new_reports:
        days.setdefault((rep["org"], str(report_day(rep))), []).append(rep)
    for rep in new_reports:
        same_day = days[(rep["org"], str(report_day(rep)))]
        label = f" — policy {SAFE_TEXT.sub('', rep['p'])}" if len(same_day) > 1 else ""
        ext = ".xml.gz" if rep["path"].lower().endswith(".xml.gz") else Path(rep["path"]).suffix.lower()
        name = (f"{prefix} — {org_label(rep['org'])} — {report_day(rep)}{label}"
                f" — v01 — {stamp}{ext}")
        plan.append(("file", rep, reports_dir / name))

    if not plan:
        print("Nothing to file: no new DMARC reports in", src)
        return 0, []
    problems, done = 0, []
    print(("Filing" if act else "Dry run (add --yes to file)") + f": {len(plan)} file(s)")
    for action, rep, target in plan:
        what = "file   " if action == "file" else "archive"
        print(f"  {what}  {Path(rep['path']).name}")
        print(f"       -> {target.parent.name}/{target.name}")
        if target.exists():
            print("       SKIPPED: a file with that name is already there")
            problems += 1
            continue
        if act:
            if action == "archive":
                archive_dir.mkdir(exist_ok=True)
            shutil.move(rep["path"], target)
            done.append((rep, str(target)))
    if not act:
        print("No files were moved.")
    return problems, done


# ---------------------------------------------------------------- Part E
def dig(args):
    """Run dig and return its short answer lines."""
    out = subprocess.run(["dig", "+short", "+time=5", "+tries=2"] + args,
                         capture_output=True, text=True, timeout=30).stdout
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def dig_txt(name, server=None):
    """Return the TXT records for a name, joining long records' quoted chunks."""
    lines = dig(([f"@{server}"] if server else []) + ["TXT", name])
    return ["".join(re.findall(r'"((?:[^"\\]|\\.)*)"', ln)) for ln in lines if '"' in ln]


def name_servers(domain):
    """The domain's authoritative name servers, checked before use."""
    return sorted(n.rstrip(".") for n in dig(["NS", domain])
                  if NAME_OK.fullmatch(n.rstrip(".")))


def key_bits(p_value):
    """Rough RSA key size from the DKIM p= value."""
    try:
        size = len(base64.b64decode(p_value))
    except ValueError:
        return "unreadable key"
    for limit, bits in ((200, 1024), (330, 2048), (600, 4096)):
        if size < limit:
            return f"about {bits}-bit"
    return "larger than 4096-bit"


def tags(record):
    return dict(t.strip().split("=", 1) for t in record.split(";") if "=" in t)


def check_dns(domain, selector, server=None):
    """Check SPF, DKIM and DMARC; return the number of problems found."""
    problems = 0
    print("=" * 60)
    print(f"DNS check: {domain}  DKIM selector: {selector}  "
          f"asked: {server or 'your normal resolver'}")

    spf = [r for r in dig_txt(domain, server) if r.lower().startswith("v=spf1")]
    print()
    if len(spf) == 1:
        print("  SPF   OK:", spf[0])
        if not spf[0].rstrip().endswith(("~all", "-all")):
            print("        WARNING: should end in ~all or -all")
            problems += 1
    else:
        print(f"  SPF   PROBLEM: {len(spf)} SPF records (there must be exactly 1)")
        for r in spf:
            print("       ", r)
        problems += 1

    dkim = [r for r in dig_txt(f"{selector}._domainkey.{domain}", server) if "p=" in r]
    print()
    if dkim and tags(dkim[0]).get("p", "").replace(" ", ""):
        print(f"  DKIM  OK: key published, {key_bits(tags(dkim[0])['p'].replace(' ', ''))}")
    elif dkim:
        print("  DKIM  PROBLEM: p= is empty (key revoked)")
        problems += 1
    else:
        print(f"  DKIM  PROBLEM: no key at {selector}._domainkey.{domain}")
        problems += 1

    dmarc = [r for r in dig_txt(f"_dmarc.{domain}", server) if r.upper().startswith("V=DMARC1")]
    print()
    if len(dmarc) == 1:
        t = tags(dmarc[0])
        print(f"  DMARC OK: p={t.get('p', '?')}  pct={t.get('pct', '100')}"
              f"  rua={t.get('rua', '(none: no reports)')}")
    else:
        print(f"  DMARC PROBLEM: {len(dmarc)} DMARC records (there must be exactly 1)")
        problems += 1

    print()
    print("Result:", "all three records look right" if problems == 0
          else f"{problems} problem(s) to fix")
    return problems


# ---------------------------------------------------------------- Part F
def main():
    ap = argparse.ArgumentParser(
        description="Read DMARC aggregate reports and check SPF, DKIM and DMARC records.",
        epilog="Exit codes: 0 all passed, 1 something needs attention, 2 usage error.")
    ap.add_argument("files", nargs="*", help="report files (.xml, .zip or .gz)")
    ap.add_argument("--rdns", action="store_true", help="add forward-confirmed reverse DNS")
    ap.add_argument("--summary", action="store_true",
                    help="one rolled-up readiness report instead of one block per file")
    ap.add_argument("--known", default=str(DEFAULT_KNOWN), metavar="FILE",
                    help="known-senders list (default: known_senders.txt beside the script)")
    ap.add_argument("--dns", metavar="DOMAIN[:SELECTOR]",
                    help="check a domain's records (selector defaults to google)")
    ap.add_argument("--authoritative", action="store_true",
                    help="with --dns, ask the domain's own name servers instead of a resolver")    
    ap.add_argument("--file", metavar="FOLDER",
                    help="file new reports found in FOLDER (dry run unless --yes)")
    ap.add_argument("--to", metavar="RECORDS",
                    help="with --file, the records folder holding Reports and _Archive")
    ap.add_argument("--prefix", default="DMARC Aggregate Report",
                    help="with --file, the start of each filed name")
    ap.add_argument("--yes", action="store_true", help="with --file, actually move the files")
    ap.add_argument("--history", metavar="FILE",
                    help="history file: flags senders never seen before, then records them")
    ap.add_argument("--version", action="version", version="dmarc_read 4.0 (2026-10-28)")
    args = ap.parse_args()
    if args.file:
        if not args.to:
            ap.error("--file needs --to RECORDS (the folder holding Reports and _Archive)")
        problems, done = file_reports(args.file, args.to, args.prefix, args.yes)
        if done and args.history:
            hist = load_history(args.history)
            filed = [rep for rep, target in done if Path(target).parent.name == "Reports"]
            remember(hist, filed, {rep["path"]: Path(t).name for rep, t in done})
            save_history(args.history, hist)
            print(f"History updated: {args.history}")
        sys.exit(1 if problems else 0)    
    if not args.files and not args.dns:
        ap.error("give at least one report file or --dns DOMAIN")
    if args.authoritative and not args.dns:
        ap.error("--authoritative only works with --dns")

    problems = 0
    if args.dns:
        domain, _, selector = args.dns.partition(":")
        selector = selector or "google"
        if not (NAME_OK.fullmatch(domain) and NAME_OK.fullmatch(selector)):
            ap.error(f"not a valid domain or selector: {args.dns}")
        try:
            servers = name_servers(domain) if args.authoritative else [None]
            if not servers:
                print("No name servers found for", domain)
                problems += 1
            for server in servers:
                problems += check_dns(domain, selector, server)
        except (OSError, subprocess.SubprocessError) as err:
            print("DNS check failed (is dig installed?):", err)
            problems += 1

    reports = []
    for path in args.files:
        try:
            reports.append(parse_report(path))
        except READ_ERRORS as err:
            print(f"Could not read {path}: {err}")
            problems += 1

    reports = drop_duplicates(reports)
    if reports:
        lookups = None
        if args.rdns or args.summary:
            lookups = lookup_all(rec["ip"] for r in reports for rec in r["records"])
        if args.history:
            hist = load_history(args.history)
            first_run = not hist["senders"]
            fresh = [r for r in reports if f"{r['org']}|{r['id']}" not in hist["reports"]]
            new = remember(hist, reports)
            print("=" * 60)
            if first_run:
                print(f"History started: {len(hist['reports'])} report(s), "
                      f"{len(new)} sender(s) recorded.")
            else:
                print(f"Since the last run: {len(fresh)} new report(s), "
                      f"{len(new)} new sender(s).")
                for ip, day in sorted(new.items()):
                    name = lookups[ip][0] if lookups else ""
                    print(f"  NEW SENDER  {ip}  {name}  (first seen {day})")
            save_history(args.history, hist)
        if args.summary:
            problems += summarize(reports, lookups, load_known(args.known))
        else:
            for rep in reports:
                problems += print_report(rep, lookups)

    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
