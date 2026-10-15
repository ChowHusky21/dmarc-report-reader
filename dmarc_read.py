#!/usr/bin/env python3
"""dmarc_read.py - summarize DMARC aggregate reports (.xml, .zip or .gz)
and check a domain's SPF, DKIM and DMARC records.
Standard library only (the DNS check uses macOS's built-in dig).
Version 2 (2026-10-15): adds the --dns check.
Usage: python3 dmarc_read.py [--rdns] FILE [FILE ...]
       python3 dmarc_read.py --dns DOMAIN[:SELECTOR]   (selector defaults to google)
"""
import base64
import gzip
import re
import socket
import subprocess
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

PT = ZoneInfo("America/Los_Angeles")
MAX_BYTES = 10 * 1024 * 1024  # refuse anything over 10 MB unpacked


def load_xml(path):
    """Return the report's XML text, whatever it is wrapped in."""
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.filename.endswith(".xml"):
                    if info.file_size > MAX_BYTES:
                        raise ValueError("XML inside the zip is too large")
                    return zf.read(info).decode("utf-8")
        raise ValueError("no .xml file inside the zip")
    if path.endswith(".gz"):
        with gzip.open(path) as gz:
            data = gz.read(MAX_BYTES + 1)
    else:
        with open(path, "rb") as f:
            data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("file is too large")
    return data.decode("utf-8")


def when(epoch):
    """Turn a Unix timestamp into UTC and Pacific time."""
    t = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    return f"{t:%Y-%m-%d %H:%M} UTC ({t.astimezone(PT):%Y-%m-%d %H:%M} PT)"


def fcrdns(ip):
    """Reverse lookup, then check the name points back to the same IP."""
    try:
        name = socket.gethostbyaddr(ip)[0]
    except OSError:
        return "no PTR record"
    try:
        forward = socket.gethostbyname_ex(name)[2]
    except OSError:
        forward = []
    status = "confirmed" if ip in forward else "NOT confirmed"
    return f"{name} ({status})"


def summarize(path, do_rdns):
    root = ET.fromstring(load_xml(path))
    meta = root.find("report_metadata")
    rng = meta.find("date_range")
    pol = root.find("policy_published")

    print("=" * 60)
    print("File:    ", path)
    print("Reporter:", meta.findtext("org_name"), " ID", meta.findtext("report_id"))
    print("From:    ", when(rng.findtext("begin")))
    print("To:      ", when(rng.findtext("end")))
    print(f"Policy:   {pol.findtext('domain')}  p={pol.findtext('p')}"
          f"  pct={pol.findtext('pct')}")

    total = passed = 0
    for rec in root.findall("record"):
        row = rec.find("row")
        ev = row.find("policy_evaluated")
        ip = row.findtext("source_ip")
        count = int(row.findtext("count"))
        dkim, spf = ev.findtext("dkim"), ev.findtext("spf")
        ok = "pass" in (dkim, spf)
        total += count
        if ok:
            passed += count

        print()
        print(f"  Source {ip}  messages={count}  DMARC={'PASS' if ok else 'FAIL'}"
              f"  (dkim={dkim}, spf={spf}, action={ev.findtext('disposition')})")
        print("    Header From:", rec.find("identifiers").findtext("header_from"))
        auth = rec.find("auth_results")
        for res in (auth if auth is not None else []):
            sel = res.findtext("selector")
            extra = f"  selector={sel}" if sel else ""
            print(f"    {res.tag.upper():4} {res.findtext('domain')}: "
                  f"{res.findtext('result')}{extra}")
        if do_rdns:
            print("    rDNS:", fcrdns(ip))

    print()
    print(f"Total: {total} message(s), {passed} passed DMARC, {total - passed} failed")


NAME_OK = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")


def dig_txt(name):
    """Return the TXT records for a DNS name, using dig."""
    out = subprocess.run(["dig", "+short", "+time=5", "+tries=2", "TXT", name],
                         capture_output=True, text=True, timeout=30).stdout
    records = []
    for line in out.splitlines():
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
        if parts:  # long records arrive in several quoted chunks
            records.append("".join(parts))
    return records


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


def check_dns(target):
    domain, _, selector = target.partition(":")
    selector = selector or "google"
    if not (NAME_OK.fullmatch(domain) and NAME_OK.fullmatch(selector)):
        print("Not a valid domain or selector:", target)
        return
    problems = 0
    print("=" * 60)
    print("DNS check:", domain, " DKIM selector:", selector)

    spf = [r for r in dig_txt(domain) if r.lower().startswith("v=spf1")]
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

    dkim = [r for r in dig_txt(f"{selector}._domainkey.{domain}") if "p=" in r]
    print()
    if dkim:
        tags = dict(t.strip().split("=", 1) for t in dkim[0].split(";") if "=" in t)
        p_value = tags.get("p", "").replace(" ", "")
        if p_value:
            print(f"  DKIM  OK: key published, {key_bits(p_value)}")
        else:
            print("  DKIM  PROBLEM: p= is empty (key revoked)")
            problems += 1
    else:
        print(f"  DKIM  PROBLEM: no key at {selector}._domainkey.{domain}")
        problems += 1

    dmarc = [r for r in dig_txt(f"_dmarc.{domain}") if r.upper().startswith("V=DMARC1")]
    print()
    if len(dmarc) == 1:
        tags = dict(t.strip().split("=", 1) for t in dmarc[0].split(";") if "=" in t)
        print(f"  DMARC OK: p={tags.get('p', '?')}  pct={tags.get('pct', '100')}"
              f"  rua={tags.get('rua', '(none: no reports)')}")
    else:
        print(f"  DMARC PROBLEM: {len(dmarc)} DMARC records (there must be exactly 1)")
        problems += 1

    print()
    print("Result:", "all three records look right" if problems == 0
          else f"{problems} problem(s) to fix")


def main():
    args = sys.argv[1:]
    do_rdns = "--rdns" in args
    dns_target = None
    if "--dns" in args:
        i = args.index("--dns")
        if i + 1 < len(args):
            dns_target = args[i + 1]
            del args[i:i + 2]
    files = [a for a in args if a != "--rdns"]
    if not files and not dns_target:
        print(__doc__)
        sys.exit(1)
    if dns_target:
        try:
            check_dns(dns_target)
        except (OSError, subprocess.SubprocessError) as err:
            print("DNS check failed (is dig installed?):", err)
    for path in files:
        try:
            summarize(path, do_rdns)
        except (OSError, ValueError, ET.ParseError, AttributeError) as err:
            print(f"Could not read {path}: {err}")


if __name__ == "__main__":
    main()
