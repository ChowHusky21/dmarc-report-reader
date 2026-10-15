#!/usr/bin/env python3
"""dmarc_read.py - summarize DMARC aggregate reports (.xml, .zip or .gz).
Standard library only.
Usage: python3 dmarc_read.py [--rdns] FILE [FILE ...]
"""
import gzip
import socket
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


def main():
    args = sys.argv[1:]
    do_rdns = "--rdns" in args
    files = [a for a in args if a != "--rdns"]
    if not files:
        print(__doc__)
        sys.exit(1)
    for path in files:
        try:
            summarize(path, do_rdns)
        except (OSError, ValueError, ET.ParseError, AttributeError) as err:
            print(f"Could not read {path}: {err}")


if __name__ == "__main__":
    main()
