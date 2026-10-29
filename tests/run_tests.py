"""Checks for dmarc_read_v4 (v3.1 checks plus v4 filing and history) with made-up reports (placeholders only).
Run: python3 tests/run_tests.py  (from the folder holding dmarc_read_v3_1.py)
Reverse DNS is replaced by a fake table so the tests work offline."""
import contextlib, io, sys, tempfile, zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import dmarc_read_v4 as d

DAY = 86400
BASE = 1790899200  # 2026-10-02 00:00 UTC


def report(day, rid, p="none", pct=100, rows=(("192.0.2.10", 2, "pass", "pass"),)):
    begin = BASE + day * DAY
    recs = "".join(
        f"<record><row><source_ip>{ip}</source_ip><count>{n}</count><policy_evaluated>"
        f"<disposition>none</disposition><dkim>{dk}</dkim><spf>{sp}</spf></policy_evaluated></row>"
        f"<identifiers><header_from>example.com</header_from></identifiers><auth_results/></record>"
        for ip, n, dk, sp in rows)
    return (f"<feedback><report_metadata><org_name>mail.example.net</org_name><report_id>{rid}</report_id>"
            f"<date_range><begin>{begin}</begin><end>{begin + DAY - 1}</end></date_range></report_metadata>"
            f"<policy_published><domain>example.com</domain><p>{p}</p><pct>{pct}</pct></policy_published>"
            f"{recs}</feedback>")


def files(tmp, specs, as_zip=True):
    out = []
    for i, xml in enumerate(specs):
        path = Path(tmp) / f"r{i:02d}.{'zip' if as_zip else 'xml'}"
        if as_zip:
            with zipfile.ZipFile(path, "w") as z:
                z.writestr(f"r{i:02d}.xml", xml)
        else:
            path.write_text(xml)
        out.append(str(path))
    return out


FAKE = {"192.0.2.10": ("mail.example.net", True), "192.0.2.20": ("fwd.example.org", True),
        "198.51.100.9": ("unknown.example.biz", True)}
KNOWN = ["example.net", "example.org"]


def run(paths):
    reps = [d.parse_report(p) for p in paths]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        reps = d.drop_duplicates(reps)
        lookups = {ip: FAKE.get(ip, ("no PTR record", False))
                   for r in reps for ip in (rec["ip"] for rec in r["records"])}
        issues = d.summarize(reps, lookups, KNOWN)
    return buf.getvalue(), issues


def check(name, cond, out):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        print(out)
    return cond


ok = True
with tempfile.TemporaryDirectory() as tmp:
    # 1. duplicates are skipped and not counted twice
    a = report(0, "A1"); b = report(20, "B1")
    paths = files(tmp, [a, b])
    dup = Path(tmp) / "dup.xml"; dup.write_text(a)
    out, issues = run(paths + [str(dup)])
    ok &= check("duplicate skipped", "Skipped duplicate" in out and "Messages: 4," in out, out)

with tempfile.TemporaryDirectory() as tmp:
    # 2. coverage and gaps
    out, _ = run(files(tmp, [report(0, "a"), report(1, "b"), report(4, "c")]))
    ok &= check("coverage counts days with a report", "3 day(s) with a report" in out, out)
    ok &= check("gaps listed", "No report for: 10-04, 10-05" in out, out)

with tempfile.TemporaryDirectory() as tmp:
    # 3. p=none, 21 clean days -> READY for quarantine
    out, issues = run(files(tmp, [report(0, "a"), report(20, "b")]))
    ok &= check("none -> ready for quarantine", "READY to move to p=quarantine" in out and issues == 0, out)

with tempfile.TemporaryDirectory() as tmp:
    # 4. policy changed 5 days ago -> NOT READY YET for removing pct
    specs = [report(0, "a"), report(15, "b"), report(16, "c", "quarantine", 25), report(20, "d", "quarantine", 25)]
    out, issues = run(files(tmp, specs))
    ok &= check("quarantine 25% young -> wait", "NOT READY YET for the next step" in out
                and "remove pct" in out and "at p=quarantine pct=25" in out, out)
    ok &= check("policy breakdown shows both", "p=none pct=100: 2 report(s)" in out
                and "p=quarantine pct=25: 2 report(s)" in out, out)

with tempfile.TemporaryDirectory() as tmp:
    # 5. same day, two reports (before and after a change): latest picks the stricter one
    specs = [report(0, "a"), report(19, "b"), report(19, "c", "quarantine", 25)]
    out, _ = run(files(tmp, specs))
    ok &= check("same-day split -> stricter is now", "Policy now: p=quarantine pct=25" in out, out)

with tempfile.TemporaryDirectory() as tmp:
    # 6. quarantine 100% for 15 days -> reject; reject 100% -> full enforcement
    out, _ = run(files(tmp, [report(0, "a", "quarantine", 100), report(14, "b", "quarantine", 100)]))
    ok &= check("quarantine 100 -> reject", "READY to move to p=reject" in out, out)
    out, _ = run(files(tmp, [report(0, "c", "reject", 100)]))
    ok &= check("reject -> full enforcement", "AT FULL ENFORCEMENT" in out, out)

with tempfile.TemporaryDirectory() as tmp:
    # 7. failures and unknown senders still win over everything
    rows = (("192.0.2.10", 2, "pass", "pass"), ("198.51.100.9", 1, "fail", "fail"))
    out, issues = run(files(tmp, [report(0, "a", rows=rows), report(20, "b")]))
    ok &= check("failure and unknown -> NOT READY", "Verdict: NOT READY." in out and issues == 2, out)

with tempfile.TemporaryDirectory() as tmp:
    # 8. forwarder (SPF fail, DKIM pass) still passes DMARC
    rows = (("192.0.2.20", 1, "pass", "fail"),)
    out, issues = run(files(tmp, [report(0, "a", rows=rows), report(20, "b")]))
    ok &= check("forwarded mail passes on DKIM", "failed: 0" in out and issues == 0, out)

# ---------------------------------------------------------------- v4.0 checks
def gname(day, n=""):
    begin = BASE + day * DAY
    return f"mail.example.net!example.com!{begin}!{begin + DAY - 1}{n}.zip"


def setup(tmp, filed, incoming):
    """filed / incoming: lists of (day, report_id, policy)."""
    src, dest = Path(tmp) / "Downloads", Path(tmp) / "Records"
    (dest / "Reports").mkdir(parents=True); src.mkdir()
    for i, (day, rid, p) in enumerate(filed):
        with zipfile.ZipFile(dest / "Reports" / f"old{i}.zip", "w") as z:
            z.writestr("r.xml", report(day, rid, p))
    for i, (day, rid, p) in enumerate(incoming):
        n = f" ({i})" if any(x[0] == day for x in incoming[:i]) else ""
        with zipfile.ZipFile(src / gname(day, n), "w") as z:
            z.writestr("r.xml", report(day, rid, p))
    (src / "holiday-photos.zip").write_bytes(b"not a report")
    return src, dest


def file_run(src, dest, act):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        problems, done = d.file_reports(src, dest, "Evidence — Test", act)
    return buf.getvalue(), problems, done


with tempfile.TemporaryDirectory() as tmp:
    # 9. dry run moves nothing; duplicate is planned for _Archive; other zips ignored
    src, dest = setup(tmp, [(0, "A", "none")], [(0, "A", "none"), (5, "B", "none")])
    out, problems, _ = file_run(src, dest, False)
    ok &= check("dry run plans, moves nothing", "Dry run" in out and "No files were moved" in out
                and len(list(src.iterdir())) == 3 and problems == 0, out)
    ok &= check("duplicate planned for _Archive", "-> _Archive/" in out, out)
    ok &= check("non-report zip ignored", "holiday-photos" not in out, out)
    # 10. --yes files the new one with the right name, archives the duplicate
    out, problems, done = file_run(src, dest, True)
    names = sorted(p.name for p in (dest / "Reports").iterdir())
    ok &= check("new report filed with dated name",
                any(n.startswith("Evidence — Test — Example — 2026-10-07 — v01 — ") for n in names), out)
    ok &= check("duplicate moved to _Archive", len(list((dest / "_Archive").iterdir())) == 1, out)
    ok &= check("only the non-report file left", [p.name for p in src.iterdir()] == ["holiday-photos.zip"], out)
    # 11. running again finds nothing
    out, problems, _ = file_run(src, dest, True)
    ok &= check("second run: nothing to file", "Nothing to file" in out, out)

with tempfile.TemporaryDirectory() as tmp:
    # 12. two reports for one day get policy labels
    src, dest = setup(tmp, [], [(19, "N", "none"), (19, "Q", "quarantine")])
    out, _, _ = file_run(src, dest, True)
    names = " | ".join(p.name for p in (dest / "Reports").iterdir())
    ok &= check("same-day reports labelled by policy", "— policy none —" in names
                and "— policy quarantine —" in names, out)

with tempfile.TemporaryDirectory() as tmp:
    # 13. a hostile reporter name can't escape the folder
    src, dest = setup(tmp, [], [])
    xml = report(3, "X").replace("mail.example.net", "../../evil/..")
    with zipfile.ZipFile(src / gname(3), "w") as z:
        z.writestr("r.xml", xml)
    out, _, done = file_run(src, dest, True)
    ok &= check("hostile org name stays inside Reports",
                done and Path(done[0][1]).parent == dest / "Reports" and "/" not in Path(done[0][1]).name, out)

with tempfile.TemporaryDirectory() as tmp:
    # 14. never overwrites: same target name already there -> skipped, exit flag set
    src, dest = setup(tmp, [], [(2, "S", "none")])
    out, _, _ = file_run(src, dest, False)
    target = out.split("-> Reports/")[1].splitlines()[0]
    (dest / "Reports" / target).write_text("keep me")
    out, problems, _ = file_run(src, dest, True)
    ok &= check("existing file never overwritten", "SKIPPED" in out and problems == 1
                and (dest / "Reports" / target).read_text() == "keep me", out)

with tempfile.TemporaryDirectory() as tmp:
    # 15. history: first run records, second run flags only the new sender
    hist_path = Path(tmp) / "history.json"
    r1 = [d.parse_report(p) for p in files(tmp, [report(0, "h1")])]
    h = d.load_history(hist_path); new = d.remember(h, r1); d.save_history(hist_path, h)
    rows = (("192.0.2.10", 1, "pass", "pass"), ("192.0.2.99", 1, "pass", "fail"))
    sub = Path(tmp) / "b"; sub.mkdir()
    r2 = [d.parse_report(p) for p in files(sub, [report(1, "h2", rows=rows)])]
    h = d.load_history(hist_path); new2 = d.remember(h, r2); d.save_history(hist_path, h)
    ok &= check("history: first run records senders", list(new) == ["192.0.2.10"], str(new))
    ok &= check("history: only the new sender flagged", list(new2) == ["192.0.2.99"], str(new2))
    ok &= check("history file holds both reports", len(d.load_history(hist_path)["reports"]) == 2, "")

with tempfile.TemporaryDirectory() as tmp:
    # 16. a damaged zip gives "Could not read", not a crash (bug in v3 and v3.1, fixed in 4.0)
    import subprocess
    bad = Path(tmp) / "bad.zip"; bad.write_bytes(b"PK not really a zip")
    good = files(tmp, [report(0, "g")])[0]
    script = Path(__file__).resolve().parent.parent / "dmarc_read_v4.py"
    run_ = subprocess.run([sys.executable, str(script), str(bad), good],
                          capture_output=True, text=True)
    ok &= check("damaged zip reported, not a crash", "Could not read" in run_.stdout
                and run_.returncode == 1 and "Traceback" not in run_.stderr,
                run_.stdout + run_.stderr)

print("ALL PASSED" if ok else "SOME TESTS FAILED")
sys.exit(0 if ok else 1)
