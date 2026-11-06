"""appsleuth command line.

    appsleuth scan  <app|dir>        static security scan (APK / APKS / XAPK / AAB / IPA)
    appsleuth info  <app>            inspect an app: identity, signing, permissions, components...
    appsleuth diff  <old> <new>      compare two builds and list regressions
    appsleuth data  ...              pull + audit an app's data container from a device
    appsleuth <app>                  same as `scan` (backward compatible)
"""
import argparse
import getpass
import json
import os
import re
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional

from . import __version__, diff as diff_mod, engine, info as info_mod, triage

COMMANDS = ("scan", "info", "diff", "data", "runtime", "sbom", "endpoints", "links", "cloud", "version")
_SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


# ------------------------------------------------------------------ terminal

class Term:
    on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    codes = {"HIGH": "1;31", "MEDIUM": "33", "LOW": "34", "INFO": "90", "bold": "1", "dim": "2", "ok": "32"}

    @classmethod
    def c(cls, text: str, kind: str) -> str:
        return f"\033[{cls.codes[kind]}m{text}\033[0m" if cls.on else text


def die(msg: str, code: int = 1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def _counts(s: Dict[str, int]) -> str:
    return "  ".join(Term.c(f"{s.get(k, 0)} {k.title()}", k) for k in ("HIGH", "MEDIUM", "LOW", "INFO"))


def print_findings(result: Dict[str, Any], *, verbose: bool = False, show: str = "LOW"):
    shown = [f for f in result["findings"] if _SEV_RANK[f["severity"]] >= _SEV_RANK[show]]
    hidden = len(result["findings"]) - len(shown)
    for f in shown:
        tag = Term.c(f"[{f['severity']}]", f["severity"])
        conf = "" if f.get("confidence") == "confirmed" else Term.c(" (heuristic)", "dim")
        print(f"  {tag} {f['title']}{conf}")
        if f.get("location"):
            print(Term.c(f"        {f['location'][:110]}", "dim"))
        if verbose:
            print(f"        {f['detail']}")
            if f.get("evidence"):
                print(f"        evidence: {f['evidence'][:300]}")
    if hidden:
        print(Term.c(f"  … {hidden} lower-severity finding(s) in the report (use --show INFO to list)", "dim"))


def _append_triage_md(path: str, result: Dict[str, Any]):
    t = result.get("triage")
    if not t:
        return
    lines = ["", "## Triage (what was filtered, and why)", ""]
    for d in t["demoted"]:
        lines.append(f"- demoted **{d['title']}** {d['from']} → {d['to']}: {d['why']}")
    for i in t["ignored_by_rule"]:
        lines.append(f"- ignored **{i['title']}** by rule `{i['rule']}`" + (f" ({i['reason']})" if i["reason"] else ""))
    if t["hidden_by_threshold"]:
        lines.append(f"- {len(t['hidden_by_threshold'])} finding(s) below the requested threshold are in report.json")
    if t["dropped"]:
        lines.append(f"- {len(t['dropped'])} duplicate finding(s) collapsed")
    if len(lines) == 3:
        lines.append("Nothing was demoted, ignored or hidden.")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_reports(result: Dict[str, Any], outdir: str, title: Optional[str] = None):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, default=str)
    md = os.path.join(outdir, "report.md")
    engine.write_markdown_report(result, md)
    if title:
        text = open(md, encoding="utf-8").read().replace("# Mobile app static security scan:", f"# {title}:", 1)
        open(md, "w", encoding="utf-8").write(text)
    _append_triage_md(md, result)
    if result.get("warnings"):
        with open(md, encoding="utf-8") as fh:
            body = fh.read()
        banner = "".join(f"> **WARNING: {w}**\n>\n" for w in result["warnings"]) + "\n"
        head, sep, rest = body.partition("\n")
        with open(md, "w", encoding="utf-8") as fh:
            fh.write(head + "\n\n" + banner + rest)
    hp = os.path.join(outdir, "report.html")
    engine.write_html_report(result, hp)
    if result.get("warnings"):
        import html as _h
        with open(hp, encoding="utf-8") as fh:
            page = fh.read()
        box = ('<div style="background:#fff3cd;border:2px solid #d39e00;padding:12px;margin:12px 0;font-weight:bold">'
               + "<br>".join("WARNING: " + _h.escape(w) for w in result["warnings"]) + "</div>")
        page = page.replace('<div class="wrap">', '<div class="wrap">' + box, 1)
        with open(hp, "w", encoding="utf-8") as fh:
            fh.write(page)


def _rules(args, target: str) -> List[triage.IgnoreRule]:
    path = getattr(args, "ignore_file", None) or triage.find_default_ignore_file(target)
    if not path:
        return []
    try:
        rules = triage.load_ignore_file(path)
    except (OSError, ValueError) as e:
        die(f"cannot read ignore file: {e}", 2)
    print(Term.c(f"[*] Using ignore rules from {path} ({len(rules)})", "dim"))
    return rules


def _scan_triaged(path: str, args, rules, tmp: str, keep: bool = False) -> Dict[str, Any]:
    try:
        res = engine.scan(path, tmp, save_extracted=keep)
    except ValueError as e:
        die(str(e), 1)
    except Exception as e:
        die(f"unexpected failure while scanning '{path}': {type(e).__name__}: {e}", 1)
    res["warnings"] = info_mod.coverage_warnings(res)
    if getattr(args, "no_triage", False):
        res["findings"] = [dict(f, fingerprint=triage._fp(f)) for f in res["findings"]]
        return res
    return triage.apply(res, rules=rules, min_severity=getattr(args, "min_severity", None),
                        min_confidence=getattr(args, "min_confidence", None))


# ------------------------------------------------------------------------ scan

def cmd_scan(a):
    if not os.path.exists(a.target):
        die(f"file not found: {a.target}", 2)
    outdir = a.outdir or f"scan_{os.path.splitext(os.path.basename(a.target.rstrip('/')))[0]}"
    if os.path.isdir(a.target):
        b = engine.batch_scan(a.target, outdir, recursive=a.recursive, save_extracted=a.keep_extracted)
        print(f"Scanned {b['count']} file(s) under {a.target}; summary in {outdir}/batch_summary.md")
        for r in b["results"]:
            if r["error"]:
                print(f"  ! {r['file']}: {r['error']}")
        return

    rules = _rules(a, a.target)
    tmp = tempfile.mkdtemp(prefix="appsleuth_")
    try:
        result = _scan_triaged(a.target, a, rules, outdir if a.keep_extracted else tmp, keep=a.keep_extracted)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if a.baseline:
        try:
            result = engine.apply_baseline(result, engine.load_baseline(a.baseline), a.baseline)
        except Exception as e:
            die(f"could not read baseline '{a.baseline}': {e}", 2)
    if a.write_baseline:
        engine.write_baseline(result, a.write_baseline)
        print(f"Baseline written to {a.write_baseline}")

    write_reports(result, outdir)
    if result.get("warnings") and a.format != "json":
        for w in result["warnings"]:
            print(Term.c("WARNING: " + w, "bold"), file=sys.stderr)
    if a.format == "json":
        print(json.dumps(result, indent=2, default=str))
    elif not a.quiet:
        m = result["meta"]
        ident = m.get("package") or m.get("bundle_id") or os.path.basename(a.target)
        ver = m.get("versionName") or m.get("version") or ""
        print(Term.c(f"{ident} {ver}", "bold") + f"  [{result['detected_type'].upper()}]")
        print_findings(result, verbose=a.verbose, show=a.show)
        print()
    print(_counts(result["summary"]) + (f"   ({result['suppressed_count']} hidden)" if result.get("suppressed_count") else ""))
    print(f"Reports: {outdir}/report.html  report.md  report.json")

    if a.fail_on:
        worst = max((_SEV_RANK[f["severity"]] for f in result["findings"]), default=-1)
        if worst >= _SEV_RANK[a.fail_on]:
            print(f"--fail-on {a.fail_on}: finding at or above this severity.", file=sys.stderr)
            sys.exit(3)


# ------------------------------------------------------------------------ info

def cmd_info(a):
    if not os.path.isfile(a.target):
        die(f"file not found: {a.target}", 2)
    tmp = tempfile.mkdtemp(prefix="appsleuth_")
    try:
        res = _scan_triaged(a.target, a, _rules(a, a.target), tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    s = info_mod.summarize(res, a.target)
    if a.json:
        print(json.dumps(s, indent=2, default=str))
    else:
        print(info_mod.render_text(s, full=a.full))


# ------------------------------------------------------------------------ diff

def cmd_diff(a):
    for p in (a.old, a.new):
        if not os.path.isfile(p):
            die(f"file not found: {p}", 2)
    rules = _rules(a, a.new)
    tmp = tempfile.mkdtemp(prefix="appsleuth_")
    try:
        d = diff_mod.diff_builds(a.old, a.new, lambda p: _scan_triaged(p, a, rules, tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    outdir = a.outdir or f"diff_{os.path.splitext(os.path.basename(a.old))[0]}_vs_{os.path.splitext(os.path.basename(a.new))[0]}"
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "diff.json"), "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=2, default=str)
    with open(os.path.join(outdir, "diff.md"), "w", encoding="utf-8") as fh:
        fh.write(diff_mod.render_markdown(d))

    if a.format == "json":
        print(json.dumps(d, indent=2, default=str))
    else:
        o, n = d["old"], d["new"]
        print(Term.c(f"{n['id']}", "bold") + f"  {o['version']} → {n['version']}")
        for w in d["warnings"]:
            print(Term.c(f"  ! {w}", "MEDIUM"))
        arts = d["artifact"]
        print(f"  package: {len(arts['added'])} added, {len(arts['removed'])} removed, {len(arts['modified'])} modified files")
        regs = [r for r in d["regressions"] if r["severity"] != "INFO" or a.verbose]
        print(f"\nRegressions: {len([r for r in d['regressions'] if r['severity'] != 'INFO'])}")
        for r in regs:
            print(f"  {Term.c('[' + r['severity'] + ']', r['severity'])} {r['text']}")
        f = d["findings"]
        print(f"\nFindings: {len(f['new'])} new, {len(f['resolved'])} resolved")
        print(f"Report: {outdir}/diff.md  diff.json")
    if a.fail_on_regression:
        if any(_SEV_RANK[r["severity"]] >= _SEV_RANK[a.fail_on_regression] for r in d["regressions"]):
            print(f"--fail-on-regression {a.fail_on_regression}: regression found.", file=sys.stderr)
            sys.exit(4)


# ------------------------------------------------------------------ intel commands

def _intel_report(res: Dict[str, Any], a, title: str, default_dir: str):
    res = triage.apply(res, rules=_rules(a, a.target), min_severity=a.min_severity, corroborate=False)
    out = a.outdir or f"{default_dir}_{os.path.splitext(os.path.basename(a.target))[0]}"
    write_reports(res, out, title)
    print(f"{os.path.basename(a.target)}: {_counts(res['summary'])}")
    print_findings(res, verbose=a.verbose, show=a.show)
    print(f"Reports: {out}/report.html  report.md  report.json")
    return res, out


def _need_file(a):
    if not os.path.isfile(a.target):
        die(f"file not found: {a.target}", 2)


def cmd_sbom(a):
    from . import sbom
    _need_file(a)
    res, cdx = sbom.run(a.target, cves=a.cves, offline=a.offline)
    res, out = _intel_report(res, a, "Software bill of materials", "sbom")
    path = os.path.join(out, "sbom.cdx.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cdx, fh, indent=2)
    print(f"CycloneDX SBOM: {path}")
    if not a.cves:
        print("Tip: add --cves to look components up on OSV.dev (sends component names and versions only).")


def cmd_endpoints(a):
    from . import endpoints
    _need_file(a)
    res = endpoints.run(a.target)
    res, out = _intel_report(res, a, "Endpoint inventory", "endpoints")
    with open(os.path.join(out, "endpoints.txt"), "w", encoding="utf-8") as fh:
        fh.write(endpoints.render_text(res, limit=100000))


def cmd_links(a):
    from . import links
    _need_file(a)
    res = links.run(a.target, check_network=a.check_network)
    _intel_report(res, a, "Deep links and URL schemes", "links")


def cmd_cloud(a):
    from . import cloud
    _need_file(a)
    if a.check:
        print("[*] --check sends read-only, unauthenticated requests to the app's cloud backends. "
              "Only use it on apps you are authorised to test.", file=sys.stderr)
    res = cloud.run(a.target, check=a.check)
    _intel_report(res, a, "Cloud backend check", "cloud")


# ------------------------------------------------------------------------ data

def cmd_runtime(a):
    from . import runtime
    platform = "ios" if a.ios else "android"
    print(f"[*] Attaching to {a.target} on {platform} for {a.seconds}s. Use the app now "
          "(log in, browse, trigger network calls); Ctrl+C ends early.", file=sys.stderr)
    try:
        events = runtime.run_probe(platform, a.target, seconds=a.seconds, spawn=a.spawn,
                                   device_id=a.device, host=a.frida_host)
    except RuntimeError as e:
        die(str(e), 2)
    except Exception as e:      # frida raises its own error types
        die(f"runtime probe failed: {type(e).__name__}: {e}", 1)
    res = runtime.events_to_result(events, platform, a.target)
    res = triage.apply(res, rules=_rules(a, a.target), min_severity=a.min_severity, corroborate=False)
    out = a.outdir or f"runtime_{a.target}"
    write_reports(res, out, "Runtime probe")
    print(f"\n{_counts(res['summary'])}   ({res['meta']['events']} events observed)")
    print_findings(res, verbose=a.verbose, show=a.show)
    if res["meta"]["events"] == 0:
        print("No events were observed. Is frida-server running, and did you use the app during the window?")
    print(f"Reports: {out}/report.html  report.md  report.json")


def cmd_data(a):
    from . import dataaudit, devdata

    def audit_and_report(root: str, platform: str, out: str, manifest=None):
        res = dataaudit.audit_dir(root, platform, reveal=a.show_values, manifest=manifest)
        res = triage.apply(res, rules=_rules(a, root), min_severity=a.min_severity, corroborate=False)
        write_reports(res, out, "App data audit")
        print(f"\n{_counts(res['summary'])}")
        print_findings(res, verbose=a.verbose, show=a.show)
        print(f"Reports: {out}/report.html  report.md  report.json")
        return res

    if a.audit_dir:
        if not os.path.isdir(a.audit_dir):
            die(f"not a directory: {a.audit_dir}", 2)
        audit_and_report(a.audit_dir, a.platform or "ios", a.outdir or "data_audit")
        return

    plat = "android" if a.android else "ios" if a.ios else a.platform
    if not plat:
        die("choose a source: --ios, --android, or --audit-dir DIR", 2)
    cap = a.max_mb << 20
    try:
        if plat == "ios":
            host, user, pw = a.host or os.environ.get("APPSLEUTH_HOST"), a.user, os.environ.get("SSH_PASSWORD")
            if not host:
                if not sys.stdin.isatty():
                    die("--host is required", 2)
                user = input(f"Username [{user}]: ").strip() or user
                host = input("Device IP (just the last number works, e.g. 9 = 192.168.1.9): ").strip()
                pw = getpass.getpass("Password (blank = use SSH key/prompt): ") or None
            host = devdata.expand_host(host or "")
            if not host:
                die("An IP address is required.", 2)
            ssh = devdata.SSH(host, a.port, user, a.key, pw)
            ssh.open()
            apps = devdata.ios_list_containers(ssh, a.include_system)
            app = _pick(apps, a.bundle_id, lambda x: x["bundle_id"],
                        lambda i, x: f"{i:3}. {x['bundle_id']}", "bundle id")
            if app is None:
                return
            out = os.path.join(a.outdir or "appdata", devdata.clean(app["bundle_id"]))
            print(f"[*] Pulling data container for {app['bundle_id']} ...")
            manifest = devdata.ios_pull(ssh, app, os.path.join(out, "data"), cap)
        else:
            serials = devdata.android_devices()
            if not serials:
                die("no Android device found (check `adb devices`)", 1)
            serial = a.serial or (serials[0] if len(serials) == 1 else None)
            if not serial:
                die("several devices connected; pick one with --serial: " + ", ".join(serials), 2)
            pkgs = devdata.android_list_packages(serial)
            pkg = _pick(pkgs, a.package, lambda x: x, lambda i, x: f"{i:3}. {x}", "package")
            if pkg is None:
                return
            out = os.path.join(a.outdir or "appdata", pkg)
            print(f"[*] Pulling data for {pkg} (method: {a.method}) ...")
            manifest = devdata.android_pull(serial, pkg, os.path.join(out, "data"), a.method, cap)
    except devdata.PullError as e:
        die(str(e), 1)

    os.chmod(out, 0o700)
    mf = {k: v for k, v in manifest.items() if k != "modes"}
    with open(os.path.join(out, "pull_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    print(f"[+] {mf['files']} files, {mf['bytes'] / 1e6:.1f} MB via {mf['method']} -> {out}/data")
    if mf.get("skipped_links_or_special"):
        print(f"    ({mf['skipped_links_or_special']} symlinks/special files skipped)")
    if not a.no_audit:
        audit_and_report(os.path.join(out, "data"), plat, out, manifest)
    print(Term.c("Note: the pulled data contains real user data and tokens. Treat it as sensitive; "
                 "delete it when done (or re-run with --no-keep-data).", "dim"))
    if a.no_keep_data:
        shutil.rmtree(os.path.join(out, "data"), ignore_errors=True)
        print("[*] Pulled data deleted; reports kept.")


def _pick(items, wanted: Optional[str], key, fmt, noun: str):
    if wanted:
        exact = [x for x in items if key(x) == wanted] or [x for x in items if wanted.lower() in key(x).lower()]
        if not exact:
            die(f"no {noun} matching '{wanted}'", 1)
        if len(exact) > 1:
            print(f"Several {noun}s match:")
            for i, x in enumerate(exact, 1):
                print(fmt(i, x))
            sys.exit(1)
        return exact[0]
    if not items:
        die(f"no {noun}s found", 1)
    if not sys.stdin.isatty():
        for i, x in enumerate(items, 1):
            print(fmt(i, x))
        return None
    print(f"Installed apps (most recently used first):")
    for i, x in enumerate(items[:25], 1):
        print(fmt(i, x))
    choice = input("Pick a number (or Enter to quit): ").strip()
    if not choice.isdigit() or not 1 <= int(choice) <= min(25, len(items)):
        return None
    return items[int(choice) - 1]


# ------------------------------------------------------------------------ parser

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="appsleuth", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"appsleuth {__version__}")
    sub = ap.add_subparsers(dest="cmd", metavar="{scan,info,diff,data,runtime,sbom,endpoints,links,cloud}")

    def triage_opts(p):
        p.add_argument("--ignore-file", help="ignore rules (default: ./.appsleuth-ignore if present)")
        p.add_argument("--min-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH"], help="hide findings below this")
        p.add_argument("--min-confidence", choices=["heuristic", "confirmed"],
                       help="'confirmed' hides pattern-based (heuristic) findings entirely")
        p.add_argument("--no-triage", action="store_true", help="raw engine output, no false-positive layer")

    s = sub.add_parser("scan", help="static security scan of an app (or a directory of apps)")
    s.add_argument("target", help=".apk .apks .xapk .aab .ipa, or a directory (batch)")
    s.add_argument("-o", "--outdir")
    s.add_argument("--recursive", action="store_true", help="batch: recurse into subdirectories")
    s.add_argument("--keep-extracted", action="store_true", help="keep the unpacked app in <outdir>/extracted")
    s.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW", "INFO"], help="exit 3 if a finding >= this remains")
    s.add_argument("--baseline", help="suppress findings listed in this baseline file")
    s.add_argument("--write-baseline", help="write the current findings as a baseline file")
    s.add_argument("--show", choices=["HIGH", "MEDIUM", "LOW", "INFO"], default="LOW",
                   help="lowest severity to print to the terminal (default LOW)")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.add_argument("-v", "--verbose", action="store_true", help="print each finding's detail and evidence")
    s.add_argument("-q", "--quiet", action="store_true")
    triage_opts(s)
    s.set_defaults(fn=cmd_scan)

    i = sub.add_parser("info", help="inspect an app: identity, signing, permissions, components, libraries")
    i.add_argument("target")
    i.add_argument("--json", action="store_true")
    i.add_argument("--full", action="store_true", help="do not truncate long lists")
    triage_opts(i)
    i.set_defaults(fn=cmd_info)

    d = sub.add_parser("diff", help="compare two builds of an app and list regressions")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("-o", "--outdir")
    d.add_argument("--format", choices=["text", "json"], default="text")
    d.add_argument("--fail-on-regression", choices=["HIGH", "MEDIUM", "LOW"], help="exit 4 on a regression >= this")
    d.add_argument("-v", "--verbose", action="store_true", help="also list informational changes")
    triage_opts(d)
    d.set_defaults(fn=cmd_diff)

    g = sub.add_parser("data", help="pull and audit an app's data container from a device you own")
    src = g.add_mutually_exclusive_group()
    src.add_argument("--ios", action="store_true", help="jailbroken iPhone over SSH")
    src.add_argument("--android", action="store_true", help="Android device/emulator over adb")
    src.add_argument("--audit-dir", metavar="DIR", help="audit an already-pulled data directory (no device)")
    g.add_argument("--platform", choices=["ios", "android"], help="platform of --audit-dir (default ios)")
    g.add_argument("--host", help="iOS: device IP (9 means 192.168.1.9) or set APPSLEUTH_HOST")
    g.add_argument("--port", type=int, default=22)
    g.add_argument("--user", default="root")
    g.add_argument("--key", help="SSH private key")
    g.add_argument("-b", "--bundle-id", help="iOS: bundle id (or substring)")
    g.add_argument("--include-system", action="store_true", help="iOS: include com.apple.* apps")
    g.add_argument("--serial", help="Android: device serial")
    g.add_argument("-p", "--package", help="Android: package name (or substring)")
    g.add_argument("--method", choices=["auto", "root", "run-as", "backup"], default="auto",
                   help="Android access method (default: try root, run-as, backup)")
    g.add_argument("--max-mb", type=int, default=2048, help="refuse containers larger than this")
    g.add_argument("-o", "--outdir")
    g.add_argument("--no-audit", action="store_true", help="only pull; skip the storage audit")
    g.add_argument("--no-keep-data", action="store_true", help="delete the pulled data after auditing")
    g.add_argument("--show-values", action="store_true", help="include a short preview of secret values in the report")
    g.add_argument("--show", choices=["HIGH", "MEDIUM", "LOW", "INFO"], default="LOW")
    g.add_argument("-v", "--verbose", action="store_true")
    g.add_argument("--ignore-file")
    g.add_argument("--min-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH"])
    g.set_defaults(fn=cmd_data)
    r = sub.add_parser("runtime", help="EXPERIMENTAL: observe a running app with Frida (root checks, cleartext, ciphers, secrets)")
    plat = r.add_mutually_exclusive_group(required=True)
    plat.add_argument("--android", action="store_true")
    plat.add_argument("--ios", action="store_true")
    r.add_argument("target", help="package name (Android) or bundle id (iOS)")
    r.add_argument("--seconds", type=int, default=60, help="observation window (default 60)")
    r.add_argument("--spawn", action="store_true", help="launch the app fresh instead of attaching to a running one")
    r.add_argument("--device", help="Frida device id (default: USB)")
    r.add_argument("--frida-host", help="connect to frida-server over the network at HOST[:PORT]")
    r.add_argument("-o", "--outdir")
    r.add_argument("--show", choices=["HIGH", "MEDIUM", "LOW", "INFO"], default="LOW")
    r.add_argument("-v", "--verbose", action="store_true")
    r.add_argument("--ignore-file")
    r.add_argument("--min-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH"])
    r.set_defaults(fn=cmd_runtime)
    def intel(name, helptext, fn):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("target", help="IPA, APK, APKS/XAPK or AAB")
        p.add_argument("-o", "--outdir")
        p.add_argument("--show", choices=["HIGH", "MEDIUM", "LOW", "INFO"], default="LOW")
        p.add_argument("-v", "--verbose", action="store_true")
        p.add_argument("--ignore-file")
        p.add_argument("--min-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH"])
        p.set_defaults(fn=fn)
        return p

    p = intel("sbom", "list embedded libraries (CycloneDX SBOM) and optionally their known CVEs", cmd_sbom)
    p.add_argument("--cves", action="store_true", help="look components up on OSV.dev (network)")
    p.add_argument("--offline", action="store_true", help="with --cves: use the local cache only")
    intel("endpoints", "inventory of hosts and API paths the app talks to", cmd_endpoints)
    p = intel("links", "deep links, URL schemes, App Links / Universal Links", cmd_links)
    p.add_argument("--check-network", action="store_true", help="fetch assetlinks.json / apple-app-site-association")
    p = intel("cloud", "Firebase / S3 / GCS backends the app uses (opt-in exposure checks)", cmd_cloud)
    p.add_argument("--check", action="store_true", help="read-only unauthenticated exposure checks (authorised targets only)")
    return ap


def main(argv: Optional[List[str]] = None):
    for _s in (sys.stdout, sys.stderr):      # Windows consoles default to a legacy codepage
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "version":
        print(f"appsleuth {__version__}")
        return
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "scan")                      # `appsleuth app.apk` == `appsleuth scan app.apk`
    ap = build_parser()
    a = ap.parse_args(argv)
    if not getattr(a, "fn", None):
        ap.print_help()
        sys.exit(2)
    try:
        a.fn(a)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
