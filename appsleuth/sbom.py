"""Software bill of materials + known-vulnerability lookup (OSV.dev).

Components come from what the build left behind (Maven pom.properties, AndroidX/Google
`.version` files, library user-agent strings, iOS framework Info.plists). Vulnerabilities are
looked up only for components whose package coordinates are known exactly, via the public
OSV API (opt-in, cached). A component that is present may still be partly removed by R8 or
never reached, so findings are leads, and say so.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import appfiles, engine, netfetch

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
CACHE_TTL = 24 * 3600
MAX_DETAIL_FETCHES = 300

# iOS frameworks whose Info.plist version equals the upstream SwiftPM tag -> OSV "SwiftURL" name.
# Deliberately short: a wrong mapping would produce false vulnerabilities.
IOS_SWIFTURL = {
    "Alamofire": "github.com/Alamofire/Alamofire",
    "SDWebImage": "github.com/SDWebImage/SDWebImage",
    "Kingfisher": "github.com/onevcat/Kingfisher",
    "SwiftyJSON": "github.com/SwiftyJSON/SwiftyJSON",
    "Lottie": "github.com/airbnb/lottie-ios",
    "RxSwift": "github.com/ReactiveX/RxSwift",
    "Sentry": "github.com/getsentry/sentry-cocoa",
    "Capacitor": "github.com/ionic-team/capacitor",
    "Starscream": "github.com/daltoniam/Starscream",
    "SwiftProtobuf": "github.com/apple/swift-protobuf",
    "AppAuth": "github.com/openid/AppAuth-iOS",
    "Mixpanel": "github.com/mixpanel/mixpanel-swift",
    "FirebaseCore": "github.com/firebase/firebase-ios-sdk",
    "FirebaseAuth": "github.com/firebase/firebase-ios-sdk",
    "FirebaseFirestore": "github.com/firebase/firebase-ios-sdk",
    "GoogleSignIn": "github.com/google/GoogleSignIn-iOS",
    "Realm": "github.com/realm/realm-swift",
    "RealmSwift": "github.com/realm/realm-swift",
    "OpenSSL": "github.com/krzyzanowskim/OpenSSL",
}
# Google/Firebase Android libraries ship `<name>.properties` with a version but no group id.
_GOOGLE_PREFIX = (("firebase-", "com.google.firebase"), ("play-services-", "com.google.android.gms"))
# Version strings that libraries embed in their own code (dex strings).
_DEX_FINGERPRINTS = [
    (re.compile(rb"okhttp/(\d+\.\d+\.\d+)"), "com.squareup.okhttp3", "okhttp"),
]


def _purl(c: Dict[str, Any]) -> str:
    if c.get("ecosystem") == "Maven" and c.get("group"):
        return f"pkg:maven/{c['group']}/{c['artifact']}@{c['version']}"
    return f"pkg:generic/{re.sub(r'[^A-Za-z0-9._-]', '_', c['name'])}@{c.get('version') or 'unknown'}"


def _add(out: Dict[str, Dict[str, Any]], c: Dict[str, Any]):
    key = (c["name"], c.get("version"))
    if key not in out:
        c["purl"] = _purl(c) if c.get("version") else None
        out[key] = c


def collect(app: appfiles.App) -> List[Dict[str, Any]]:
    """Inventory of third-party components present in the app."""
    found: Dict[Tuple[str, Any], Dict[str, Any]] = {}
    if app.platform == "android":
        for root in app.roots:
            names = []
            for full in app.files([root]):
                names.append(os.path.relpath(full, root).replace(os.sep, "/"))
            # Maven metadata left in the jars: exact coordinates
            for n in names:
                m = re.fullmatch(r"META-INF/maven/([^/]+)/([^/]+)/pom\.properties", n)
                if m:
                    props = _read_props(os.path.join(root, n))
                    ver = props.get("version")
                    if ver:
                        _add(found, {"name": f"{m.group(1)}:{m.group(2)}", "group": m.group(1), "artifact": m.group(2),
                                     "version": ver, "ecosystem": "Maven", "source": n, "type": "library"})
            # AndroidX / Google .version files and Google *.properties
            for item in engine.collect_android_sbom(root, names):
                name, ver, src = item["name"], item.get("version"), item.get("source", "")
                if not ver:
                    continue
                if src.endswith(".version") and ":" in name:
                    g, a = name.split(":", 1)
                    _add(found, {"name": name, "group": g, "artifact": a, "version": ver,
                                 "ecosystem": "Maven", "source": src, "type": "library"})
                else:
                    group = next((g for p, g in _GOOGLE_PREFIX if name.startswith(p)), None)
                    _add(found, {"name": f"{group}:{name}" if group else name, "group": group, "artifact": name,
                                 "version": ver, "ecosystem": "Maven" if group else None, "source": src,
                                 "type": "library"})
            # library self-reported versions in dex
            for n in names:
                if n.endswith(".dex"):
                    try:
                        with open(os.path.join(root, n), "rb") as fh:
                            blob = fh.read(60 << 20)
                    except OSError:
                        continue
                    for rx, g, a in _DEX_FINGERPRINTS:
                        m = rx.search(blob)
                        if not m:
                            continue
                        version = m.group(1).decode()
                        major = int(version.split(".")[0])
                        if a == "okhttp":
                            if major not in (2, 3, 4, 5):          # other libraries send "okhttp/1.x"-style strings
                                continue
                            if major == 2:                          # OkHttp 2 used the pre-okhttp3 coordinates
                                g = "com.squareup.okhttp"
                        _add(found, {"name": f"{g}:{a}", "group": g, "artifact": a,
                                     "version": version, "ecosystem": "Maven",
                                     "source": n + " (user-agent string)", "type": "library"})
    else:
        base = app.main_root
        if base:
            fw = os.path.join(base, "Frameworks")
            if os.path.isdir(fw):
                for d in sorted(os.listdir(fw)):
                    if not d.endswith(".framework"):
                        continue
                    try:
                        with open(os.path.join(fw, d, "Info.plist"), "rb") as fh:
                            info = plistlib.load(fh)
                    except Exception:
                        continue
                    name = d[:-len(".framework")]
                    ver = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
                    _add(found, {"name": name, "artifact": name, "version": ver, "bundle_id": info.get("CFBundleIdentifier"),
                                 "ecosystem": "SwiftURL" if name in IOS_SWIFTURL else None,
                                 "osv_name": IOS_SWIFTURL.get(name), "source": f"Frameworks/{d}", "type": "framework"})
    return sorted(found.values(), key=lambda c: (c["name"].lower(), str(c.get("version"))))


def _read_props(path: str) -> Dict[str, str]:
    props = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    props[k.strip()] = v.strip()
    except OSError:
        pass
    return props


# ----------------------------------------------------------------------------- OSV

def _cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    d = os.path.join(base, "appsleuth", "osv")
    os.makedirs(d, exist_ok=True)
    return d


def _cache_get(key: str, ttl: int = CACHE_TTL, allow_stale: bool = False):
    p = os.path.join(_cache_dir(), hashlib.sha256(key.encode()).hexdigest() + ".json")
    try:
        if allow_stale or time.time() - os.path.getmtime(p) < ttl:
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
    except (OSError, ValueError):
        pass
    return None


def _cache_put(key: str, value: Any):
    p = os.path.join(_cache_dir(), hashlib.sha256(key.encode()).hexdigest() + ".json")
    try:
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(value, fh)
    except OSError:
        pass


def _post_json(url: str, payload: Dict[str, Any], fetch) -> Optional[Dict[str, Any]]:
    status, _h, body = fetch(url, "POST", json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    return json.loads(body) if status == 200 else None


def _get_json(url: str, fetch) -> Optional[Dict[str, Any]]:
    status, _h, body = fetch(url, "GET")
    return json.loads(body) if status == 200 else None


def _osv_package(c: Dict[str, Any]) -> Optional[Dict[str, str]]:
    if c.get("ecosystem") == "Maven" and c.get("group") and c.get("version"):
        return {"name": f"{c['group']}:{c['artifact']}", "ecosystem": "Maven"}
    if c.get("ecosystem") == "SwiftURL" and c.get("osv_name") and c.get("version"):
        return {"name": c["osv_name"], "ecosystem": "SwiftURL"}
    return None


def _cvss3_score(vector: str) -> Optional[float]:
    """CVSS v3.x base score from a vector string."""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[parts["AV"]]
        ac = {"L": .77, "H": .44}[parts["AC"]]
        scope_changed = parts["S"] == "C"
        pr = {"N": .85, "L": .68 if scope_changed else .62, "H": .5 if scope_changed else .27}[parts["PR"]]
        ui = {"N": .85, "R": .62}[parts["UI"]]
        imp = {"H": .56, "L": .22, "N": 0}
        iss = 1 - (1 - imp[parts["C"]]) * (1 - imp[parts["I"]]) * (1 - imp[parts["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
        return round(-(-raw * 10 // 1) / 10, 1)               # round up to 1 decimal
    except (KeyError, ValueError):
        return None


def severity_of(vuln: Dict[str, Any]) -> Tuple[str, Optional[float]]:
    """-> (HIGH|MEDIUM|LOW, score). Uses CVSS when present, else the advisory's own label."""
    score = None
    for s in vuln.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3") and s.get("score"):
            score = _cvss3_score(s["score"])
            if score is not None:
                break
    if score is not None:
        return ("HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"), score
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if label in ("CRITICAL", "HIGH"):
        return "HIGH", None
    if label in ("MODERATE", "MEDIUM"):
        return "MEDIUM", None
    if label == "LOW":
        return "LOW", None
    return "MEDIUM", None            # unknown severity: not silently dropped, not alarming


def _fixed_versions(vuln: Dict[str, Any], pkg_name: str) -> List[str]:
    out = []
    for aff in vuln.get("affected") or []:
        if (aff.get("package") or {}).get("name") != pkg_name:
            continue
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    out.append(ev["fixed"])
    return sorted(set(out))


def lookup(components: List[Dict[str, Any]], *, fetch: Callable = netfetch.fetch, offline: bool = False,
           progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Annotate components with `vulns`. Returns {'queried': n, 'skipped': n, 'errors': [...]}."""
    stats = {"queried": 0, "skipped": 0, "errors": []}
    queries = []
    idx = []
    for i, c in enumerate(components):
        pkg = _osv_package(c)
        if pkg:
            queries.append({"package": pkg, "version": c["version"]})
            idx.append(i)
        else:
            stats["skipped"] += 1
    stats["queried"] = len(queries)
    results: List[Optional[List[str]]] = [None] * len(queries)
    # batch lookup (cached per query)
    to_fetch = []
    for qi, q in enumerate(queries):
        cached = _cache_get("q:" + json.dumps(q, sort_keys=True), allow_stale=offline)
        if cached is not None:
            results[qi] = cached
        else:
            to_fetch.append(qi)
    if to_fetch and not offline:
        for start in range(0, len(to_fetch), 500):
            chunk = to_fetch[start:start + 500]
            try:
                data = _post_json(OSV_BATCH, {"queries": [queries[i] for i in chunk]}, fetch)
            except (OSError, ValueError) as e:
                stats["errors"].append(f"OSV batch query failed: {e}")
                continue
            if not data:
                stats["errors"].append("OSV batch query returned an error")
                continue
            for qi, res in zip(chunk, data.get("results", [])):
                ids = [v["id"] for v in (res.get("vulns") or [])]
                results[qi] = ids
                _cache_put("q:" + json.dumps(queries[qi], sort_keys=True), ids)
    elif to_fetch:
        stats["errors"].append(f"{len(to_fetch)} component(s) not in the offline cache")
    # details
    details: Dict[str, Dict[str, Any]] = {}
    fetches = 0
    for ids in results:
        for vid in ids or []:
            if vid in details:
                continue
            cached = _cache_get("v:" + vid, allow_stale=offline)
            if cached is not None:
                details[vid] = cached
            elif not offline and fetches < MAX_DETAIL_FETCHES:
                fetches += 1
                try:
                    d = _get_json(OSV_VULN + vid, fetch)
                except (OSError, ValueError):
                    d = None
                if d:
                    details[vid] = d
                    _cache_put("v:" + vid, d)
    for qi, ci in enumerate(idx):
        c = components[ci]
        pkg = queries[qi]["package"]["name"]
        groups: Dict[str, Dict[str, Any]] = {}        # merge GHSA/CVE aliases into one advisory
        for vid in results[qi] or []:
            d = details.get(vid)
            if not d:
                groups.setdefault(vid, {"id": vid, "aliases": [], "summary": "(details unavailable)",
                                        "severity": "MEDIUM", "score": None, "fixed": []})
                continue
            ids = {d["id"], *d.get("aliases", [])}
            hit = next((g for g in groups.values() if ids & ({g["id"], *g["aliases"]})), None)
            sev, score = severity_of(d)
            entry = {"id": d["id"], "aliases": sorted(ids - {d["id"]}), "summary": (d.get("summary") or "")[:200],
                     "severity": sev, "score": score, "fixed": _fixed_versions(d, pkg)}
            if hit is None:
                groups[d["id"]] = entry
            else:                                       # keep the worst severity, union the rest
                hit["aliases"] = sorted(set(hit["aliases"]) | ids - {hit["id"]})
                if ("LOW", "MEDIUM", "HIGH").index(sev) > ("LOW", "MEDIUM", "HIGH").index(hit["severity"]):
                    hit["severity"], hit["score"] = sev, score
                hit["fixed"] = sorted(set(hit["fixed"]) | set(entry["fixed"]))
        c["vulns"] = sorted(groups.values(), key=lambda g: -("LOW", "MEDIUM", "HIGH").index(g["severity"]))
    return stats


def _cve_ids(v: Dict[str, Any]) -> str:
    ids = [i for i in [v["id"], *v["aliases"]] if i.startswith("CVE-")]
    return ids[0] if ids else v["id"]


def to_findings(components: List[Dict[str, Any]], looked_up: bool, stats: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    vulnerable = [c for c in components if c.get("vulns")]
    for c in vulnerable:
        vs = c["vulns"]
        worst = vs[0]["severity"]
        fixed = sorted({f for v in vs for f in v["fixed"]})
        shown = ", ".join(f"{_cve_ids(v)} ({v['severity'].lower()})" for v in vs[:6]) + (" ..." if len(vs) > 6 else "")
        out.append(appfiles.finding(
            worst, f"Known vulnerabilities in {c['name']} {c['version']} ({len(vs)})",
            "OSV.dev lists published advisories for exactly this package version. Presence in the app does not "
            "prove the vulnerable code is reachable (R8 may remove it, and many advisories need a specific usage). "
            "Check each advisory against how the app uses the library"
            + (f"; fixed in {', '.join(fixed[:4])}." if fixed else "."),
            evidence=shown, location=c.get("source"), confidence="heuristic"))
    out.append(appfiles.finding(
        "INFO", f"{len(components)} third-party component(s) inventoried",
        "Names and versions come from build metadata left in the app. Components without package metadata "
        "cannot be matched to advisories."
        + ("" if looked_up else " Vulnerability lookup was not run (use --cves)."),
        evidence=f"{sum(1 for c in components if c.get('version'))} with a version; "
                 f"{stats.get('queried', 0)} checked against OSV, {stats.get('skipped', 0)} not matchable"))
    for e in stats.get("errors", []):
        out.append(appfiles.finding("INFO", "Vulnerability lookup incomplete", e))
    return out


def to_cyclonedx(app: appfiles.App, components: List[Dict[str, Any]], tool_version: str) -> Dict[str, Any]:
    comps, vulns = [], []
    for c in components:
        ref = c.get("purl") or f"{c['name']}@{c.get('version') or 'unknown'}"
        entry = {"type": "framework" if c.get("type") == "framework" else "library", "bom-ref": ref,
                 "name": c.get("artifact") or c["name"], "version": c.get("version") or "unknown"}
        if c.get("group"):
            entry["group"] = c["group"]
        if c.get("purl"):
            entry["purl"] = c["purl"]
        comps.append(entry)
        for v in c.get("vulns") or []:
            vulns.append({"id": v["id"], "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{v['id']}"},
                          "ratings": [{"severity": v["severity"].lower(), **({"score": v["score"]} if v["score"] else {})}],
                          "description": v["summary"], "affects": [{"ref": ref}]})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"tools": [{"vendor": "Rudranetra", "name": "appsleuth", "version": tool_version}],
                         "component": {"type": "application", "name": app.package or os.path.basename(app.path),
                                       "version": (app.info_plist.get("CFBundleShortVersionString") if app.info_plist
                                                   else (app.manifest.get("versionName") if app.manifest else None)) or "unknown"}},
            "components": comps, **({"vulnerabilities": vulns} if vulns else {})}


def run(path: str, *, cves: bool = False, offline: bool = False,
        fetch: Callable = netfetch.fetch) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """-> (scan-style result, CycloneDX document)."""
    from . import __version__
    with appfiles.unpacked(path) as app:
        comps = collect(app)
        stats = {"queried": 0, "skipped": 0, "errors": []}
        if cves or offline:
            stats = lookup(comps, fetch=fetch, offline=offline)
        findings = to_findings(comps, cves or offline, stats)
        result = appfiles.new_result(app, "sbom", findings, {"components": comps, "lookup": stats})
        return result, to_cyclonedx(app, comps, __version__)
