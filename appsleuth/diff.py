"""Build-to-build comparison (`appsleuth diff old new`).

Three layers, from cheap to expensive:
  1. artifact diff   - what changed inside the package (files added/removed/modified, by category)
  2. posture diff    - permissions, components, entitlements, signer, risky flags, hosts, libraries
  3. finding diff    - findings that are new / resolved / changed severity

and a distilled list of REGRESSIONS: changes that make the new build weaker than the old one.
"""
import os
import re
import zipfile
from typing import Any, Callable, Dict, List, Tuple

from . import info as info_mod

_SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

# Flags that, when switched ON in the new build, are regressions (and how bad).
RISK_FLAGS = {
    "debuggable": "HIGH", "get_task_allow": "HIGH", "ats_disabled": "HIGH", "cleartext_allowed": "HIGH",
    "remote_web_content": "HIGH", "cordova_access_any_origin": "MEDIUM", "cordova_navigation_any_host": "MEDIUM", "cordova_intent_any_url": "MEDIUM", "capacitor_navigation_any_host": "MEDIUM", "user_ca_trusted": "MEDIUM", "webview_debugging": "MEDIUM",
    "allow_backup": "MEDIUM", "file_sharing": "MEDIUM", "no_cert_pinning": "LOW",
}


# ---------------------------------------------------------------- artifact layer

def _norm_name(name: str) -> str:
    """Strip Payload/<App>.app/ so a renamed .app does not make every file look changed."""
    return re.sub(r"^Payload/[^/]+\.app/", "", name)


def _category(name: str, kind: str) -> str:
    n = name.lower()
    if kind in ("apks",):
        return "split apk"
    if kind == "ipa":
        if n.startswith("frameworks/"):
            return "frameworks"
        if n.startswith("plugins/"):
            return "app extensions"
        if n.startswith(("public/", "www/")):
            return "web layer"
        if n.startswith("_codesignature") or n.endswith(".mobileprovision"):
            return "signing"
        if n.endswith((".car", ".nib", ".storyboardc", ".png", ".jpg", ".lproj/localizable.strings")) or "/" in n and ".lproj" in n:
            return "resources"
        if n == "info.plist" or n.endswith(".plist"):
            return "plists"
        if "/" not in n and "." not in n:
            return "code (main binary)"
        return "other"
    if re.match(r"classes\d*\.dex$", n):
        return "code (dex)"
    if n.startswith("lib/"):
        return "native libs"
    if n.startswith("assets/"):
        return "assets"
    if n.startswith("res/") or n == "resources.arsc":
        return "resources"
    if n.startswith("meta-inf/"):
        return "signing/meta"
    if n == "androidmanifest.xml":
        return "manifest"
    return "other"


def zip_inventory(path: str) -> Dict[str, Tuple[int, int]]:
    inv = {}
    if not zipfile.is_zipfile(path):
        return inv
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            if not i.filename.endswith("/"):
                inv[_norm_name(i.filename)] = (i.CRC, i.file_size)
    return inv


def artifact_diff(old_path: str, new_path: str, kind: str) -> Dict[str, Any]:
    old, new = zip_inventory(old_path), zip_inventory(new_path)
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    modified = sorted(n for n in set(old) & set(new) if old[n][0] != new[n][0])
    cats: Dict[str, Dict[str, int]] = {}
    for kindname, names in (("added", added), ("removed", removed), ("modified", modified)):
        for n in names:
            c = cats.setdefault(_category(n, kind), {"added": 0, "removed": 0, "modified": 0, "bytes_delta": 0})
            c[kindname] += 1
            if kindname == "added":
                c["bytes_delta"] += new[n][1]
            elif kindname == "removed":
                c["bytes_delta"] -= old[n][1]
            else:
                c["bytes_delta"] += new[n][1] - old[n][1]
    return {
        "added": added, "removed": removed, "modified": modified,
        "unchanged": len(set(old) & set(new)) - len(modified),
        "by_category": dict(sorted(cats.items())),
        "size_old": sum(v[1] for v in old.values()), "size_new": sum(v[1] for v in new.values()),
    }


# ----------------------------------------------------------------- posture layer

def _sets(a, b) -> Dict[str, List[str]]:
    a, b = set(a or []), set(b or [])
    return {"added": sorted(b - a), "removed": sorted(a - b)}


def _comp_labels(s):
    return [f"{c['type']}:{c['name']}" + ("" if c.get("permission") else " (no permission)")
            for c in (s.get("exported_components") or []) if not c.get("launcher")]


def _dict_changes(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    a, b = a or {}, b or {}
    return {
        "added": {k: b[k] for k in sorted(set(b) - set(a), key=str)},
        "removed": {k: a[k] for k in sorted(set(a) - set(b), key=str)},
        "changed": {k: {"old": a[k], "new": b[k]} for k in sorted(set(a) & set(b), key=str) if a[k] != b[k]},
    }


def _num(x):
    """Version -> comparable tuple: 34 -> (34,), '15.6' -> (15, 6). None if unparseable."""
    if x is None:
        return None
    parts = re.findall(r"\d+", str(x))
    return tuple(int(p) for p in parts) if parts else None


def _vs(t) -> str:
    return ".".join(str(i) for i in t)


def posture_diff(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "version": {"old": a.get("version"), "new": b.get("version")},
        "build": {"old": a.get("build"), "new": b.get("build")},
        "min_os": {"old": a.get("min_os"), "new": b.get("min_os")},
        "target_sdk": {"old": a.get("target_sdk"), "new": b.get("target_sdk")},
        "permissions": _sets(a.get("permissions"), b.get("permissions")),
        "exported_components": _sets(_comp_labels(a), _comp_labels(b)),
        "url_schemes": _sets(a.get("url_schemes"), b.get("url_schemes")),
        "associated_domains": _sets(a.get("associated_domains"), b.get("associated_domains")),
        "libraries": _sets(a.get("libraries"), b.get("libraries")),
        "entitlements": _dict_changes(a.get("entitlements"), b.get("entitlements")),
        "flags": {k: {"old": a.get("flags", {}).get(k, False), "new": b.get("flags", {}).get(k, False)}
                  for k in sorted(set(a.get("flags", {})) | set(b.get("flags", {})))
                  if a.get("flags", {}).get(k, False) != b.get("flags", {}).get(k, False)},
        "signer": {"old": a.get("signer"), "new": b.get("signer")},
        "hybrid_hosts": _sets((a.get("hybrid") or {}).get("external_hosts"), (b.get("hybrid") or {}).get("external_hosts")),
        "hybrid_plugins": _sets((a.get("hybrid") or {}).get("plugins"), (b.get("hybrid") or {}).get("plugins")),
    }
    old_sb = {e["name"]: e.get("version") for e in a.get("sbom") or []}
    new_sb = {e["name"]: e.get("version") for e in b.get("sbom") or []}
    d["sbom"] = {"added": sorted(set(new_sb) - set(old_sb)), "removed": sorted(set(old_sb) - set(new_sb)),
                 "version_changed": sorted(f"{k}: {old_sb[k]} -> {new_sb[k]}" for k in set(old_sb) & set(new_sb)
                                           if old_sb[k] != new_sb[k])}
    return d


# --------------------------------------------------------------------- findings

def _fp(f: Dict[str, Any]) -> str:
    """Identity of a finding across builds: counts and DEX method refs shift, so normalise them."""
    title = re.sub(r"\d+", "N", f.get("title", ""))
    loc = (f.get("location") or "").split(" [")[0]
    loc = re.sub(r"[^\s/\\]+\.(?:ipa|apk|apks|xapk|aab)", "<app>", loc)     # the file name is not part of identity
    return f"{title}|{loc}"


def finding_diff(old_f: List[Dict[str, Any]], new_f: List[Dict[str, Any]]) -> Dict[str, Any]:
    o = {_fp(f): f for f in old_f}
    n = {_fp(f): f for f in new_f}
    changed = [{"title": n[k]["title"], "old": o[k]["severity"], "new": n[k]["severity"]}
               for k in sorted(set(o) & set(n)) if o[k]["severity"] != n[k]["severity"]]
    return {"new": [n[k] for k in sorted(set(n) - set(o), key=lambda k: -_SEV[n[k]["severity"]])],
            "resolved": [o[k] for k in sorted(set(o) - set(n), key=lambda k: -_SEV[o[k]["severity"]])],
            "severity_changed": changed}


# -------------------------------------------------------------------- regressions

def regressions(old: Dict[str, Any], new: Dict[str, Any], p: Dict[str, Any], fd: Dict[str, Any]) -> List[Dict[str, str]]:
    R: List[Dict[str, str]] = []

    def add(sev, text):
        R.append({"severity": sev, "text": text})

    # signer
    so, sn = old.get("signer") or {}, new.get("signer") or {}
    if new["platform"] == "android":
        if so.get("sha256") and sn.get("sha256") and set(so["sha256"]) != set(sn["sha256"]):
            add("HIGH", "Signing certificate changed (users cannot upgrade in place; check this is intentional)")
    elif so.get("team_id") and sn.get("team_id") and so["team_id"] != sn["team_id"]:
        add("HIGH", f"Team ID changed: {so['team_id']} -> {sn['team_id']}")

    for flag, d in p["flags"].items():
        if d["new"] and not d["old"] and flag in RISK_FLAGS:
            add(RISK_FLAGS[flag], f"New risky setting: {flag.replace('_', ' ')}")

    dangerous = set(new.get("dangerous_permissions") or []) - set(old.get("dangerous_permissions") or [])
    for perm in sorted(dangerous):
        add("MEDIUM", f"New dangerous permission: {perm}")
    if new["platform"] == "ios":
        for perm in p["permissions"]["added"]:
            add("LOW", f"New permission requested: {perm}")
    elif not dangerous:
        for perm in p["permissions"]["added"]:
            add("INFO", f"New permission: {perm}")

    for comp in p["exported_components"]["added"]:
        add("MEDIUM" if comp.endswith("(no permission)") else "LOW", f"New exported component: {comp}")
    for sc in p["url_schemes"]["added"]:
        add("LOW", f"New custom URL scheme: {sc}://")
    for k, v in p["entitlements"]["added"].items():
        add("HIGH" if k == "get-task-allow" and v else "LOW", f"New entitlement: {k} = {str(v)[:60]}")

    t_o, t_n = _num(old.get("target_sdk")), _num(new.get("target_sdk"))
    if t_o is not None and t_n is not None and t_n < t_o:
        add("MEDIUM", f"targetSdkVersion lowered: {_vs(t_o)} -> {_vs(t_n)}")
    m_o, m_n = _num(old.get("min_os")), _num(new.get("min_os"))
    if m_o is not None and m_n is not None and m_n < m_o:
        add("LOW", f"Minimum OS lowered: {_vs(m_o)} -> {_vs(m_n)} (supports older, less hardened releases)")

    for host in p["hybrid_hosts"]["added"][:15]:
        add("INFO", f"New external host in web layer: {host}")
    for lib in p["sbom"]["added"][:15]:
        add("INFO", f"New third-party library: {lib}")

    for f in fd["new"]:
        if f["severity"] in ("HIGH", "MEDIUM"):
            add(f["severity"], f"New finding: {f['title']}")
    for c in fd["severity_changed"]:
        if _SEV[c["new"]] > _SEV[c["old"]] and c["new"] in ("HIGH", "MEDIUM"):
            add(c["new"], f"Finding got worse ({c['old']} -> {c['new']}): {c['title']}")

    R.sort(key=lambda r: -_SEV[r["severity"]])
    return R


# -------------------------------------------------------------------------- API

def endpoint_diff(old_path: str, new_path: str) -> Dict[str, Any]:
    """New and removed network hosts between two builds."""
    from . import endpoints
    try:
        old_h, new_h = endpoints.host_set(old_path), endpoints.host_set(new_path)
    except Exception as e:                       # never let this break the rest of the diff
        return {"added": [], "removed": [], "regressions": [], "error": str(e)[:200]}
    added = sorted(set(new_h) - set(old_h))
    removed = sorted(set(old_h) - set(new_h))
    regs = []
    for h in added:
        flags = new_h[h].get("flags") or []
        risky = [f for f in flags if f in ("raw IP address", "cleartext scheme seen") or "non-prod" in f.lower()]
        regs.append({"severity": "MEDIUM" if risky else "LOW",
                     "text": f"New network host: {h}" + (f" ({', '.join(risky)})" if risky else "")})
    return {"added": added, "removed": removed, "regressions": regs}


def diff_builds(old_path: str, new_path: str, scan_fn: Callable[[str], Dict[str, Any]]) -> Dict[str, Any]:
    old_res, new_res = scan_fn(old_path), scan_fn(new_path)
    old_s, new_s = info_mod.summarize(old_res, old_path), info_mod.summarize(new_res, new_path)
    out: Dict[str, Any] = {
        "old": {"file": os.path.abspath(old_path), "id": old_s.get("id"), "version": old_s.get("version"),
                "kind": old_s.get("kind"), "sha256": (old_s.get("file") or {}).get("sha256"),
                "counts": old_res.get("summary")},
        "new": {"file": os.path.abspath(new_path), "id": new_s.get("id"), "version": new_s.get("version"),
                "kind": new_s.get("kind"), "sha256": (new_s.get("file") or {}).get("sha256"),
                "counts": new_res.get("summary")},
        "warnings": [],
    }
    if old_s["platform"] != new_s["platform"]:
        out["warnings"].append(f"Comparing different platforms ({old_s['platform']} vs {new_s['platform']}); "
                               "results are not meaningful.")
    if old_s.get("id") != new_s.get("id"):
        out["warnings"].append(f"Different app identifiers: {old_s.get('id')} vs {new_s.get('id')}")
    if out["old"]["sha256"] and out["old"]["sha256"] == out["new"]["sha256"]:
        out["warnings"].append("The two files are byte-for-byte identical.")
    out["artifact"] = artifact_diff(old_path, new_path, new_s.get("kind"))
    out["posture"] = posture_diff(old_s, new_s)
    out["findings"] = finding_diff(old_res.get("findings", []), new_res.get("findings", []))
    out["regressions"] = regressions(old_s, new_s, out["posture"], out["findings"])
    out["endpoints"] = endpoint_diff(old_path, new_path)
    out["regressions"].extend(out["endpoints"]["regressions"])
    return out


# ---------------------------------------------------------------------- rendering

def _fmt_bytes(n: int) -> str:
    sign = "-" if n < 0 else "+"
    n = abs(n)
    return f"{sign}{n / 1e6:.2f} MB" if n >= 1e6 else f"{sign}{n / 1e3:.1f} KB" if n >= 1e3 else f"{sign}{n} B"


def render_markdown(d: Dict[str, Any]) -> str:
    o, n, p, a, f = d["old"], d["new"], d["posture"], d["artifact"], d["findings"]
    L = [f"# Build diff: {os.path.basename(o['file'])} → {os.path.basename(n['file'])}", ""]
    L.append(f"- App: `{n['id']}`   Version: `{o['version']}` → `{n['version']}`")
    for w in d["warnings"]:
        L.append(f"- ⚠ {w}")
    L.append("")
    regs = d["regressions"]
    L.append(f"## Regressions ({len([r for r in regs if r['severity'] != 'INFO'])} notable, {len(regs)} total)")
    if not regs:
        L.append("None found.")
    for r in regs:
        L.append(f"- **[{r['severity']}]** {r['text']}")
    L.append("")

    def sect(title, sets):
        if sets.get("added") or sets.get("removed"):
            L.append(f"## {title}")
            L.extend(f"- + `{x}`" for x in sets["added"])
            L.extend(f"- − `{x}`" for x in sets["removed"])
            L.append("")

    sect("Permissions", p["permissions"])
    sect("Exported components", p["exported_components"])
    sect("URL schemes", p["url_schemes"])
    sect("Associated domains", p["associated_domains"])
    sect("Libraries / frameworks", p["libraries"])
    sect("Network hosts", d.get("endpoints", {}))
    sect("Web-layer hosts", p["hybrid_hosts"])
    sect("Hybrid plugins", p["hybrid_plugins"])
    sect("Third-party libraries (SBOM)", {"added": p["sbom"]["added"], "removed": p["sbom"]["removed"]})
    if p["sbom"]["version_changed"]:
        L.append("## Library version changes")
        L.extend(f"- ~ `{x}`" for x in p["sbom"]["version_changed"])
        L.append("")
    ec = p["entitlements"]
    if ec["added"] or ec["removed"] or ec["changed"]:
        L.append("## Entitlements")
        L.extend(f"- + `{k}` = {str(v)[:60]}" for k, v in ec["added"].items())
        L.extend(f"- − `{k}`" for k in ec["removed"])
        L.extend(f"- ~ `{k}`: {str(v['old'])[:40]} → {str(v['new'])[:40]}" for k, v in ec["changed"].items())
        L.append("")
    if p["flags"]:
        L.append("## Posture flags")
        L.extend(f"- `{k}`: {v['old']} → {v['new']}" for k, v in p["flags"].items())
        L.append("")
    for key, label in (("min_os", "Min OS/SDK"), ("target_sdk", "Target SDK")):
        if p[key]["old"] != p[key]["new"]:
            L.append(f"- {label}: `{p[key]['old']}` → `{p[key]['new']}`")
    L.append("")

    L.append("## Package contents")
    L.append(f"Size {a['size_old'] / 1e6:.1f} MB → {a['size_new'] / 1e6:.1f} MB "
             f"({_fmt_bytes(a['size_new'] - a['size_old'])}); "
             f"{len(a['added'])} added, {len(a['removed'])} removed, {len(a['modified'])} modified, {a['unchanged']} unchanged.")
    if a["by_category"]:
        L.append("")
        L.append("| Category | Added | Removed | Modified | Size change |")
        L.append("|---|---|---|---|---|")
        for cat, c in a["by_category"].items():
            L.append(f"| {cat} | {c['added']} | {c['removed']} | {c['modified']} | {_fmt_bytes(c['bytes_delta'])} |")
    L.append("")
    for title, key in (("Added files", "added"), ("Removed files", "removed"), ("Modified files", "modified")):
        if a[key]:
            L.append(f"<details><summary>{title} ({len(a[key])})</summary>\n")
            L.extend(f"- `{x}`" for x in a[key][:200])
            if len(a[key]) > 200:
                L.append(f"- … {len(a[key]) - 200} more")
            L.append("\n</details>\n")

    L.append(f"## Findings: {len(f['new'])} new, {len(f['resolved'])} resolved, {len(f['severity_changed'])} changed severity")
    for x in f["new"]:
        L.append(f"- 🆕 **[{x['severity']}]** {x['title']}")
    for x in f["resolved"]:
        L.append(f"- ✅ **[{x['severity']}]** {x['title']}")
    for x in f["severity_changed"]:
        L.append(f"- ↕ {x['title']}: {x['old']} → {x['new']}")
    return "\n".join(L) + "\n"
