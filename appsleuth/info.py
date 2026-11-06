"""App inspection: a normalised, platform-independent summary of an APK / APKS / XAPK /
AAB / IPA. This is the data model shared by `appsleuth info` and `appsleuth diff`."""
import hashlib
import os
from typing import Any, Dict, List, Optional

from . import engine

# Boolean "posture" flags, derived from findings so that scan, info and diff all agree.
FLAG_TITLES = {
    "debuggable": ("android:debuggable",),
    "allow_backup": ("android:allowBackup",),
    "cleartext_allowed": ("android:usesCleartextTraffic", "Cleartext traffic permitted for specific",
                          "Cleartext HTTP allowed for domain", "Capacitor cleartext traffic enabled"),
    "ats_disabled": ("App Transport Security disabled globally",),
    "user_ca_trusted": ("Network Security Config trusts user-installed CAs",),
    "no_cert_pinning": ("No certificate pinning configured",),
    "get_task_allow": ("Provisioning profile allows debugging",),
    "webview_debugging": ("WebView debugging enabled in release config",),
    "remote_web_content": ("Capacitor loads app content from a remote URL",),
    "main_binary_encrypted": ("Main binary is still FairPlay-encrypted",),
    "file_sharing": ("iTunes/Finder file sharing enabled",),
}


def file_digests(path: str) -> Dict[str, Any]:
    sha, md = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)
            md.update(chunk)
    return {"name": os.path.basename(path), "size": os.path.getsize(path),
            "sha256": sha.hexdigest(), "md5": md.hexdigest()}


def _flags(findings: List[Dict[str, Any]]) -> Dict[str, bool]:
    titles = [f.get("title", "") for f in findings]
    return {flag: any(t.startswith(prefixes) for t in titles) for flag, prefixes in FLAG_TITLES.items()}


def _base_meta(meta: Dict[str, Any]) -> Dict[str, Any]:
    """For split bundles, the base split carries the app's identity and manifest."""
    for sp in meta.get("splits", []) or []:
        if sp.get("name") == meta.get("base_split"):
            return sp.get("meta", {})
    return meta


def summarize(result: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    """Normalise a scan result (engine.scan output) into a flat, comparable summary."""
    kind = result.get("detected_type")
    meta = result.get("meta", {})
    m = _base_meta(meta) if kind == "apks" else meta
    findings = result.get("findings", [])
    s: Dict[str, Any] = {
        "kind": kind,
        "platform": "ios" if kind == "ipa" else "android",
        "file": file_digests(path or result.get("input_file")) if (path or result.get("input_file")) and
                os.path.isfile(path or result.get("input_file")) else {},
        "flags": _flags(findings),
        "warnings": coverage_warnings(result),
    }

    if kind == "ipa":
        ents = m.get("entitlements") or {}
        team = None
        appid = ents.get("application-identifier") or ents.get("com.apple.application-identifier")
        if isinstance(appid, str) and "." in appid:
            team = appid.split(".", 1)[0]
        prov = m.get("provisioning") or {}
        if not team:
            ti = prov.get("TeamIdentifier")
            if isinstance(ti, list) and ti:
                team = ti[0]
        usage = m.get("permission_usage_descriptions") or {}
        s.update({
            "id": m.get("bundle_id"), "name": m.get("name"), "version": m.get("version"), "build": m.get("build"),
            "min_os": m.get("min_os"), "executable": m.get("executable"),
            "permissions": sorted(usage),
            "permission_purposes": usage,
            "url_schemes": sorted(m.get("custom_url_schemes") or []),
            "queries_schemes": sorted(m.get("queries_schemes") or []),
            "entitlements": ents,
            "associated_domains": sorted(m.get("associated_domains") or []),
            "libraries": sorted(m.get("embedded_frameworks") or []),
            "ats": m.get("ats") or {},
            "signer": {"team_id": team},
            "provisioning": prov,
            "encryption": m.get("macho_encryption_verified") or m.get("macho_encryption") or [],
            "embedded_binaries_still_encrypted": m.get("embedded_binaries_still_encrypted") or [],
            "hybrid": m.get("hybrid") or {},
            "privacy_manifests": sorted((m.get("privacy_manifests") or {}).keys()),
            "firebase": m.get("google_service_info") or {},
            "hardening": m.get("macho_hardening") or {},
        })
    else:
        perms = sorted(m.get("permissions") or [])
        certs = m.get("signing_certs") or []
        s.update({
            "id": m.get("package"), "version": m.get("versionName"), "build": m.get("versionCode"),
            "min_os": m.get("minSdkVersion"), "target_sdk": m.get("targetSdkVersion"),
            "name": m.get("app_label_resolved"),
            "permissions": perms,
            "dangerous_permissions": sorted(set(perms) & engine.DANGEROUS_PERMISSIONS),
            "exported_components": [c for c in (m.get("exported_components") or [])],
            "libraries": sorted(m.get("native_libraries") or []),
            "dex_files": m.get("dex_files") or [],
            "signer": {"schemes": m.get("signing_schemes") or [],
                       "sha256": sorted({c.get("sha256_fingerprint") for c in certs if c.get("sha256_fingerprint")}),
                       "subjects": list(dict.fromkeys(c.get("subject") for c in certs if c.get("subject")))},
            "network_security_config": m.get("networkSecurityConfig_resolved"),
            "sbom": m.get("sbom") or [],
            "firebase": m.get("google_firebase_config") or {},
            "splits": [sp.get("name") for sp in (meta.get("splits") or [])],
            "native_hardening": m.get("native_library_hardening") or [],
        })
    s["sbom"] = s.get("sbom") or []
    s["counts"] = result.get("summary", {})
    return s


# ------------------------------------------------------------------ rendering

def _kv(lines: List[str], label: str, value: Any):
    if value in (None, "", [], {}):
        return
    lines.append(f"  {label:<18}{value}")


def coverage_warnings(result: Dict[str, Any]) -> List[str]:
    """Conditions under which the scan could not see the app's real code, so a clean
    result must not be read as 'secure'."""
    meta = result.get("meta", {}) or {}
    out: List[str] = []
    verified = meta.get("macho_encryption_verified") or []
    if any(isinstance(e, dict) and e.get("verdict") == "ciphertext" for e in verified):
        out.append("The main binary is still FairPlay-encrypted. Its code and strings were NOT scanned, "
                   "so this result is incomplete. Re-dump the app decrypted (e.g. getipa --decrypted) and scan again.")
    bad = meta.get("embedded_binaries_still_encrypted") or []
    if bad:
        only_ext = all(b.endswith(".appex") for b in bad)
        out.append(("App extension(s) still encrypted and not scanned (usually minor): " if only_ext
                    else "Still-encrypted embedded binaries were not scanned: ")
                   + ", ".join(bad[:6]) + (" ..." if len(bad) > 6 else ""))
    return out


def render_text(s: Dict[str, Any], *, full: bool = False) -> str:
    L: List[str] = []
    for w in s.get("warnings") or []:
        L.append(f"!! WARNING: {w}")
    if s.get("warnings"):
        L.append("")
    title = s.get("name") or s.get("id") or "?"
    L.append(f"{title}  ({s.get('id')})" if title != s.get("id") else title)
    L.append("=" * min(78, len(L[0])))
    f = s.get("file") or {}
    _kv(L, "File", f.get("name"))
    _kv(L, "Type", f"{(s.get('kind') or '?').upper()} ({s['platform']})")
    _kv(L, "Version", f"{s.get('version')} (build {s.get('build')})" if s.get("version") or s.get("build") else None)
    if s["platform"] == "ios":
        _kv(L, "Min iOS", s.get("min_os"))
        _kv(L, "Executable", s.get("executable"))
    else:
        _kv(L, "Min / target SDK", f"{s.get('min_os')} / {s.get('target_sdk')}")
    _kv(L, "Size", f"{f['size'] / 1e6:.1f} MB" if f.get("size") else None)
    _kv(L, "SHA-256", f.get("sha256"))
    _kv(L, "MD5", f.get("md5"))

    L.append("")
    L.append("Signing")
    sg = s.get("signer") or {}
    if s["platform"] == "ios":
        _kv(L, "Team ID", sg.get("team_id"))
        enc = s.get("encryption") or []
        if enc:
            verdicts = sorted({e.get("verdict", "?") for e in enc if isinstance(e, dict)})
            _kv(L, "Main binary", ", ".join(verdicts))
        _kv(L, "Still encrypted", ", ".join(s.get("embedded_binaries_still_encrypted") or []) or None)
    else:
        _kv(L, "Schemes", ", ".join(sg.get("schemes") or []))
        for fp in dict.fromkeys(sg.get("sha256") or []):
            _kv(L, "Cert SHA-256", fp)
        for subj in sg.get("subjects") or []:
            _kv(L, "Subject", subj)

    L.append("")
    L.append("Posture")
    for flag, on in sorted(s.get("flags", {}).items()):
        if on:
            L.append(f"  ! {flag.replace('_', ' ')}")
    if not any(s.get("flags", {}).values()):
        L.append("  (no risky flags)")

    perms = s.get("permissions") or []
    L.append("")
    if s["platform"] == "ios":
        L.append(f"Permissions requested ({len(perms)})")
        purposes = s.get("permission_purposes") or {}
        for p in perms[: (len(perms) if full else 12)]:
            L.append(f"  {p}: {str(purposes.get(p, ''))[:70]}")
    else:
        dang = set(s.get("dangerous_permissions") or [])
        L.append(f"Permissions ({len(perms)}, {len(dang)} dangerous)")
        for p in perms[: (len(perms) if full else 15)]:
            L.append(f"  {'!' if p in dang else ' '} {p}")
    if not full and len(perms) > 15:
        L.append(f"  … {len(perms) - 15} more (use --full)")

    if s["platform"] == "ios":
        ents = s.get("entitlements") or {}
        if ents:
            L.append("")
            L.append(f"Entitlements ({len(ents)})")
            for k in sorted(ents)[: (len(ents) if full else 12)]:
                v = ents[k]
                L.append(f"  {k}: {str(v)[:70]}")
        _kv(L, "URL schemes", ", ".join(s.get("url_schemes") or []))
        _kv(L, "Associated domains", ", ".join(s.get("associated_domains") or []))
        ats = s.get("ats")
        _kv(L, "ATS", "default" if not ats else ", ".join(sorted(ats)))
    else:
        comps = [c for c in (s.get("exported_components") or []) if not c.get("launcher")]
        L.append("")
        L.append(f"Exported components ({len(comps)})")
        for c in comps[: (len(comps) if full else 10)]:
            L.append(f"  {c['type']}: {c['name']}" + ("" if c.get("permission") else "   (no permission)"))
        if not full and len(comps) > 10:
            L.append(f"  … {len(comps) - 10} more (use --full)")
        _kv(L, "Network sec. config", s.get("network_security_config"))

    libs = s.get("libraries") or []
    L.append("")
    L.append(f"{'Frameworks' if s['platform'] == 'ios' else 'Native libraries'} ({len(libs)})")
    if libs:
        L.append("  " + ", ".join(libs[: (len(libs) if full else 12)]) + ("" if full or len(libs) <= 12 else f" … +{len(libs) - 12}"))

    hy = s.get("hybrid") or {}
    if hy:
        L.append("")
        L.append(f"Hybrid app: {hy.get('framework')}  (web layer: {hy.get('web_files_scanned')} files)")
        _kv(L, "Plugins", ", ".join(hy.get("plugins") or []))
        _kv(L, "External hosts", ", ".join((hy.get("external_hosts") or [])[: (60 if full else 8)]))

    sb = s.get("sbom") or []
    if sb:
        L.append("")
        L.append(f"Third-party libraries ({len(sb)})")
        L.append("  " + ", ".join(f"{e['name']}={e.get('version')}" for e in sb[: (len(sb) if full else 10)]))

    c = s.get("counts") or {}
    if c:
        L.append("")
        L.append(f"Scan: {c.get('HIGH', 0)} High, {c.get('MEDIUM', 0)} Medium, {c.get('LOW', 0)} Low, {c.get('INFO', 0)} Info")
    return "\n".join(L)
