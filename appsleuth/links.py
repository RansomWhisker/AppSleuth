"""Deep-link analysis: Android intent filters (App Links / custom schemes) and iOS URL schemes
and Universal Links, with optional verification of the domain-association files.

Offline part: parse what the app *declares*. Network part (opt-in, `--check-network`): fetch
`/.well-known/assetlinks.json` or `apple-app-site-association` from each declared domain and
confirm they actually authorise this app. A declared link whose association file is missing or
names another signer will silently fall back to the disambiguation dialog (Android) or open in
the browser (iOS), which is when link hijacking becomes possible.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Callable, Dict, List, Optional, Set

from . import appfiles, engine, netfetch

GENERIC_SCHEMES = {"app", "myapp", "mobile", "android", "ios", "open", "deeplink", "link", "native", "main", "http", "https"}
SAFE_SCHEMES_IOS = {"http", "https", "tel", "mailto", "sms"}


def _exported_state(comp, targetsdk: int) -> bool:
    ex = comp.get("exported")
    if ex in ("true", True):
        return True
    if ex in ("false", False):
        return False
    return bool(comp.find_all("intent-filter")) and targetsdk < 31


def android_filters(root, package: str) -> List[Dict[str, Any]]:
    """One dict per intent-filter that can be reached from a link / external intent."""
    app = next(iter(root.find_all("application")), None)
    if app is None:
        return []
    try:
        targetsdk = int(next(iter(root.find_all("uses-sdk")), None).get("targetSdkVersion") or 0)
    except (AttributeError, TypeError, ValueError):
        targetsdk = 0
    out = []
    for tag in ("activity", "activity-alias"):
        for comp in app.find_all(tag):
            name = comp.get("name") or "?"
            if name.startswith("."):
                name = package + name
            for f in comp.find_all("intent-filter"):
                actions = {a.get("name") for a in f.find_all("action")}
                cats = {c.get("name") for c in f.find_all("category")}
                datas = f.find_all("data")
                schemes = sorted({d.get("scheme") for d in datas if d.get("scheme")})
                hosts = sorted({d.get("host") for d in datas if d.get("host")})
                paths = sorted({d.get("path") or d.get("pathPrefix") or d.get("pathPattern") or d.get("pathAdvancedPattern")
                                for d in datas if (d.get("path") or d.get("pathPrefix") or d.get("pathPattern")
                                                   or d.get("pathAdvancedPattern"))})
                if "android.intent.action.VIEW" not in actions or not schemes:
                    continue
                out.append({
                    "activity": name, "schemes": schemes, "hosts": hosts, "paths": paths,
                    "browsable": "android.intent.category.BROWSABLE" in cats,
                    "auto_verify": f.get("autoVerify") == "true",
                    "exported": _exported_state(comp, targetsdk),
                    "permission": comp.get("permission"),
                    "launcher": "android.intent.category.LAUNCHER" in cats,
                })
    return out


def android_findings(filters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    web = [f for f in filters if set(f["schemes"]) & {"http", "https"} and f["browsable"]]
    custom = [f for f in filters if f["browsable"] and set(f["schemes"]) - {"http", "https"}]
    if filters:
        out.append(appfiles.finding(
            "INFO", f"{len(filters)} deep-link intent filter(s)",
            "Entry points reachable from links or other apps. Each one is attack surface: the URL parameters "
            "reach the activity's code.",
            evidence="; ".join(f"{f['activity'].rsplit('.', 1)[-1]}: {','.join(f['schemes'])}://{','.join(f['hosts']) or '*'}"
                               for f in filters[:8])))
    unverified = sorted({h for f in web if not f["auto_verify"] for h in (f["hosts"] or ["(any host)"])})
    if unverified:
        out.append(appfiles.finding(
            "LOW", "http(s) deep links without Android App Links verification",
            "Without android:autoVerify=\"true\" and a matching assetlinks.json, another app can register the same "
            "links and be offered (or silently chosen) instead.", evidence=", ".join(unverified[:8]), confidence="confirmed"))
    nohost = [f for f in web if not f["hosts"]]
    if nohost:
        out.append(appfiles.finding(
            "LOW", "http(s) intent filter with no host restriction",
            "The filter matches links on any website, which is almost never intended and widens the surface.",
            evidence=", ".join(f["activity"] for f in nohost[:5]), confidence="confirmed"))
    wild = [f for f in web if any(h.startswith("*") for h in f["hosts"]) or any(p in (".*", "/.*", "*") for p in f["paths"])]
    if wild:
        out.append(appfiles.finding(
            "INFO", "Broad wildcard in deep-link host or path",
            "Wildcard hosts/paths make every subdomain or path a valid entry. Check that all of them are intended.",
            evidence=", ".join(f["activity"].rsplit('.', 1)[-1] for f in wild[:5])))
    seen = set()
    for f in custom:
        for s in f["schemes"]:
            if s in ("http", "https") or s in seen:
                continue
            seen.add(s)
            generic = s.lower() in GENERIC_SCHEMES
            out.append(appfiles.finding(
                "LOW" if generic else "INFO", f"Custom URL scheme `{s}://` handled by {f['activity'].rsplit('.', 1)[-1]}",
                "Custom schemes cannot be verified: any app can register the same scheme and receive the link. Never "
                "pass tokens or sensitive actions through them (use App Links)."
                + (" The scheme name is generic, which makes collisions with other apps likely." if generic else ""),
                evidence=f"exported={f['exported']}" + (f", permission={f['permission']}" if f['permission'] else ""),
                confidence="confirmed"))
    return out


# --------------------------------------------------------------------------- iOS

def ios_declared(app: appfiles.App) -> Dict[str, Any]:
    info = app.info_plist or {}
    schemes: List[str] = []
    for t in info.get("CFBundleURLTypes") or []:
        schemes += [s for s in (t.get("CFBundleURLSchemes") or []) if isinstance(s, str)]
    domains: List[str] = []
    team = None
    ents = None
    exe = info.get("CFBundleExecutable")
    if app.main_root and exe:
        try:
            ents = engine.extract_entitlements_from_macho(os.path.join(app.main_root, exe))
        except Exception:
            ents = None
    if ents:
        domains = [d for d in (ents.get("com.apple.developer.associated-domains") or []) if isinstance(d, str)]
        appid = ents.get("application-identifier") or ""
        if "." in appid:
            team = appid.split(".", 1)[0]
    if not team:
        try:                                             # fall back to the provisioning profile
            raw = open(os.path.join(app.main_root, "embedded.mobileprovision"), "rb").read()
            prof = engine._extract_mobileprovision_plist(raw) or {}
            team = (prof.get("TeamIdentifier") or [None])[0]
            if not domains:
                domains = list((prof.get("Entitlements") or {}).get("com.apple.developer.associated-domains") or [])
        except Exception:
            pass
    return {"schemes": sorted(set(schemes)), "associated_domains": domains, "team_id": team,
            "bundle_id": app.package, "queried_schemes": list(info.get("LSApplicationQueriesSchemes") or [])}


def ios_findings(d: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    custom = [s for s in d["schemes"] if s.lower() not in SAFE_SCHEMES_IOS]
    for s in custom:
        generic = s.lower() in GENERIC_SCHEMES
        out.append(appfiles.finding(
            "LOW" if generic else "INFO", f"Custom URL scheme `{s}://` registered",
            "Any app can claim the same scheme; iOS delivers the link to whichever registered it last/first. "
            "Do not pass tokens or sensitive actions through custom schemes; use Universal Links.",
            evidence=f"CFBundleURLSchemes", confidence="confirmed"))
    applinks = [x for x in d["associated_domains"] if x.startswith("applinks:")]
    if applinks:
        out.append(appfiles.finding(
            "INFO", f"{len(applinks)} Universal Link domain(s) declared",
            "Domains in the associated-domains entitlement. iOS only honours them if the domain serves a matching "
            "apple-app-site-association file.", evidence=", ".join(x.split(":", 1)[1] for x in applinks[:8]),
            confidence="confirmed"))
    elif custom:
        out.append(appfiles.finding(
            "LOW", "Custom URL scheme(s) but no Universal Links",
            "The app is reachable only through unverifiable custom schemes; Universal Links would let iOS "
            "verify link ownership.", evidence=", ".join(custom[:5]), confidence="confirmed"))
    for x in d["associated_domains"]:
        if "?mode=developer" in x:
            out.append(appfiles.finding(
                "LOW", "Associated domain in developer mode left in a release build",
                "`?mode=developer` bypasses Apple's CDN cache for the association file; it is meant for development.",
                evidence=x, confidence="confirmed"))
    return out


# ------------------------------------------------------------------ network verification

def _fetch_json(fetch, url: str):
    status, _h, body = fetch(url, "GET")
    if status != 200:
        return status, None
    try:
        return 200, json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return 200, "invalid-json"


def check_assetlinks(hosts: Set[str], package: str, fingerprints: Set[str], fetch: Callable,
                     public_host: Callable[[str], bool]) -> List[Dict[str, Any]]:
    out = []
    for host in sorted(hosts):
        if host.startswith("*."):
            host = host[2:]
        if not public_host(host):
            out.append(appfiles.finding("INFO", f"Skipped App Links check for {host}",
                                        "Not a public DNS name (or resolves to a private address); not contacted."))
            continue
        url = f"https://{host}/.well-known/assetlinks.json"
        try:
            status, data = _fetch_json(fetch, url)
        except OSError as e:
            out.append(appfiles.finding("INFO", f"Could not reach {host}", str(e)[:150], location=url))
            continue
        if status != 200 or data in (None, "invalid-json") or not isinstance(data, list):
            why = "redirects" if status in (301, 302, 307, 308) else f"HTTP {status}" if status != 200 else "not valid JSON list"
            out.append(appfiles.finding(
                "MEDIUM", f"App Links verification will fail for {host}",
                f"/.well-known/assetlinks.json is unusable ({why}). Android will not verify the link, so it shows a "
                "chooser and another app can intercept it. (Redirects are not allowed for this file.)",
                location=url, confidence="confirmed"))
            continue
        match = False
        names = set()
        for st in data:
            tgt = (st or {}).get("target") or {}
            if "delegate_permission/common.handle_all_urls" not in ((st or {}).get("relation") or []):
                continue
            if tgt.get("namespace") != "android_app":
                continue
            names.add(tgt.get("package_name"))
            if tgt.get("package_name") == package:
                have = {x.upper() for x in tgt.get("sha256_cert_fingerprints") or []}
                if not fingerprints or have & fingerprints:
                    match = True
        if match:
            out.append(appfiles.finding("INFO", f"App Links verified for {host}",
                                        "assetlinks.json authorises this package and signing certificate.", location=url,
                                        confidence="confirmed"))
        else:
            out.append(appfiles.finding(
                "MEDIUM", f"assetlinks.json for {host} does not authorise this app",
                "The file exists but does not list this package with this signing certificate "
                "(common after a signing-key change, or when only the debug key is listed).",
                evidence=f"package listed: {', '.join(sorted(n for n in names if n)) or 'none'}", location=url,
                confidence="confirmed"))
    return out


def check_aasa(domains: List[str], team: Optional[str], bundle: str, fetch: Callable,
               public_host: Callable[[str], bool]) -> List[Dict[str, Any]]:
    out = []
    want = f"{team}.{bundle}" if team else None
    for entry in domains:
        if not entry.startswith("applinks:"):
            continue
        host = entry.split(":", 1)[1].split("?", 1)[0]
        if host.startswith("*."):
            host = host[2:]
        if not public_host(host):
            out.append(appfiles.finding("INFO", f"Skipped Universal Links check for {host}",
                                        "Not a public DNS name (or resolves to a private address); not contacted."))
            continue
        data, used, status = None, None, None
        for path in ("/.well-known/apple-app-site-association", "/apple-app-site-association"):
            url = f"https://{host}{path}"
            try:
                status, data = _fetch_json(fetch, url)
            except OSError as e:
                out.append(appfiles.finding("INFO", f"Could not reach {host}", str(e)[:150], location=url))
                data = None
                break
            if isinstance(data, dict):
                used = url
                break
        if not isinstance(data, dict):
            out.append(appfiles.finding(
                "MEDIUM", f"Universal Links will not work for {host}",
                f"No usable apple-app-site-association file (last status {status}). iOS will open these links in "
                "the browser, and the custom-scheme fallback (if any) becomes the only app entry.",
                confidence="confirmed"))
            continue
        ids = set()
        for det in ((data.get("applinks") or {}).get("details") or []):
            ids.update(det.get("appIDs") or ([det["appID"]] if det.get("appID") else []))
        if want and want in ids:
            out.append(appfiles.finding("INFO", f"Universal Links verified for {host}",
                                        "apple-app-site-association lists this app ID.", location=used, confidence="confirmed"))
        elif want:
            out.append(appfiles.finding(
                "MEDIUM", f"apple-app-site-association for {host} does not list this app",
                "The file is served but does not include this app's ID (Team ID + bundle ID).",
                evidence=f"expected {want}; found {', '.join(sorted(ids)[:4]) or 'none'}", location=used, confidence="confirmed"))
        else:
            out.append(appfiles.finding("INFO", f"apple-app-site-association found for {host}",
                                        "Could not determine this app's Team ID to compare it.", location=used))
    return out


def run(path: str, *, check_network: bool = False, fetch: Callable = netfetch.fetch,
        public_host: Callable[[str], bool] = netfetch.is_public_host) -> Dict[str, Any]:
    with appfiles.unpacked(path) as app:
        findings: List[Dict[str, Any]] = []
        meta: Dict[str, Any] = {}
        if app.platform == "android":
            if app.manifest is None:
                findings.append(appfiles.finding("INFO", "Manifest not parsed",
                                                 "AAB manifests use a protobuf format that AppSleuth does not parse; "
                                                 "extract an APK from the bundle (bundletool) to analyse links."))
                filters = []
            else:
                filters = android_filters(app.manifest, app.package or "")
                findings += android_findings(filters)
            meta["filters"] = filters
            if check_network:
                hosts = {h for f in filters if f["auto_verify"] or (f["browsable"] and set(f["schemes"]) & {"http", "https"})
                         for h in f["hosts"] if set(f["schemes"]) & {"http", "https"}}
                fps: Set[str] = set()
                if app.main_apk_bytes:
                    sig = engine.extract_apk_signing_certs(app.main_apk_bytes)
                    for der in sig.get("certs_der") or []:
                        h = hashlib.sha256(der).hexdigest().upper()
                        fps.add(":".join(h[i:i + 2] for i in range(0, 64, 2)))
                if not fps:
                    findings.append(appfiles.finding(
                        "INFO", "Signing certificate fingerprint unavailable",
                        "No v2/v3 signing block, so the assetlinks.json fingerprint could not be compared "
                        "(only the package name was)."))
                findings += check_assetlinks(hosts, app.package or "", fps, fetch, public_host)
        else:
            d = ios_declared(app)
            findings += ios_findings(d)
            meta.update(d)
            if check_network:
                findings += check_aasa(d["associated_domains"], d["team_id"], d["bundle_id"] or "", fetch, public_host)
        meta["network_checked"] = check_network
        return appfiles.new_result(app, "links", findings, meta)
