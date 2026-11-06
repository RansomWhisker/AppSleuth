"""Endpoint inventory: every host the app talks to (or contains), grouped and classified.

Pulls URLs out of dex / native / Mach-O / web-asset / config files, normalises them, drops
documentation and schema noise, then labels each host: first-party vs known SDK vs other,
and flags the ones testers care about (raw IPs, private ranges, cleartext, staging hosts,
tunnel services). It is the map you start a test from, and `diff` uses it to show new hosts.
"""
from __future__ import annotations

import ipaddress
import os
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from . import appfiles, engine
from .style import Term, bad, dim, good, head, warn

MAX_FILE = 200 << 20
URL_RE = re.compile(rb"(?i)\b(https?|wss?)://([A-Za-z0-9._~%\-]+(?:\.[A-Za-z0-9._~%\-]+)*|\[[0-9A-Fa-f:]+\])"
                    rb"(?::(\d{1,5}))?((?:[/?#][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-{}]*)?)")
PATH_RE = re.compile(rb"(?<![A-Za-z0-9/._-])(/(?:api|rest|graphql|oauth2?|auth|v[0-9]{1,2})(?:/[A-Za-z0-9_.{}:-]{1,60}){1,8})")
TEXT_EXT = {".js", ".mjs", ".json", ".html", ".htm", ".xml", ".plist", ".properties", ".txt", ".yml", ".yaml",
            ".config", ".strings", ".ini", ".cfg", ".env", ".map", ".css", ".conf", ".gradle", ".kt", ".java"}
BIN_EXT = {".dex", ".so", ".dylib", ".a", ".bin", ".dat"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ttf", ".otf", ".woff", ".woff2", ".mp3", ".mp4", ".mov",
            ".caf", ".car", ".nib", ".storyboardc", ".mom", ".momd", ".ico", ".icns", ".pdf", ".zip", ".arsc"}

# (domain suffix, category). First match wins; suffix match on the registrable-ish host.
KNOWN = [
    ("googleapis.com", "google"), ("google.com", "google"), ("gstatic.com", "google-cdn"), ("googleusercontent.com", "google"),
    ("firebaseio.com", "firebase"), ("firebaseapp.com", "firebase"), ("firebasedatabase.app", "firebase"),
    ("crashlytics.com", "crash-reporting"), ("app-measurement.com", "analytics"), ("doubleclick.net", "ads"),
    ("googleadservices.com", "ads"), ("googlesyndication.com", "ads"), ("admob.com", "ads"),
    ("facebook.com", "social"), ("facebook.net", "social"), ("fbcdn.net", "social"), ("instagram.com", "social"),
    ("sentry.io", "crash-reporting"), ("bugsnag.com", "crash-reporting"), ("appcenter.ms", "crash-reporting"),
    ("appsflyer.com", "attribution"), ("adjust.com", "attribution"), ("adjust.io", "attribution"), ("branch.io", "attribution"),
    ("amplitude.com", "analytics"), ("mixpanel.com", "analytics"), ("segment.io", "analytics"), ("segment.com", "analytics"),
    ("clevertap.com", "analytics"), ("moengage.io", "analytics"), ("onesignal.com", "push"), ("braze.com", "analytics"),
    ("razorpay.com", "payments"), ("stripe.com", "payments"), ("paypal.com", "payments"), ("paytm.com", "payments"),
    ("braintreegateway.com", "payments"), ("adyen.com", "payments"), ("phonepe.com", "payments"),
    ("apple.com", "apple"), ("icloud.com", "apple"), ("mzstatic.com", "apple"),
    ("microsoft.com", "microsoft"), ("live.com", "microsoft"), ("azureedge.net", "cdn"), ("windows.net", "cloud"),
    ("amazonaws.com", "cloud"), ("cloudfront.net", "cdn"), ("cloudflare.com", "cdn"), ("jsdelivr.net", "cdn"),
    ("unpkg.com", "cdn"), ("cdnjs.cloudflare.com", "cdn"), ("fastly.net", "cdn"), ("akamaized.net", "cdn"),
    ("github.com", "code-host"), ("githubusercontent.com", "code-host"),
    ("twitter.com", "social"), ("linkedin.com", "social"), ("youtube.com", "google"), ("ytimg.com", "google"),
]
TUNNELS = ("ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "loca.lt", "localtunnel.me",
           "serveo.net", "herokuapp.com", "vercel.app", "netlify.app", "pagekite.me", "ngrok.dev")
NONPROD = re.compile(r"(^|[.-])(dev|develop|staging|stage|stg|uat|qa|test|testing|sandbox|preprod|pre-prod|internal|demo|beta)([.-]|\d|$)")
_MULTI_TLD = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in", "org.in", "co.jp",
              "com.br", "com.cn", "com.mx", "co.nz", "co.za", "com.sg", "com.hk", "com.tr", "com.ar", "co.kr", "com.pk", "com.ng"}


def registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_TLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def owner_domains(app: appfiles.App) -> Set[str]:
    """Registrable domains the app's own id implies: com.abstox.tr -> abstox.com."""
    pid = (app.package or "")
    parts = pid.split(".")
    out: Set[str] = set()
    if len(parts) >= 2 and parts[0] in ("com", "in", "io", "org", "net", "co", "app", "ai", "me", "dev", "us", "uk"):
        out.add(f"{parts[1]}.{parts[0]}")
        out.add(f"{parts[1]}.com")
        out.add(f"{parts[1]}.in")
    return out


def _is_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _clean_url(scheme: bytes, host: bytes, port: Optional[bytes], rest: bytes) -> Optional[Tuple[str, str, str]]:
    sch = scheme.decode().lower()
    h = host.decode("ascii", "ignore").lower().rstrip(".")
    if not h or "%" in h:
        return None
    path = rest.decode("ascii", "ignore")
    path = path.rstrip(".,;:)'\"`]}>")                      # trailing punctuation from prose / code
    if port and int(port) not in (80, 443) and 0 < int(port) < 65536:
        h_port = f"{h}:{int(port)}"
    else:
        h_port = h
    return sch, h, f"{sch}://{h_port}{path}"


def _noise(scheme: str, host: str, url: str) -> bool:
    if _is_ip(host) is None and not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", host):
        return True                                           # format strings, templates
    if "." not in host and _is_ip(host) is None and host != "localhost":
        return True                                           # bare words: http://tr, http://burp
    if host.endswith((".invalid", ".example", ".test")) or host in ("example.com", "example.org", "www.example.com"):
        return True
    probe = ("http://" + url.split("://", 1)[1]).encode()
    return engine._is_noise_cleartext_url(probe)


def _files(app: appfiles.App):
    for full in app.files():
        ext = os.path.splitext(full)[1].lower()
        if ext in SKIP_EXT:
            continue
        try:
            size = os.path.getsize(full)
        except OSError:
            continue
        if size > MAX_FILE or size == 0:
            continue
        yield full, ext, size


def scan_files(app: appfiles.App) -> Dict[str, Dict[str, Any]]:
    hosts: Dict[str, Dict[str, Any]] = {}
    paths: Dict[str, int] = defaultdict(int)
    for full, ext, size in _files(app):
        try:
            with open(full, "rb") as fh:
                blob = fh.read()
        except OSError:
            continue
        label = app.rel(full)
        for m in URL_RE.finditer(blob):
            parsed = _clean_url(m.group(1), m.group(2), m.group(3), m.group(4))
            if not parsed:
                continue
            scheme, host, url = parsed
            if _noise(scheme, host, url):
                continue
            h = hosts.setdefault(host, {"host": host, "schemes": set(), "count": 0, "files": set(), "urls": []})
            h["schemes"].add(scheme)
            h["count"] += 1
            if len(h["files"]) < 5:
                h["files"].add(label)
            if url not in h["urls"] and len(h["urls"]) < 4:
                h["urls"].append(url[:200])
        if ext in TEXT_EXT or ext in BIN_EXT or ext == "":
            for m in PATH_RE.finditer(blob):
                paths[m.group(1).decode("ascii", "ignore")] += 1
    return hosts, paths


def classify(host: str, owners: Set[str]) -> Dict[str, Any]:
    flags: List[str] = []
    ip = _is_ip(host.split(":")[0]) if host.count(":") <= 1 else _is_ip(host)
    bare = host.split(":")[0]
    reg = registrable(bare)
    category, party = "other", "unknown"
    if ip is not None:
        category, party = "raw-ip", "unknown"
        flags.append("raw IP address")
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            flags.append("private/loopback address")
    elif bare == "localhost" or bare.endswith((".local", ".internal", ".lan")):
        flags.append("private/loopback address")
    else:
        if reg in owners:
            category, party = "first-party", "first-party"
        else:
            for suf, cat in KNOWN:
                if bare == suf or bare.endswith("." + suf):
                    category, party = cat, "third-party"
                    break
        if any(bare == t or bare.endswith("." + t) for t in TUNNELS):
            flags.append("tunnel / temporary hosting service")
        if NONPROD.search(bare.rsplit(".", 1)[0]):
            flags.append("looks like a non-production environment")
    return {"category": category, "party": party, "flags": flags, "domain": reg if ip is None else bare}


def inventory(app: appfiles.App) -> Dict[str, Any]:
    raw_hosts, raw_paths = scan_files(app)
    owners = owner_domains(app)
    rows = []
    for host, h in raw_hosts.items():
        c = classify(host, owners)
        flags = list(c["flags"])
        if "http" in h["schemes"] or "ws" in h["schemes"]:
            flags.append("cleartext scheme seen")
        rows.append({"host": host, "domain": c["domain"], "category": c["category"], "party": c["party"],
                     "schemes": sorted(h["schemes"]), "count": h["count"], "files": sorted(h["files"]),
                     "sample_urls": h["urls"], "flags": flags})
    order = {"first-party": 0, "unknown": 1, "third-party": 2}
    rows.sort(key=lambda r: (order.get(r["party"], 1), -r["count"], r["host"]))
    paths = sorted(raw_paths.items(), key=lambda kv: (-kv[1], kv[0]))[:200]
    return {"hosts": rows, "paths": [p for p, _ in paths], "owner_domains": sorted(owners)}


def to_findings(inv: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    rows = inv["hosts"]
    by_party: Dict[str, int] = defaultdict(int)
    for r in rows:
        by_party[r["party"]] += 1
    out.append(appfiles.finding(
        "INFO", f"{len(rows)} network host(s) referenced",
        "Every distinct host found in code, assets and config (documentation and schema URLs removed). "
        "Hosts are labelled first-party (matches the app id), known third-party SDK, or other. A host being "
        "listed does not mean the app contacts it at runtime.",
        evidence=", ".join(f"{k}: {v}" for k, v in sorted(by_party.items())), confidence="heuristic"))
    nonprod = [r["host"] for r in rows if "looks like a non-production environment" in r["flags"]]
    if nonprod:
        out.append(appfiles.finding(
            "LOW", "Non-production host name(s) referenced",
            "Staging/dev/test hosts left in a release build often run older code, weaker auth or test data. "
            "Confirm they are unreachable from the internet or intentionally used.",
            evidence=", ".join(nonprod[:8])))
    private = [r["host"] for r in rows if "private/loopback address" in r["flags"]
               and not r["host"].startswith(("127.", "localhost", "0.0.0.0", "10.0.2.2"))]
    if private:
        out.append(appfiles.finding(
            "LOW", "Private-network address(es) referenced",
            "Internal addresses in a shipped app leak network layout and usually mean a debug or test path.",
            evidence=", ".join(private[:8])))
    tunnels = [r["host"] for r in rows if "tunnel / temporary hosting service" in r["flags"]]
    if tunnels:
        out.append(appfiles.finding(
            "LOW", "Temporary tunnel / hosting-service host(s) referenced",
            "Tunnel hosts (ngrok and similar) are usually developer leftovers and can be re-registered by "
            "anyone once the original tunnel stops, which would let them serve content to the app.",
            evidence=", ".join(tunnels[:8])))
    raw_cleartext = [r["host"] for r in rows if "raw IP address" in r["flags"] and "cleartext scheme seen" in r["flags"]
                     and "private/loopback address" not in r["flags"]]
    if raw_cleartext:
        out.append(appfiles.finding(
            "MEDIUM", "Cleartext HTTP to a raw public IP address",
            "Traffic to a bare IP over http:// is unencrypted and bypasses hostname-based protections "
            "such as certificate pinning and HSTS.", evidence=", ".join(raw_cleartext[:6]), confidence="heuristic"))
    return out


def host_set(path: str) -> Dict[str, Dict[str, Any]]:
    """host -> row, for diffing builds."""
    with appfiles.unpacked(path) as app:
        return {r["host"]: r for r in inventory(app)["hosts"]}


def run(path: str) -> Dict[str, Any]:
    with appfiles.unpacked(path) as app:
        inv = inventory(app)
        return appfiles.new_result(app, "endpoints", to_findings(inv), inv)


def render_text(result: Dict[str, Any], limit: int = 60) -> str:
    inv = result["meta"]
    L = [Term.c(f"{result['meta'].get('package') or ''}  endpoints", "id"), dim("=" * 60)]
    rows = inv["hosts"]
    L.append(head(f"{'HOST':45} {'PARTY':12} {'CATEGORY':16} N  FLAGS"))
    for r in rows[:limit]:
        party = (good if r["party"] == "first-party" else dim)(f"{r['party']:12}")
        flags = "; ".join(r["flags"])
        L.append(f"{r['host'][:44]:45} {party} {r['category']:16} {r['count']:<3}{(bad if flags else dim)(flags)}")
    if len(rows) > limit:
        L.append(f"... {len(rows) - limit} more (use --full or the JSON/HTML report)")
    if inv["paths"]:
        L.append("")
        L.append("API-looking paths (heuristic): " + ", ".join(inv["paths"][:15]) + (" ..." if len(inv["paths"]) > 15 else ""))
    return "\n".join(L)
