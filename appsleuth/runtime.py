"""Runtime probe (EXPERIMENTAL): observe what an app *actually does* on a device, via Frida.

Observe-only. It never patches behaviour or bypasses pinning/root checks; it just records
calls (root checks, plaintext HTTP, ciphers, credentials written to preferences, secrets in
logs) while you use the app, then turns them into findings. Values are never stored: only
key names and a description such as "JWT, 412 chars".

Needs `pip install frida` (or `pip install appsleuth[runtime]`) and frida-server on the device.
Only run it against apps and devices you are authorised to test.
"""
from __future__ import annotations

import os
import sys
import re
import time
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from . import dataaudit, engine

JS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runtime_js")
MAX_EVENTS = 20000

_WEAK_CIPHER = re.compile(r"(?i)(^|[^A-Za-z0-9])(DES|DESEDE|3DES|RC2|RC4|ARCFOUR|BLOWFISH)([^A-Za-z0-9]|$)")
_SECRET_IN_LOG = [
    (re.compile(r"(?i)authorization:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}"), "Authorization header"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S{3,}"), "password= value"),
    (re.compile(r"eyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]*"), "JWT"),
    (re.compile(r"(?i)(access|refresh|auth|api|session)[_-]?(token|key)\"?\s*[=:]\s*\"?[A-Za-z0-9._~+/=-]{16,}"), "token value"),
]


def _jsonable_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [e for e in events if isinstance(e, dict) and isinstance(e.get("t"), str)][:MAX_EVENTS]


def events_to_result(events: Iterable[Dict[str, Any]], platform: str, target: str = "") -> Dict[str, Any]:
    """Pure function: probe events -> scan-style result dict (testable without a device)."""
    ev = _jsonable_events(events)
    findings: List[Dict[str, Any]] = []

    def add(sev, title, detail, evidence=None, conf="confirmed"):
        findings.append({"severity": sev, "title": title, "detail": detail, "evidence": evidence,
                         "location": f"runtime:{target}" if target else "runtime", "confidence": conf})

    by: Dict[str, List[Dict[str, Any]]] = {}
    for e in ev:
        by.setdefault(e["t"], []).append(e)
    kind = "root" if platform == "android" else "jailbreak"

    # tamper checks the app performs
    if by.get("root_check"):
        args = sorted({e.get("arg", "") for e in by["root_check"]})
        add("INFO", f"App performs {kind} detection (observed)",
            f"The app probed for {kind} indicators while running. This is a defensive control; "
            "whether it is robust is a separate manual test.", evidence=", ".join(args[:5]))

    # pinning
    hosts = sorted({e.get("host", "") for e in by.get("pinning", []) if e.get("host")})
    if hosts:
        how = sorted({e.get("how", "") for e in by["pinning"] if e.get("how")})
        add("INFO", "Certificate pinning exercised (observed)",
            "Server-trust checks ran for these hosts (" + ("; ".join(h.split(" ")[0] + (" ..." if " " in h else "") for h in how[:3]) or "pinning hook")
            + "). Only the implementations the probe hooks are visible: OkHttp on Android; on iOS, URLSession "
            "challenge delegates in the app's own classes.", evidence=", ".join(hosts[:8]))
    app_trust = [e for e in by.get("trust_eval", []) if e.get("by") == "app"]
    if app_trust:
        add("INFO", "App code evaluates TLS trust itself (observed)",
            "SecTrustEvaluate was called from the app's own code, which is how custom certificate pinning "
            "and custom trust decisions are implemented. Review that code: a trust decision that always "
            "returns success disables TLS validation.", evidence=f"{len(app_trust)} call(s)", conf="heuristic")
    exc = [e for e in by.get("trust_override", []) if e.get("how") == "SecTrustSetExceptions"]
    if exc:
        add("MEDIUM", "App code sets TLS trust exceptions at runtime (observed)",
            "SecTrustSetExceptions was called from the app's own code. It is how a certificate that failed "
            "validation gets accepted anyway (self-signed or invalid certificates), so check what the app "
            "trusts and for which hosts.", evidence=f"{len(exc)} call(s)", conf="heuristic")
    anchors = sorted({e.get("how", "") for e in by.get("trust_override", []) if e.get("how") != "SecTrustSetExceptions"})
    if anchors:
        add("INFO", "App code customises TLS trust anchors (observed)",
            "SecTrustSetAnchorCertificates(Only) was called from the app's own code. This narrows or replaces "
            "the certificates it trusts, which is typical of certificate pinning and is not a weakness by itself.",
            evidence=", ".join(anchors), conf="heuristic")
    socks = Counter((e.get("ip", ""), e.get("port")) for e in by.get("socket", [])
                    if e.get("ip") and not re.match(r"(127\.|::1$|0\.0\.0\.0)", e["ip"]))
    if socks:
        plain = sorted(f"{ip}:{port}" for (ip, port) in socks if port == 80)
        if plain:
            add("MEDIUM", "App opened a connection to port 80 (plaintext HTTP likely)",
                "A socket was connected to port 80 from the app's own code. This sees stacks that bypass URLSession "
                "(Flutter/Dart, embedded HTTP libraries). Port 80 is normally unencrypted HTTP.",
                evidence=", ".join(plain[:6]), conf="heuristic")
        add("INFO", f"Raw socket connections observed to {len(socks)} endpoint(s)",
            "Destinations the app connected to directly, outside URLSession. Port 443 is normally TLS.",
            evidence=", ".join(f"{ip}:{port}" for (ip, port) in sorted(socks)[:10]))
    reqs = Counter(e.get("host", "") for e in by.get("net", []) if e.get("host"))
    if reqs:
        add("INFO", f"Network requests observed to {len(reqs)} host(s)",
            "Hosts the app actually contacted while it was observed (URLSession, Alamofire, NSURLConnection, CFNetwork).",
            evidence=", ".join(f"{h} ({n})" for h, n in reqs.most_common(10)))
    pages = sorted({e.get("url", "") for e in by.get("webview_load", []) if e.get("url")})
    if pages:
        add("INFO", f"WebView loaded {len(pages)} page(s) (observed)",
            "Pages and files the app's web views loaded. Check remote content for HTTPS and trusted origins.",
            evidence=", ".join(pages[:8]))

    # plaintext HTTP actually requested
    urls = sorted({e.get("url", "") for e in by.get("cleartext", [])
                   if e.get("url") and not engine._is_noise_cleartext_url(e["url"].encode())})
    if urls:
        add("MEDIUM", "App requested plaintext HTTP URL(s) at runtime",
            "These http:// URLs were actually requested (not just present in the binary), so the "
            "traffic can be read or modified on the network.", evidence=", ".join(urls[:6]))

    # crypto in use
    ciphers = Counter(e.get("alg", "") for e in by.get("cipher", []))
    weak = sorted(a for a in ciphers if _WEAK_CIPHER.search(a))
    # "RSA/ECB/PKCS1Padding" is just the JCA name for textbook RSA, not a block-cipher mode problem
    ecb = sorted(a for a in ciphers if not a.strip().upper().startswith("RSA")
                 and (re.search(r"(?i)/ECB/", a) or a.strip().upper() in ("AES", "AES/ECB")))
    if weak:
        add("MEDIUM", "Weak cipher used at runtime", "A legacy cipher was requested while the app ran.",
            evidence=", ".join(weak[:6]))
    if ecb:
        add("MEDIUM", "ECB mode used at runtime",
            'ECB leaks patterns in the plaintext. On Android, Cipher.getInstance("AES") defaults to ECB.',
            evidence=", ".join(ecb[:6]))
    md5 = [e for e in by.get("digest", []) if re.fullmatch(r"(?i)(md5|md2|sha-?1)", e.get("alg", ""))]
    if md5:
        add("INFO", "MD5/SHA-1 digest used at runtime",
            "Fine for cache keys or checksums, not for passwords or signatures.", evidence=md5[0]["alg"], conf="heuristic")

    # credentials written to preferences
    bad = {}
    for e in by.get("prefs_write", []):
        key = e.get("key", "")
        kind_ = dataaudit.sensitive_key(key)
        if not kind_:
            continue
        desc, strong = dataaudit.classify_value(e.get("value", ""))
        if desc in ("empty", "scalar", "short string"):
            continue
        sev = "HIGH" if strong else "MEDIUM"
        if dataaudit.is_session_id_key(key):          # analytics/SDK session ids, not login credentials
            sev, kind_ = "LOW", "session identifier"
        if key not in bad or sev == "HIGH":
            bad[key] = (sev, kind_, desc)
    for key, (sev, kind_, desc) in sorted(bad.items()):
        store = "SharedPreferences" if platform == "android" else "NSUserDefaults"
        add(sev, f"Credential-like value written to {store} in plaintext",
            f"Key `{key}` ({kind_}, {desc}) is stored unencrypted. Use the Keystore/Keychain instead."
            + (" Session ids written by analytics SDKs are usually harmless; check whether it authenticates the user."
               if kind_ == "session identifier" else ""),
            evidence=f"{key}: {desc}", conf="confirmed" if sev == "HIGH" else "heuristic")

    # secrets in logs
    seen = set()
    for e in by.get("log", []):
        msg = e.get("msg", "")
        for pat, what in _SECRET_IN_LOG:
            if pat.search(msg) and what not in seen:
                seen.add(what)
                add("HIGH" if what != "JWT" else "MEDIUM", f"{what} written to the system log",
                    "Log output is readable by other tools on the device (and by anyone with adb/Console). "
                    "Remove it from release builds.", evidence=f"tag={e.get('tag', '')}")

    verifiers = sorted({e.get("cls", "") for e in by.get("hostname_verifier", []) if e.get("cls")})
    if verifiers:
        loose = [v for v in verifiers if re.search(r"(?i)allow.?all|trust.?all|insecure|accept.?all|null.?host|no.?op", v)]
        if loose:
            add("HIGH", "Hostname verification may be disabled",
                "A default HostnameVerifier with a permissive-sounding name was installed. If it accepts any "
                "host, TLS connections can be intercepted.", evidence=", ".join(loose[:4]), conf="heuristic")
        else:
            add("INFO", "Custom default hostname verifier installed (observed)",
                "Review that it actually checks the host name.", evidence=", ".join(verifiers[:4]), conf="heuristic")

    if by.get("webview_debug"):
        add("MEDIUM", "WebView debugging enabled at runtime",
            "setWebContentsDebuggingEnabled(true) was called; pages can be inspected over USB and may leak data.")

    if by.get("keychain_add"):
        # pdmn codes: ak=WhenUnlocked, ck=AfterFirstUnlock, dk=Always (deprecated), *u = ThisDeviceOnly
        accs = {e.get("accessible", "") for e in by["keychain_add"]}
        weak = sorted(a for a in accs if re.fullmatch(r"(?i)dku?", a) or "kSecAttrAccessibleAlways" in a)
        if weak:
            add("MEDIUM", "Keychain item stored with weak accessibility",
                "kSecAttrAccessibleAlways can be read while the device is locked (and is deprecated). "
                "Use WhenUnlocked, or AfterFirstUnlock only if background access is required.",
                evidence=", ".join(weak), conf="heuristic")

    if platform == "ios" and by.get("early_exit") and not by.get("ready"):
        add("INFO", "App exited right after launch while instrumented",
            "On jailbroken devices this is often jailbreak/tamper detection, but it could also be a hook "
            "problem. Try attach mode (open the app first, then run without --spawn). AppSleuth does not "
            "bypass these checks.", conf="heuristic")

    hooks = hook_breakdown(ev)
    gaps = coverage_gaps(ev, hooks)
    for g in gaps:
        add(g["severity"], g["title"], g["detail"], evidence=g.get("evidence"), conf="heuristic")

    summary = {s: sum(1 for f in findings if f["severity"] == s) for s in ("HIGH", "MEDIUM", "LOW", "INFO")}
    return {
        "detected_type": "runtime", "input_file": target,
        "meta": {"platform": platform, "target": target, "events": len(ev),
                 "event_types": dict(Counter(e["t"] for e in ev)),
                 "hooks": hooks,
                 "probe_errors": sorted({e.get("what", "") for e in by.get("probe_error", [])})[:10]},
        "findings": findings, "summary": summary,
    }


_NET_EVENTS = ("net", "cleartext", "socket")
_APPLE_HOST = re.compile(r"(^|\.)(apple\.com|icloud\.com|mzstatic\.com|apple-dns\.net|local|localhost|in-addr\.arpa|ip6\.arpa)$")


def hook_breakdown(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per-hook picture of a run: [{name, installed, calls, events, types}], sorted busiest first.

    iOS agents report every hook's install state and call count in a `hook_stats` event; events carry
    a `hook` tag, so we also count what each hook recorded. Without stats (Android, or the probe ended
    abruptly) the breakdown falls back to events grouped by their `hook` tag, or by type and `how`."""
    stats = next((e["hooks"] for e in reversed(events) if e.get("t") == "hook_stats" and isinstance(e.get("hooks"), dict)), None)
    rec: Dict[str, Counter] = {}
    for e in events:
        if e["t"] in ("hook_stats", "ready", "probe_error", "early_exit"):
            continue
        name = e.get("hook") or (f"{e['t']}: {e['how']}" if e.get("how") else e["t"])
        rec.setdefault(name, Counter())[e["t"]] += 1
    rows: Dict[str, Dict[str, Any]] = {}
    for name, h in (stats or {}).items():
        if isinstance(h, dict):
            rows[name] = {"name": name, "installed": bool(h.get("installed")), "calls": int(h.get("calls") or 0),
                          "optional": bool(h.get("optional")), "alias": h.get("alias")}
    for name, c in rec.items():
        r = rows.setdefault(name, {"name": name, "installed": True, "calls": None, "optional": False, "alias": None})
        r["events"] = sum(c.values())
        r["types"] = dict(c)
    for r in rows.values():
        r.setdefault("events", 0)
        r.setdefault("types", {})
    return sorted(rows.values(), key=lambda r: (-(r["calls"] or r["events"]), r["name"]))


def coverage_gaps(events: List[Dict[str, Any]], hooks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """What the probe could not see, so '0 findings' is not read as 'nothing happened'."""
    out: List[Dict[str, Any]] = []
    missing = sorted(h["name"] for h in hooks if not h["installed"] and not h["optional"])
    if missing:
        out.append({"severity": "LOW", "title": f"{len(missing)} runtime hook(s) could not be installed",
                    "detail": "These classes or functions were not found, so behaviour they cover was not observed "
                              "(wrong OS version, framework not loaded yet, or the app does not use it).",
                    "evidence": "; ".join(missing[:8])})
    net_seen = sum(1 for e in events if e["t"] in _NET_EVENTS)
    hosts = sorted({e.get("host", "") for e in events if e["t"] == "dns" and e.get("host")
                    and not _APPLE_HOST.search(e["host"])})
    if hosts and not net_seen:
        out.append({"severity": "LOW", "title": "Network hooks saw no requests although the app resolved host names",
                    "detail": "The app looked up these hosts, but no request went through a hooked networking API. It "
                              "probably uses a stack the probe does not cover (raw sockets, a custom or embedded "
                              "HTTP library, Flutter/Dart or another cross-platform engine), so plaintext HTTP and "
                              "request-level problems may have been missed.",
                    "evidence": ", ".join(hosts[:8])})
    return out


def breakdown_lines(result: Dict[str, Any], color=None) -> List[str]:
    """Terminal table for `appsleuth runtime`: what each hook did during the run."""
    c = color or (lambda text, _kind: text)
    hooks = (result.get("meta") or {}).get("hooks") or []
    if not hooks:
        return []
    have_calls = any(h["calls"] is not None for h in hooks)
    fired = [h for h in hooks if (h["calls"] or h["events"])]
    quiet = [h for h in hooks if h["installed"] and not (h["calls"] or h["events"])]
    missing = [h for h in hooks if not h["installed"] and not h["optional"]]
    head = f"Hooks: {len(fired)} fired"
    if have_calls:
        head += f", {len(quiet)} installed but silent, {len(missing)} not found"
    out = [c(head, "id")]
    w = max(len(h["name"]) for h in fired) if fired else 0
    for h in fired:
        calls = f"{h['calls']:>6} calls  " if h["calls"] is not None else ""
        out.append(f"  {h['name'].ljust(w)}  {calls}{h['events']:>5} events")
    if quiet:
        out.append(c("  silent: " + ", ".join(h["name"] for h in quiet[:12]) + (" ..." if len(quiet) > 12 else ""), "dim"))
    if missing:
        out.append(c("  not found: " + ", ".join(h["name"] for h in missing[:12]), "MEDIUM"))
    return out


_VALUE_KEYS = ("value", "msg")


def redact_event(e: Dict[str, Any]) -> Dict[str, Any]:
    """An event safe to write to disk: values become a description, log lines are masked if they hold a secret."""
    out = dict(e)
    if "value" in out:
        out["value"] = f"<{dataaudit.classify_value(out['value'])[0]}>"
    if isinstance(out.get("msg"), str):
        msg = out["msg"]
        out["msg"] = "<masked: contains a secret>" if any(p.search(msg) for p, _ in _SECRET_IN_LOG) else msg[:200]
    return out


def dump_events(events: Iterable[Dict[str, Any]], path: str) -> int:
    """Write the raw event stream as JSON lines (values redacted). Returns the number of lines."""
    import json
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for e in _jsonable_events(events):
            fh.write(json.dumps(redact_event(e), sort_keys=True) + "\n")
            n += 1
    os.chmod(path, 0o600)
    return n


def _pick_usb_device(frida, platform: str):
    """The USB device running `platform`. get_usb_device() alone picks whichever phone is first,
    which is wrong when an iPhone and an Android phone are both attached."""
    matches = []
    for d in frida.enumerate_devices():
        if d.type != "usb":
            continue
        try:
            if d.query_system_parameters().get("os", {}).get("id") == platform:
                matches.append(d)
        except Exception:
            continue
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise RuntimeError(f"several {platform} devices connected; choose one with --device ID "
                           f"({', '.join(d.id for d in matches)})")
    return frida.get_usb_device(timeout=10)


def mismatch_hint(frida_version: str) -> str:
    major = frida_version.split(".")[0]
    return (f"Python Frida is {frida_version} but frida-server does not match it (the major version must "
            f"agree, ideally the exact version). Install the matching server from "
            f"https://github.com/frida/frida/releases (frida-server-{frida_version}-<os>-<arch>), or run "
            f"`pip install frida=={major}.*` to match the server you already have.")


def looks_like_version_mismatch(exc: BaseException) -> bool:
    msg = f"{type(exc).__name__} {exc}".lower()
    return ("protocolerror" in msg or "major versions match" in msg or "unexpected message" in msg
            or "unable to communicate with remote frida-server" in msg)


def _check_server_compat(frida, dev) -> None:
    """Fail early with a clear message when frida-server and the Python bindings disagree,
    instead of a cryptic ProtocolError halfway through attaching."""
    try:
        dev.query_system_parameters()
    except Exception as e:
        if looks_like_version_mismatch(e):
            raise RuntimeError(mismatch_hint(getattr(frida, "__version__", "?"))) from e
        # anything else (e.g. server not running) is reported by the later attach/spawn


def run_probe(platform: str, target: str, *, seconds: int = 60, spawn: bool = False,
              device_id: Optional[str] = None, host: Optional[str] = None) -> List[Dict[str, Any]]:
    """Attach (or spawn) with Frida and collect events for `seconds`. Needs the frida module."""
    try:
        import frida  # type: ignore
    except ImportError:
        raise RuntimeError("the runtime probe needs Frida: pip install frida   (and frida-server on the device)")
    if platform not in ("android", "ios"):
        raise RuntimeError("platform must be android or ios")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", target):
        raise RuntimeError("invalid package / bundle id")
    if host:
        dev = frida.get_device_manager().add_remote_device(host)
    elif device_id:
        dev = frida.get_device(device_id, timeout=10)
    else:
        dev = _pick_usb_device(frida, platform)
    _check_server_compat(frida, dev)
    with open(os.path.join(JS_DIR, f"{platform}.js"), encoding="utf-8") as fh:
        source = fh.read()
    events: List[Dict[str, Any]] = []

    def on_message(msg, _data):
        p = msg.get("payload")
        if msg.get("type") == "send" and isinstance(p, dict) and (len(events) < MAX_EVENTS or p.get("t") == "hook_stats"):
            events.append(p)

    state = {"detached": None}

    def start(pid: int, resume_first: bool):
        """Attach and load the agent. resume_first: let the app boot, then attach (avoids ART crashes
        that some apps hit when instrumented before they start)."""
        if resume_first:
            dev.resume(pid)
            time.sleep(2.0)
        session = dev.attach(pid)
        session.on("detached", lambda reason, *_: state.__setitem__("detached", reason))
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        if platform == "android":          # the Android agent installs its hooks when it gets this
            skip = [x for x in os.environ.get("APPSLEUTH_SKIP_HOOKS", "").split(",") if x]
            script.post({"type": "config", "skip": skip,
                         "delay_ms": int(os.environ.get("APPSLEUTH_HOOK_DELAY_MS", "0") or 0)})
        if not resume_first and spawn:
            dev.resume(pid)
        return session, script

    pid = None
    if spawn:
        pid = dev.spawn([target])
        try:
            session, script = start(pid, False)
            time.sleep(4)                      # an early crash shows up as: no 'ready' event, session detached
            crashed = state["detached"] is not None and not any(e.get("t") == "ready" for e in events)
        except Exception:
            session = script = None
            crashed = True
        if crashed:
            print("[!] The app did not survive early instrumentation; retrying with a delayed attach "
                  "(very early startup checks will be missed).", file=sys.stderr)
            try:
                dev.kill(pid)
            except Exception:
                pass
            state["detached"] = None
            events.clear()
            pid = dev.spawn([target])
            session, script = start(pid, True)
    else:
        for app in dev.enumerate_applications():          # Frida names processes by label, not package
            if app.identifier == target and app.pid:
                pid = app.pid
                break
        if pid is None:
            raise RuntimeError(f"{target} is not running; start it first, or use --spawn")
        session, script = start(pid, False)
    t0 = time.time()
    try:
        time.sleep(max(1, seconds))
    except KeyboardInterrupt:
        pass
    finally:
        if state["detached"] is not None:      # the process went away before the window ended
            events.append({"t": "early_exit", "reason": str(state["detached"])[:60], "after_s": round(time.time() - t0, 1)})
        if platform == "ios" and state["detached"] is None:      # ask the agent for its per-hook counters
            try:
                script.post({"type": "stats"})
                for _ in range(20):
                    if any(e.get("t") == "hook_stats" for e in events):
                        break
                    time.sleep(0.1)
            except Exception:
                pass
        try:
            script.unload()
            session.detach()
        except Exception:
            pass
    return events


def read_keychain_values(bundle_id: str, *, device_id: Optional[str] = None, host: Optional[str] = None,
                         wait: float = 15.0) -> Dict[str, Any]:
    """Read the app's own keychain items, values included, by running SecItemCopyMatching inside the app.

    Attaches to the running app, or launches it (and closes it again afterwards) if it is not running.
    Returns {"items": [...], "status": {class: OSStatus}, "errors": [...], "spawned": bool}.
    Needs frida + frida-server; only works for items the app itself may read (its access groups), and
    items protected with WhenUnlocked need the device unlocked."""
    try:
        import frida  # type: ignore
    except ImportError:
        raise RuntimeError("reading keychain values needs Frida: pip install frida   (and frida-server on the device)")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", bundle_id):
        raise RuntimeError("invalid bundle id")
    if host:
        dev = frida.get_device_manager().add_remote_device(host)
    elif device_id:
        dev = frida.get_device(device_id, timeout=10)
    else:
        dev = _pick_usb_device(frida, "ios")
    _check_server_compat(frida, dev)
    with open(os.path.join(JS_DIR, "keychain.js"), encoding="utf-8") as fh:
        source = fh.read()
    events: List[Dict[str, Any]] = []
    pid = next((a.pid for a in dev.enumerate_applications() if a.identifier == bundle_id and a.pid), None)
    spawned = pid is None
    session = script = None
    try:
        if not spawned:
            try:
                session = dev.attach(pid)
            except Exception:           # a stale or hung instance: close it and start a fresh one
                try:
                    dev.kill(pid)
                except Exception:
                    pass
                spawned = True
        if spawned:
            pid = dev.spawn([bundle_id])
            dev.resume(pid)             # attaching to a still-suspended app times out on some devices
            time.sleep(2.0)
            session = dev.attach(pid)
        script = session.create_script(source)
        script.on("message", lambda m, _d: events.append(m["payload"])
                  if m.get("type") == "send" and isinstance(m.get("payload"), dict) else None)
        script.load()
        deadline = time.time() + wait
        while time.time() < deadline and not any(e.get("t") == "kc_done" for e in events):
            time.sleep(0.2)
    finally:
        try:
            if script:
                script.unload()
            if session:
                session.detach()
        except Exception:
            pass
        if spawned:
            try:
                dev.kill(pid)
            except Exception:
                pass
    if not any(e.get("t") == "kc_done" for e in events):
        raise RuntimeError("the keychain reader did not finish (the app may have exited, or the device is locked)")
    return {"items": [{k: v for k, v in e.items() if k != "t"} for e in events if e.get("t") == "kc_item"],
            "status": {e["class"]: e["status"] for e in events if e.get("t") == "kc_status"},
            "errors": [e.get("what", "") for e in events if e.get("t") == "kc_error"], "spawned": spawned}
