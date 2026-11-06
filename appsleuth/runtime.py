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
        add("INFO", "Certificate pinning exercised (observed)",
            "OkHttp's CertificatePinner ran for these hosts. Only OkHttp pinning is monitored; other "
            "implementations are not visible to this probe.", evidence=", ".join(hosts[:8]))

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
    ecb = sorted(a for a in ciphers if re.search(r"(?i)/ECB/", a) or a.strip().upper() in ("AES", "AES/ECB"))
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
        if key not in bad or sev == "HIGH":
            bad[key] = (sev, kind_, desc)
    for key, (sev, kind_, desc) in sorted(bad.items()):
        store = "SharedPreferences" if platform == "android" else "NSUserDefaults"
        add(sev, f"Credential-like value written to {store} in plaintext",
            f"Key `{key}` ({kind_}, {desc}) is stored unencrypted. Use the Keystore/Keychain instead.",
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

    summary = {s: sum(1 for f in findings if f["severity"] == s) for s in ("HIGH", "MEDIUM", "LOW", "INFO")}
    return {
        "detected_type": "runtime", "input_file": target,
        "meta": {"platform": platform, "target": target, "events": len(ev),
                 "probe_errors": sorted({e.get("what", "") for e in by.get("probe_error", [])})[:10]},
        "findings": findings, "summary": summary,
    }


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
    with open(os.path.join(JS_DIR, f"{platform}.js"), encoding="utf-8") as fh:
        source = fh.read()
    events: List[Dict[str, Any]] = []

    def on_message(msg, _data):
        if msg.get("type") == "send" and isinstance(msg.get("payload"), dict) and len(events) < MAX_EVENTS:
            events.append(msg["payload"])

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
    try:
        time.sleep(max(1, seconds))
    except KeyboardInterrupt:
        pass
    finally:
        try:
            script.unload()
            session.detach()
        except Exception:
            pass
    return events
