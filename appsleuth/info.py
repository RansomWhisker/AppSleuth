"""App inspection: a normalised, platform-independent summary of an APK / APKS / XAPK /
AAB / IPA. This is the data model shared by `appsleuth info` and `appsleuth diff`."""
import hashlib
import os
from typing import Any, Dict, List, Optional

from . import engine
from .style import Term, bad, dim, good, head, warn
from . import perms as perms_mod

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
    "cordova_access_any_origin": ("Cordova <access origin=",),
    "cordova_navigation_any_host": ("Cordova <allow-navigation",),
    "cordova_intent_any_url": ("Cordova <allow-intent",),
    "capacitor_navigation_any_host": ("Capacitor allowNavigation permits any host",),
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

def _yn(v: Any, yes: str, no: str):
    return None if v is None else (good(yes) if v else bad(no))


def _enc_plain(verdicts: List[str]) -> str:
    if "ciphertext" in verdicts:
        return bad("FairPlay-encrypted: the code is NOT readable here (scan coverage limited)")
    if "flag-set-but-readable" in verdicts:
        return warn("FairPlay flag set but code is readable (decrypted dump)")
    if "decrypted" in verdicts:
        return "decrypted dump" + dim(": FairPlay (App Store DRM) removed, so the code could be scanned")
    return "unknown"


def ats_lines(ats: Dict[str, Any]) -> List[str]:
    """ATS settings with their values; the key alone says nothing (NSAllowsArbitraryLoads can be false)."""
    if not ats:
        return ["  " + good("ENFORCED") + dim(" (no ATS overrides; HTTPS with modern TLS required)")]
    off = bool(ats.get("NSAllowsArbitraryLoads"))
    web = bool(ats.get("NSAllowsArbitraryLoadsInWebContent"))
    if off:
        verdict = bad("DISABLED globally (NSAllowsArbitraryLoads = true)")
    elif web:
        verdict = warn("ENFORCED for the app, but disabled for web content")
    else:
        verdict = (warn("ENFORCED (with exceptions)") if ats.get("NSExceptionDomains") else good("ENFORCED"))
    out = ["  " + dim("Status".ljust(18)) + verdict]
    for k in sorted(ats):
        v = ats[k]
        if k == "NSExceptionDomains" and isinstance(v, dict):
            for dom, rules in sorted(v.items()):
                insecure = isinstance(rules, dict) and rules.get("NSExceptionAllowsInsecureHTTPLoads")
                out.append("  " + dim("Exception".ljust(18)) + str(dom) + (bad("  (plaintext HTTP allowed)") if insecure else ""))
        else:
            out.append(f"  {k}: {v}")
    return out


def _kv(lines: List[str], label: str, value: Any):
    if value in (None, "", [], {}):
        return
    lines.append(f"  {dim(f'{label:<18}')}{value}")


_LEVEL_STYLE = {"detected": good, "likely": warn, "weak signal": warn, "SDK only": warn}


def _level(cat: str, level: str) -> str:
    if level == "not found":
        return dim(level) if cat in ("obfuscation", "rasp") else bad(level)
    return _LEVEL_STYLE.get(level, str)(level)


# (platform, group, technique, [(indicator label, required text in the location's "via" or None)])
_PROBE = "File / process / environment probe API (in a function that also holds indicators)"
_SVC = "Inline syscall instruction (svc) - bypasses libc hooks"
_SVC_IOS = "Inline syscall instruction (svc #0x80) - bypasses libc hooks"
CHECK_TYPES = [
    ("android", "Root (Magisk, KernelSU, ...)", "su / Magisk / KernelSU file paths",
     [("su binary probes", None), ("Other su / busybox / root-app file probes", None), ("More su file locations", None),
      ("Magisk / KernelSU / APatch / Zygisk artefacts", None)]),
    ("android", "Root (Magisk, KernelSU, ...)", "Root-manager package names",
     [("Magisk / SuperSU package probes", None), ("Root-management / root-cloak package probes", None), ("Installed-package probe", None)]),
    ("android", "Root (Magisk, KernelSU, ...)", "Executing su / which su",
     [("Runtime.exec('su' / 'which su')", None), ("Command-execution probe (su / which / getprop / ps)", None)]),
    ("android", "Root (Magisk, KernelSU, ...)", "System properties (test-keys, ro.debuggable, ro.secure)",
     [("test-keys build check", None), ("Build.TAGS read (test-keys check)", None),
      ("Root system-property checks (ro.debuggable / ro.secure / ro.build.tags)", None), ("System-property / environment probe", None)]),
    ("android", "Root (Magisk, KernelSU, ...)", "Mount table (/proc/self/mounts, mountinfo)", [("Mount-table inspection (/proc/mounts, mountinfo)", None)]),
    ("android", "Root (Magisk, KernelSU, ...)", "Injected libraries in /proc/self/maps (Zygisk / Riru)", [("/proc/self/maps scan", None)]),
    ("android", "Root (Magisk, KernelSU, ...)", "SELinux mode", [("SELinux mode check", None), ("SELinux API call", None)]),
    ("android", "Root (Magisk, KernelSU, ...)", "Unix sockets (/proc/net/unix)", [("Unix-socket probe (/proc/net/unix)", None)]),
    ("android", "Root (Magisk, KernelSU, ...)", "Direct syscalls (svc) instead of libc", [(_SVC, None)]),
    ("android", "Root (Magisk, KernelSU, ...)", "Verified boot / bootloader lock", [("Verified-boot / bootloader-lock state", None)]),
    ("android", "Root (Magisk, KernelSU, ...)", "Key attestation / Play Integrity",
     [("Play Integrity / SafetyNet attestation", None), ("Hardware key attestation", None), ("Hardware key attestation API call", None)]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "Jailbreak files and apps (Cydia, Sileo, Zebra, /var/lib/dpkg, ...)",
     [("Jailbreak file probes", None), ("Tweak / package-manager file probes", None), ("TrollStore (sideload-installer) probe", None)]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "Rootless jailbreak paths (/var/jb, Dopamine, palera1n)",
     [("Dopamine / palera1n / rootless jailbreak artefacts", None)]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "URL schemes via canOpenURL (cydia://, sileo://, zbra://)",
     [("Cydia / Sileo URL scheme probe", None), (_PROBE, "canOpenURL")]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "Local SSH / port probe", [(_PROBE, "connect("), (_PROBE, "socket(")]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "Sandbox tests (write outside sandbox, fork())",
     [("Sandbox-escape write probes", None), ("Native import: fork (sandbox-integrity probe)", None),
      ("Native import: vfork (sandbox-integrity probe)", None), ("Native import: posix_spawn (sandbox-integrity probe)", None)]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "Loaded-image enumeration (_dyld_image_count / _dyld_get_image_name)",
     [("Native import: _dyld_image_count (loaded-library scan)", None), ("Native import: _dyld_get_image_name (loaded-library scan)", None),
      ("Loaded-image enumeration", None)]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "Hook-library names (Substrate, Substitute, ElleKit, libhooker)",
     [("Substrate / libhooker / ElleKit", None)]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "DYLD_INSERT_LIBRARIES in the environment", [("DYLD_INSERT_LIBRARIES check", None)]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "Symlink checks on system directories",
     [("Symlinked-system-directory probes", None), (_PROBE, "readlink("), (_PROBE, "lstat(")]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "dladdr to verify a function's home library", [("Native import: dladdr (hook detection)", None)]),
    ("ios", "Jailbreak (Dopamine, palera1n, ...)", "Raw syscalls instead of the C library", [(_SVC_IOS, None)]),
    ("any", "Frida", "Default port 27042", [("Frida default port probe (27042)", None)]),
    ("any", "Frida", "D-Bus handshake probe", [("D-Bus handshake probe (AUTH)", None)]),
    ("any", "Frida", "frida-server / frida-helper names and on-disk paths",
     [("frida artefact strings", None), ("Frida on-disk / network probes", None)]),
    ("any", "Frida", "frida-agent / FridaGadget in loaded libraries or images",
     [("frida artefact strings", None), ("IOSSecuritySuite runtime-hook checks", None)]),
    ("android", "Frida", "Thread names (gmain, gdbus, gum-js-loop, pool-frida)", [("Thread-name probes (gmain / gdbus)", None)]),
    ("android", "Frida", "Memory maps (/proc/self/maps)", [("/proc/self/maps scan", None)]),
    ("android", "Frida", "Open fds / tasks under /proc/self", [("Thread / fd enumeration under /proc/self", None)]),
    ("any", "Frida", "Inline-hook / on-disk library comparison",
     [("Inline-hook / library-integrity probes (libc on-disk path)", None), (_PROBE, "mprotect(")]),
    ("android", "Frida", "Java-layer anomalies (native-looking methods, hook frames in stack traces)",
     [("Native-modifier check (hooked-method anomaly)", None), ("Stack-trace inspection (hook-frame scan)", None),
      ("Java-layer hook anomalies (zygote / Xposed frames)", None)]),
    ("any", "Frida", "Anti-attach (TracerPid, ptrace, self-trace)",
     [("TracerPid check", None), ("ptrace anti-attach", None), ("Native import: ptrace (anti-debug)", None),
      ("/proc/self/status or jdwp probe", None), ("Native import: sysctl (P_TRACED check)", None), ("amIDebugged-style helper", None)]),
    ("any", "Frida", "Timing checks", [("Timing measurement (slow-down check)", None), (_PROBE, "clock_gettime("),
                                       (_PROBE, "mach_absolute_time("), (_PROBE, "gettimeofday(")]),
    ("any", "Server-side attestation", "Play Integrity / App Attest / DeviceCheck",
     [("Play Integrity / SafetyNet attestation", None), ("App Attest / DeviceCheck", None)]),
]

LOC_LIMIT = 30     # lines per indicator in the text view; --json carries every record

_KIND_TAG = {"java-method": "java method", "java-class": "java class", "java-field": "java field", "java-string": "dex string", "objc-method": "objc method",
             "objc-class": "objc class", "native-function": "native func", "native-symbol": "symbol",
             "native-string": "string", "native-import": "import", "file-string": "file"}


def location_lines(records: List[Dict[str, Any]], platform: str) -> List[str]:
    """Every place a protection check lives: methods, runtime-dispatched methods, native functions, addresses."""
    from . import protections
    labels = {c: l[platform] for c, l in protections.CATEGORIES}
    by: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    notes: List[str] = []
    for r in records:
        if r["kind"] == "note":
            notes.append(f"{r['file']}: {r['where']}")
        elif r["kind"] != "error":
            by.setdefault(r["category"], {}).setdefault(r["indicator"], []).append(r)
    L = ["", head("Techniques checked (what each looks for, and how many code locations were found)")]
    last = None
    for plat, group, tech, wants in CHECK_TYPES:
        if plat not in (platform, "any"):
            continue
        if group != last:
            L.append("  " + head(group))
            last = group
        n = sum(1 for r in records if r["kind"] not in ("note", "error")
                and any(r["indicator"] == ind and (v is None or v in r["via"]) for ind, v in wants))
        L.append("    " + (good("found    ") + dim(f"{n:>4} locations   ") if n else dim("not found".ljust(25))) + tech)
    L.append("")
    L.append(head("Where the checks are (every location found, static)"))
    if not by:
        L.append("  " + dim("no locations found"))
    for cat, _l in protections.CATEGORIES:
        inds = by.get(cat)
        if not inds:
            continue
        total = sum(len(v) for v in inds.values())
        L.append("")
        L.append("  " + head(labels.get(cat, cat)) + dim(f"  ({total} locations)"))
        for ind, recs in inds.items():
            recs = sorted(recs, key=lambda r: (r["sdk"], r["kind"], r["file"], r["where"]))
            L.append("    " + warn(ind) + dim(f"  ({len(recs)})"))
            for r in recs[:LOC_LIMIT]:
                addr = (r["address"] or "").ljust(12)
                tag = _KIND_TAG.get(r["kind"], r["kind"]).ljust(12)
                sdk = dim(" [SDK]") if r["sdk"] else ""
                L.append(f"      {dim(tag)} {r['where']}")
                L.append(f"      {' ' * 12} {dim((addr + ' ' if r['address'] else '') + r['via'] + ' - ' + r['file'])}{sdk}")
            if len(recs) > LOC_LIMIT:
                L.append("      " + dim(f"... and {len(recs) - LOC_LIMIT} more (all of them are in --json)"))
    for n in notes[:5]:
        L.append("  " + warn(n))
    L.append("")
    L.append("  " + dim("Addresses are virtual addresses inside the named binary; java/objc methods have none (they are "
                        "reached by name through the runtime). Native names shown as sub_<addr> are stripped functions."))
    return L


_STACK_ORDER = ["Framework", "Language", "Engine", "UI", "Architecture", "Networking", "Serialization", "Images", "Storage",
                "Media", "Maps", "Analytics & crash", "Attribution & ads", "Push & messaging", "Payments", "Auth & security",
                "Security", "Updates", "Native"]


def techstack_lines(ts: Dict[str, Any], platform: str, *, full: bool = False) -> List[str]:
    """What the app is built with: framework, languages, libraries / SDKs by purpose, and the build toolchain."""
    L = ["", head("Tech stack")]
    items = ts.get("items") or []
    tool = ts.get("toolchain") or {}
    L.append("  " + dim("Built with".ljust(18)) + good(ts.get("primary") or "?"))
    by: Dict[str, List[Dict[str, Any]]] = {}
    for it in items:
        by.setdefault(it["category"], []).append(it)
    for cat in _STACK_ORDER + sorted(set(by) - set(_STACK_ORDER)):
        its = by.get(cat)
        if not its:
            continue
        names = ", ".join(i["name"] + (" " + str(i["version"]) if i.get("version") else "") for i in its)
        L.append("  " + dim(cat.ljust(18)) + names)
        if full:
            for i in its:
                if i.get("evidence"):
                    L.append("  " + " " * 18 + dim("%s: %s" % (i["name"], "; ".join(i["evidence"]))))
    t: List[str] = []
    if platform == "ios":
        if tool.get("xcode"):
            t.append("Xcode " + str(tool["xcode"]) + (" (%s)" % tool["xcode_build"] if tool.get("xcode_build") else ""))
        if tool.get("sdk"):
            t.append("SDK " + str(tool["sdk"]))
        if tool.get("compiler"):
            t.append(str(tool["compiler"]).replace("com.apple.compilers.llvm.clang.1_0", "Apple clang (LLVM)"))
        if tool.get("archs"):
            t.append("arch " + "+".join(tool["archs"]))
    else:
        if tool.get("agp"):
            t.append("Android Gradle Plugin " + str(tool["agp"]))
        if tool.get("compile_sdk"):
            t.append("compileSdk " + str(tool["compile_sdk"]))
        if tool.get("abis"):
            t.append("ABIs " + ", ".join(tool["abis"]))
    if t:
        L.append("  " + dim("Toolchain".ljust(18)) + "; ".join(t))
    ob = tool.get("obfuscation")
    if ob:
        pct = ob["percent_short_names"]
        verdict = (warn("likely obfuscated / minified (R8, ProGuard or similar)") if pct >= 40
                   else "partly minified" if pct >= 10 else "class names look intact")
        L.append("  " + dim("Code names".ljust(18)) + f"{verdict}" + dim(f"  ({pct}% of {ob['classes']} classes have 1-2 letter names)"))
    if not items:
        L.append("  " + dim("(nothing recognised)"))
    return L


def protection_lines(s: Dict[str, Any], *, full: bool = False) -> List[str]:
    """Static detection of client-side protections, per-binary hardening and (if present) Capacitor SQL encryption."""
    P = s.get("protections")
    if not P:
        return (["", head("Protections"), "  " + dim(f"(not available: {s['protections_error']})")]
                if s.get("protections_error") else [])
    L: List[str] = ["", head("Protections found in the app (static)")]
    for cat, c in P["categories"].items():
        ev = ", ".join(c["evidence"][: (8 if full else 3)])
        extra = ""
        if c.get("sdk_evidence") and c["level"] != "SDK only":
            extra = dim(f"   (+ in third-party SDKs: {', '.join(c['sdk_evidence'][:2])})")
        lv = _level(cat, c["level"])
        pad = " " * max(1, 13 - len(c["level"]))
        L.append(f"  {dim(c['label'].ljust(38))}{lv}{pad}{dim(ev) if c['level'] == 'SDK only' else ev}{extra}")
    cap = P.get("capacitor") or {}
    if cap.get("privacy_screen_enabled") is not None:
        L.append("  " + dim(f"{'Capacitor PrivacyScreen':<38}") + (good("enabled") if cap["privacy_screen_enabled"] else bad("disabled")))
    L.append("  " + dim("Static indicators only: 'detected' means the code/SDK is present, not that it is effective or "
                         "unbypassable. 'not found' can also mean the app is packed or obfuscated."))
    if P.get("packed"):
        L.append("  " + bad("App looks packed / shielded: static results above are incomplete."))

    if full and P.get("locations") is not None:
        L += location_lines(P["locations"], s["platform"])

    sq = P.get("capacitor_sql") or {}
    if sq:
        L.append("")
        L.append(head("Capacitor SQLite database encryption"))
        st = sq["status"]
        _kv(L, "Encryption", {"on": good("ON"), "off": bad("OFF"), "unclear": warn("unclear")}[st]
            + (dim(f"  ({sq['config_key']} = {str(sq['config_flag']).lower()})") if sq.get("config_key") else ""))
        _kv(L, "Connection modes", ", ".join(sq.get("modes") or []))
        if sq.get("sqlcipher"):
            _kv(L, "SQLCipher", good("bundled") + dim("  " + ", ".join(x.rsplit("/", 1)[-1] for x in sq["sqlcipher"])) +
                (warn("  (bundled, but encryption is off)") if st == "off" else ""))
        elif st == "on":
            _kv(L, "SQLCipher", warn("not found in the package"))
        if sq.get("hard_coded_secret"):
            _kv(L, "Passphrase", bad("a literal passphrase is passed to setEncryptionSecret() in the web code"))
        if sq.get("plain_bundled_dbs"):
            _kv(L, "Bundled databases", bad("plain SQLite (unencrypted): ") + ", ".join(sq["plain_bundled_dbs"]))
        if sq.get("biometric"):
            _kv(L, "Biometric unlock", good("configured"))

    b = P.get("binaries") or {}
    if b.get("total"):
        L.append("")
        L.append(head(f"Binary protection ({b['total']} binaries checked)"))
        weak = b.get("weak") or []
        rows = b["rows"]
        if s["platform"] == "ios":
            mains = [r for r in rows if r.get("main")]
            if mains:
                m = mains[0]
                _kv(L, "Main binary", f"PIE {_yn(m.get('pie'), 'yes', 'NO')}   canary {_yn(m.get('canary'), 'yes', 'no')}"
                    + ("   " + bad("exec stack") if m.get("exec_stack") else "")
                    + ("   " + bad("FairPlay-encrypted") if m.get("encrypted") else ""))
            pie_bad = sum(1 for r in rows if r.get("main") and r.get("pie") is False)
            can_bad = [r for r in rows if r.get("canary") is False and not r.get("swift")]
            _kv(L, "Missing canary", (warn if can_bad else good)(f"{len(can_bad)} of {len(rows)} binaries") + dim("  (heuristic; Swift code is excluded)"))
            n = len(rows)
            ex = sum(1 for r in rows if r.get("exec_stack"))
            _kv(L, "Executable stack", (bad if ex else good)(f"{ex} of {n} binaries") + dim("  (0 is good)" if not ex else ""))
            enc = [r for r in rows if r.get("encrypted")]
            # FairPlay is Apple's App Store DRM, not a protection the developer chose: every App Store build is encrypted
            # on the device, and 0 here only means this copy is a decrypted dump. Not a weakness of the app, so no
            # good/bad colour; still-encrypted binaries matter only because their code could not be scanned.
            _kv(L, "Still encrypted", (warn(f"{len(enc)} of {n} binaries") if enc else f"0 of {n} binaries")
                + (dim("  not scanned: " + ", ".join(r["name"].rsplit("/", 1)[-1] for r in enc[:5])) if enc
                   else dim("  (decrypted dump: all code was scanned; FairPlay is App Store DRM, not an app weakness)")))
        else:
            n = len(rows)
            nr = sum(1 for r in rows if r.get("relro") == "none")
            nx = sum(1 for r in rows if r.get("nx") is False)
            can = sum(1 for r in rows if r.get("canary") is False)
            _kv(L, "Missing RELRO", (bad if nr else good)(f"{nr} of {n} libraries") + dim("  (0 is good)" if not nr else ""))
            _kv(L, "Executable stack", (bad if nx else good)(f"{nx} of {n} libraries") + dim("  (0 is good)" if not nx else ""))
            _kv(L, "Missing canary", (warn if can else good)(f"{can} of {n} libraries") + dim("  (heuristic)"))
        if weak:
            L.append("  " + dim("Binaries with issues:"))
            for r in weak[: (len(weak) if full else 6)]:
                L.append(f"    {r['name'].rsplit('/', 2)[-1] if not full else r['name']}  " + warn(", ".join(r["issues"])))
            if not full and len(weak) > 6:
                L.append("    " + dim(f"... {len(weak) - 6} more (use --full)"))
    return L


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
        L.append(bad(f"!! WARNING: {w}"))
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

    if s.get("tech_stack"):
        L.extend(techstack_lines(s["tech_stack"], s["platform"], full=full))
    elif s.get("tech_stack_error"):
        L += ["", head("Tech stack"), "  " + dim(f"(not available: {s['tech_stack_error']})")]

    L.append("")
    L.append("Signing")
    sg = s.get("signer") or {}
    if s["platform"] == "ios":
        _kv(L, "Team ID", sg.get("team_id"))
        enc = s.get("encryption") or []
        if enc:
            verdicts = sorted({e.get("verdict", "?") for e in enc if isinstance(e, dict)})
            _kv(L, "Main binary", ", ".join(verdicts))
            _kv(L, "Encryption", _enc_plain(verdicts))
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
            L.append("  " + bad("! " + flag.replace("_", " ")))
    if not any(s.get("flags", {}).values()):
        L.append("  " + good("(no risky flags)"))

    L.extend(protection_lines(s, full=full))

    perms = s.get("permissions") or []
    if s["platform"] == "ios":
        L.extend(perms_mod.ios_permission_lines(perms, s.get("permission_purposes") or {}, full=full))
        L.extend(perms_mod.ios_entitlement_lines(s.get("entitlements") or {}, full=full))
        _kv(L, "URL schemes", ", ".join(s.get("url_schemes") or []))
        _kv(L, "Associated domains", ", ".join(s.get("associated_domains") or []))
        ats = s.get("ats")
        L.append("")
        L.append("App Transport Security (ATS)")
        L.extend(ats_lines(ats))
    else:
        L.extend(perms_mod.android_permission_lines(perms, s.get("dangerous_permissions") or [], full=full))
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
        L.append("Scan: " + "  ".join(Term.c(f"{c.get(k, 0)} {k.title()}", k) for k in ("HIGH", "MEDIUM", "LOW", "INFO")))
    out = []
    title_done = False
    for ln in L:
        plain = ln.lstrip()
        if (not title_done) and ln and not ln.startswith((" ", "\x1b", "!")):
            out.append(Term.c(ln, "id"))
            title_done = True
        elif ln and not ln.startswith((" ", "=", "\x1b", "!", "Scan:")):
            out.append(head(ln))
        elif ln.startswith("="):
            out.append(dim(ln))
        else:
            out.append(ln)
    return "\n".join(out)
