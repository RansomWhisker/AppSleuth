"""Where exactly is each protection check? (static, observe-only)

For every indicator in the protection signature table this finds the concrete locations:

* Java / Kotlin  - methods that reference the indicator string, call a matching method or use a matching
                   class, plus classes / methods *defined* with a matching name (app and library code).
* Native (ELF)   - exported / internal symbols, the string's address and the functions that reference it
                   (arm64 adrp+add, x86-64 rip-relative), and call sites of imported functions such as ptrace.
* Native (Mach-O)- symbols, string / CFString / selector addresses with the functions that use them,
                   Objective-C methods and classes (the runtime's dispatch tables), call sites of imports.
* Other files    - web bundles, plists, configs: file and offset.

Record: {category, indicator, kind, file, where, address, via, sdk}. Static analysis only; addresses are virtual
addresses inside the named binary. Observe-only: nothing here modifies or bypasses a check.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import appfiles, engine, protections

TEXT_EXT = {".js", ".mjs", ".json", ".plist", ".xml", ".html", ".properties", ".txt"}
MAX_CLASS_METHODS = 40     # methods listed per matching class (the class itself is always listed)
MAX_PER_FILE = 12          # text-file hits per indicator per file


def rec(cat: str, label: str, kind: str, file: str, where: str, address: Optional[int] = None,
        via: str = "", sdk: bool = False) -> Dict[str, Any]:
    return {"category": cat, "indicator": label, "kind": kind, "file": file, "where": where,
            "address": ("0x%x" % address) if address is not None else None, "via": via, "sdk": sdk}


def sigs_for(plat: str) -> List[Tuple[str, str, List[str]]]:
    """[(category, label, needles as str)] with dotted and JNI-underscore variants added."""
    out = []
    for cat, label, pl, _st, needles in protections.SIGS:
        if pl not in (plat, "any"):
            continue
        ns: List[str] = []
        for n in needles:
            ns.append(n)
            if "/" in n and "." not in n and n.count("/") >= 2 and n[0].isalpha():
                ns.append(n.replace("/", "."))
        out.append((cat, label, ns))
    return out


def _sdk_class(desc: str) -> bool:
    return bool(protections._THIRD_PARTY.search(desc))


# ---------------------------------------------------------------- API probes
# Generic APIs (file / process / package / property / class probes) are everywhere in normal code, so they are only
# reported for a class that also holds an indicator of the category (e.g. a "su" path next to File.exists()).
# Specific ones are reported wherever they occur.  (category or None, label, kind, [callee/field signatures])
JAVA_PROBES = [
    (None, "File-existence / file-read probe", "m",
     ["Ljava/io/File;->exists", "Ljava/io/File;->canRead", "Ljava/io/File;->isFile", "Ljava/io/File;->isDirectory",
      "Ljava/io/File;->list", "Ljava/io/File;->listFiles", "Ljava/io/FileInputStream;-><init>", "Ljava/io/FileReader;-><init>",
      "Ljava/io/RandomAccessFile;-><init>", "Ljava/nio/file/Files;->exists", "Landroid/system/Os;->access",
      "Landroid/system/Os;->stat", "Landroid/system/Os;->lstat"]),
    (None, "Command-execution probe (su / which / getprop / ps)", "m",
     ["Ljava/lang/Runtime;->exec", "Ljava/lang/ProcessBuilder;->start"]),
    (None, "Installed-package probe", "m",
     ["Landroid/content/pm/PackageManager;->getPackageInfo", "Landroid/content/pm/PackageManager;->getApplicationInfo",
      "Landroid/content/pm/PackageManager;->getInstalledPackages", "Landroid/content/pm/PackageManager;->getInstalledApplications",
      "Landroid/content/pm/PackageManager;->getLaunchIntentForPackage", "Landroid/content/pm/PackageManager;->queryIntentActivities",
      "Landroid/content/pm/PackageManager;->resolveActivity"]),
    (None, "System-property / environment probe", "m",
     ["Landroid/os/SystemProperties;->get", "Ljava/lang/System;->getProperty", "Ljava/lang/System;->getenv"]),
    (None, "Class-presence probe (Class.forName / loadClass)", "m",
     ["Ljava/lang/Class;->forName", "Ljava/lang/ClassLoader;->loadClass"]),
    (None, "Stack-trace inspection (hook-frame scan)", "m",
     ["Ljava/lang/Thread;->getStackTrace", "Ljava/lang/Throwable;->getStackTrace", "Ljava/lang/Thread;->getAllStackTraces"]),
    (None, "Native check library load", "m", ["Ljava/lang/System;->loadLibrary", "Ljava/lang/System;->load"]),
    (None, "Integrity hashing / zip inspection", "m",
     ["Ljava/security/MessageDigest;->getInstance", "Ljava/util/zip/ZipFile;-><init>", "Ljava/util/zip/ZipEntry;->getCrc"]),
    (None, "Native-modifier check (hooked-method anomaly)", "m",
     ["Ljava/lang/reflect/Modifier;->isNative", "Ljava/lang/reflect/Method;->getModifiers"]),
    (None, "Timing measurement (slow-down check)", "m",
     ["Ljava/lang/System;->nanoTime", "Landroid/os/SystemClock;->elapsedRealtimeNanos", "Landroid/os/SystemClock;->uptimeMillis"]),
    ("root", "SELinux API call", "m", ["Landroid/os/SELinux;->isSELinuxEnforced", "Landroid/os/SELinux;->isSELinuxEnabled"]),
    ("root", "Hardware key attestation API call", "m",
     ["Landroid/security/keystore/KeyGenParameterSpec$Builder;->setAttestationChallenge"]),
    ("emulator", "Build identity fields read (emulator check)", "f",
     ["Landroid/os/Build;->FINGERPRINT", "Landroid/os/Build;->MODEL", "Landroid/os/Build;->MANUFACTURER", "Landroid/os/Build;->BRAND",
      "Landroid/os/Build;->DEVICE", "Landroid/os/Build;->PRODUCT", "Landroid/os/Build;->HARDWARE", "Landroid/os/Build;->BOARD"]),
    ("root", "Build.TAGS read (test-keys check)", "f", ["Landroid/os/Build;->TAGS"]),
    ("debugger", "ApplicationInfo.flags read (debuggable check)", "f", ["Landroid/content/pm/ApplicationInfo;->flags"]),
    ("tamper", "PackageInfo signatures read (signature check)", "f",
     ["Landroid/content/pm/PackageInfo;->signatures", "Landroid/content/pm/PackageInfo;->signingInfo"]),
    ("debugger", "Debugger-state API call", "m",
     ["Landroid/os/Debug;->isDebuggerConnected", "Landroid/os/Debug;->waitingForDebugger"]),
    ("screen", "Window flags set (FLAG_SECURE candidates)", "m",
     ["Landroid/view/Window;->setFlags", "Landroid/view/Window;->addFlags", "Landroid/app/Activity;->registerScreenCaptureCallback"]),
]


# --------------------------------------------------------------------------- DEX
def _java_name(desc: str) -> str:
    d = desc
    if d.startswith("L") and d.endswith(";"):
        d = d[1:-1]
    return d.replace("/", ".")


def locate_dex(path: str, rel: str, sigs) -> List[Dict[str, Any]]:
    with open(path, "rb") as fh:
        dx = engine.DexFile(fh.read(), track_refs=True)
    out: List[Dict[str, Any]] = []
    strings = dx.strings
    type_of_string: Dict[int, int] = {}
    for t, sidx in enumerate(dx.type_ids):
        type_of_string[sidx] = t
    by_name: Dict[int, List[int]] = {}
    by_class: Dict[int, List[int]] = {}
    for mi, (ci, _pi, ni) in enumerate(dx.method_ids):
        by_name.setdefault(ni, []).append(mi)
        by_class.setdefault(ci, []).append(mi)
    by_field: Dict[int, List[int]] = {}
    for fi, (_ci, _ti, ni) in enumerate(dx.field_ids):
        by_field.setdefault(ni, []).append(fi)
    defined = {mi for _c, mi in dx.defs}
    defined_class = {c["class_idx"] for c in dx.classes}
    seen = set()

    def add(cat, label, kind, where, via, sdk_desc, idx=None):
        key = (cat, label, kind, where, via)
        if key in seen:
            return
        seen.add(key)
        out.append(rec(cat, label, kind, rel, where, None, via, _sdk_class(sdk_desc)))

    def mlabel(mi):
        return dx.method_label(mi)

    def owner_desc(mi):
        return dx.type_name(dx.method_ids[mi][0])

    for cat, label, needles in sigs:
        lowered = [(n, n.lower()) for n in needles]
        for sidx, s in enumerate(strings):
            if not s:
                continue
            hit = None
            for n, nl in lowered:
                if n in s:
                    hit = n
                    break
            if hit is None or s in protections.BENIGN_DEX_FIELDS:      # the bare identifier, not a longer string
                continue
            shown = (s if len(s) <= 80 else s[:77] + "...").replace("\n", "\\n").replace("\r", "\\r")
            n_before = len(out)
            # 1. methods loading the string constant
            for lab in dx.string_owners.get(sidx, []):
                add(cat, label, "java-method", lab, 'uses string "%s"' % shown, lab.split("->")[0])
            # 2. a class descriptor: defined here? used by whom?
            t = type_of_string.get(sidx)
            if t is not None:
                if t in defined_class:
                    add(cat, label, "java-class", _java_name(s), "class defined", s)
                    shown_m = 0
                    for mi in by_class.get(t, []):
                        if mi in defined and shown_m < MAX_CLASS_METHODS:
                            shown_m += 1
                            add(cat, label, "java-method", mlabel(mi), "method of matching class", s)
                for mi in sorted(dx.type_users.get(t, ())):
                    add(cat, label, "java-method", mlabel(mi), "uses class %s" % _java_name(s), owner_desc(mi))
                for mj in by_class.get(t, []):
                    for caller in sorted(dx.callees.get(mj, ())):
                        add(cat, label, "java-method", mlabel(caller), "calls %s" % mlabel(mj), owner_desc(caller))
            # 3. a method name: defined here? called by whom?
            for mj in by_name.get(sidx, []):
                if mj in defined:
                    add(cat, label, "java-method", mlabel(mj), "method defined (name matches)", owner_desc(mj))
                for caller in sorted(dx.callees.get(mj, ())):
                    add(cat, label, "java-method", mlabel(caller), "calls %s" % mlabel(mj), owner_desc(caller))
            # 4. a field name: who reads / writes it? (constants javac inlined leave only the field itself)
            for fi in by_field.get(sidx, []):
                fci = dx.field_ids[fi][0]
                fname = "%s.%s" % (_java_name(dx.type_name(fci)), s)
                users = sorted(dx.field_users.get(fi, ()))
                for mi in users:
                    add(cat, label, "java-method", mlabel(mi), "accesses field %s" % fname, owner_desc(mi))
                if not users:
                    add(cat, label, "java-field", fname, "field referenced", dx.type_name(fci))
            if len(out) == n_before:
                add(cat, label, "java-string", '"%s"' % shown, "in the dex string table only: no code loads it "
                    "(debug-info name, annotation or Kotlin metadata)", "")
    out += _dex_probes(dx, rel, out)
    return _merge_methods(out)


def _dex_probes(dx, rel: str, found: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Calls / field reads that implement a check (file, process, package, property, class, stack probes)."""
    msig: Dict[str, List[int]] = {}
    for mi, (ci, _pi, ni) in enumerate(dx.method_ids):
        nm = dx.strings[ni] if 0 <= ni < len(dx.strings) else None
        if nm:
            msig.setdefault(dx.type_name(ci) + "->" + nm, []).append(mi)
    fsig: Dict[str, List[int]] = {}
    for fi, (ci, _ti, ni) in enumerate(dx.field_ids):
        nm = dx.strings[ni] if 0 <= ni < len(dx.strings) else None
        if nm:
            fsig.setdefault(dx.type_name(ci) + "->" + nm, []).append(fi)
    ctx: Dict[str, Dict[str, set]] = {}        # category -> class descriptor -> {indicator labels}
    for r in found:
        if r["kind"] == "java-method" and "->" in r["where"]:
            ctx.setdefault(r["category"], {}).setdefault(r["where"].split("->")[0], set()).add(r["indicator"])
    out: List[Dict[str, Any]] = []
    for cat, label, kind, sigs in JAVA_PROBES:
        for sg in sigs:
            if kind == "m":
                users = [(mj, c) for mj in msig.get(sg, []) for c in dx.callees.get(mj, ())]
            else:
                users = [(fi, c) for fi in fsig.get(sg, []) for c in dx.field_users.get(fi, ())]
            api = _java_name(sg.split("->")[0]) + "." + sg.split("->")[1]
            for _t, caller in users:
                owner = dx.type_name(dx.method_ids[caller][0])
                where = dx.method_label(caller)
                if cat is not None:
                    out.append(rec(cat, label, "java-method", rel, where, None,
                                   "%s %s" % ("reads" if kind == "f" else "calls", api), _sdk_class(owner)))
                else:
                    for c2, classes in ctx.items():
                        if owner in classes:
                            out.append(rec(c2, label, "java-method", rel, where, None,
                                           "calls %s; class also holds: %s" % (api, ", ".join(sorted(classes[owner])[:3])),
                                           _sdk_class(owner)))
    return out


def _merge_methods(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One record per (indicator, method): several reasons for the same method are joined into one line."""
    merged: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {}
    reasons: Dict[Tuple[str, str, str, str, str], List[str]] = {}
    order: List[Tuple[str, str, str, str, str]] = []
    for r in records:
        k = (r["category"], r["indicator"], r["kind"], r["file"], r["where"])
        if k not in merged:
            merged[k] = r
            reasons[k] = []
            order.append(k)
        reasons[k].append(r["via"])
    for k in order:
        vs = reasons[k]
        strs = [v[len("uses string "):] for v in vs if v.startswith("uses string ")]
        rest = [v for v in vs if not v.startswith("uses string ")]
        parts = []
        if strs:  # the string constant is the most direct evidence, so it goes first
            more = " (+%d more)" % (len(strs) - 4) if len(strs) > 4 else ""
            parts.append("uses string%s %s%s" % ("s" if len(strs) > 1 else "", ", ".join(strs[:4]), more))
        parts += rest
        via = "; ".join(parts[:4])
        merged[k]["via"] = via if len(via) <= 220 else via[:217] + "..."
    return [merged[k] for k in order]


# ------------------------------------------------------------------ plain files
def locate_text(path: str, rel: str, sigs, data: bytes) -> List[Dict[str, Any]]:
    out = []
    sdk = protections._is_sdk_path(rel)
    for cat, label, needles in sigs:
        n_hits = 0
        for n in needles:
            nb = n.encode()
            pos = data.find(nb)
            while pos != -1 and n_hits < MAX_PER_FILE:
                line = data.count(b"\n", 0, pos) + 1
                out.append(rec(cat, label, "file-string", rel, 'text "%s" at line %d' % (n, line), pos,
                               "file offset", sdk))
                n_hits += 1
                pos = data.find(nb, pos + len(nb))
    return out


# ----------------------------------------------------------------------- driver
def locate_all(app: appfiles.App) -> List[Dict[str, Any]]:
    from . import locate_elf, locate_macho            # imported lazily: only needed for --full
    sigs = sigs_for(app.platform)
    results: List[Dict[str, Any]] = []
    for p in app.files():
        rel = app.rel(p)
        ext = os.path.splitext(p)[1].lower()
        try:
            size = os.path.getsize(p)
            if size == 0 or size > protections.MAX_FILE:
                continue
            with open(p, "rb") as fh:
                head = fh.read(4)
            if head == b"dex\n":
                results += locate_dex(p, rel, sigs)
            elif head == b"\x7fELF" and app.platform == "android":
                results += locate_elf.locate(p, rel, sigs, protections._is_sdk_path(rel))
            elif head in protections.MACHO_MAGIC and app.platform == "ios":
                results += locate_macho.locate(p, rel, sigs, protections._is_sdk_path(rel))
            elif ext in TEXT_EXT:
                with open(p, "rb") as fh:
                    results += locate_text(p, rel, sigs, fh.read())
        except Exception as ex:   # one unreadable binary must not hide the rest
            results.append(rec("", "", "error", rel, "%s: %s" % (type(ex).__name__, ex)))
    return results


def locate_path(path: str) -> List[Dict[str, Any]]:
    with appfiles.unpacked(path) as app:
        return locate_all(app)


def group(records: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    g: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for r in records:
        if r["kind"] in ("error", "note"):
            continue
        g.setdefault(r["category"], {}).setdefault(r["indicator"], []).append(r)
    return g
