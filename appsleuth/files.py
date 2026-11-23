"""`appsleuth files`: list the important files inside an IPA / APK / APKS / AAB and open any of them.

Binary formats are decoded for reading: binary plists and .mobileprovision become XML, compiled Android XML
(AndroidManifest.xml, res/xml/*.xml) becomes text, JSON is pretty-printed. Anything else binary is shown as a hex dump.
Content goes to stdout (pipe-friendly); status lines go to stderr.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
from typing import Any, Dict, List, Optional, Tuple
from xml.sax.saxutils import quoteattr

from . import appfiles, engine

MAX_TEXT = 400_000          # bytes shown per file unless full=True
HEX_BYTES = 4096

# (regex on the lower-cased path inside the app, label). First match wins.
_IMPORTANT: List[Tuple[re.Pattern, str]] = [(re.compile(p), l) for p, l in [
    (r"(^|/)androidmanifest\.xml$", "Android manifest"),
    (r"^payload/[^/]+\.app/info\.plist$", "App Info.plist"),
    (r"^payload/[^/]+\.app/plugins/[^/]+\.appex/info\.plist$", "App extension Info.plist"),
    (r"(^|/)embedded\.mobileprovision$", "Provisioning profile"),
    (r"(^|/)googleservice-info\.plist$", "Firebase config (iOS)"),
    (r"(^|/)google-services\.json$", "Firebase config (Android)"),
    (r"(^|/)capacitor\.config\.(json|js|ts)$", "Capacitor config"),
    (r"(^|/)capacitor\.plugins\.json$", "Capacitor plugins"),
    (r"(^|/)ionic\.config\.json$", "Ionic config"),
    (r"(^|/)(www/|assets/www/)?config\.xml$", "Cordova config"),
    (r"(^|/)cordova_plugins\.js$", "Cordova plugins"),
    (r"(^|/)network_security_config\.xml$", "Network security config"),
    (r"(^|/)privacyinfo\.xcprivacy$", "Privacy manifest"),
    (r"(^|/)settings\.bundle/root\.plist$", "Settings bundle"),
    (r"(^|/)\.env[^/]*$", "Environment file"),
    (r"(^|/)(appsettings[^/]*|app\.config|config|configuration|secrets?|credentials?|keys?)\.(json|plist|xml|ya?ml|properties|ini)$", "App configuration"),
    (r"(^|/)(firebase|remoteconfig|branch|amplify[^/]*|aws[^/]*)\.(json|plist|xml)$", "Service configuration"),
    (r"(^|/)manifest\.json$", "Web manifest"),
    (r"(^|/)(assetlinks\.json|apple-app-site-association)$", "Link association"),
    (r"(^|/)meta-inf/[^/]+\.(rsa|dsa|ec|sf|mf)$", "APK signature"),
    (r"(^|/)_codesignature/coderesources$", "Code signature"),
    (r"\.(pem|p12|pfx|cer|crt|der|keystore|jks|bks|key)$", "Certificate / key material"),
    (r"\.(sqlite3?|db|realm)$", "Database"),
    (r"\.(map)$", "Source map"),
    (r"(^|/)(index\.android\.bundle|main\.jsbundle)$", "React Native bundle"),
    (r"(^|/)res/raw/[^/]+\.json$", "Raw JSON resource"),
    (r"(^|/)assets/[^/]+\.(json|xml|ya?ml|properties|plist)$", "Asset config"),
]]


def classify(rel: str) -> Optional[str]:
    low = rel.lower()
    if ":" in low.split("/", 1)[0]:                 # split label "split0_x.apk:path"
        low = low.split(":", 1)[1]
    for rx, label in _IMPORTANT:
        if rx.search(low):
            return label
    return None


def collect(app: appfiles.App, *, everything: bool = False, pattern: Optional[str] = None) -> List[Dict[str, Any]]:
    """[{rel, path, size, label}] sorted: important files first (in table order), then the rest if everything."""
    rows = []
    for full in app.files():
        rel = app.rel(full)
        label = classify(rel)
        if label is None and not everything:
            continue
        rows.append({"rel": rel, "path": full, "size": _size(full), "label": label or ""})
    if pattern:
        rx = _pattern(pattern)
        rows = [r for r in rows if rx.search(r["rel"])]
    order = {lab: i for i, (_, lab) in enumerate(_IMPORTANT)}
    rows.sort(key=lambda r: (order.get(r["label"], 999), r["rel"].lower()))
    return rows


def _pattern(p: str) -> re.Pattern:
    """Case-insensitive; `*` and `?` work as globs, anything else is a plain substring."""
    return re.compile(".*".join(re.escape(x) for x in re.split(r"\*+", p.replace("?", "*"))), re.I)


def _size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return str(n)


def resolve(rows: List[Dict[str, Any]], ref: str) -> List[Dict[str, Any]]:
    """A row number (as printed), an exact path, or a name / glob / substring. May return several."""
    if ref.isdigit() and 1 <= int(ref) <= len(rows):
        return [rows[int(ref) - 1]]
    exact = [r for r in rows if r["rel"].lower() == ref.lower()]
    if exact:
        return exact
    base = [r for r in rows if r["rel"].rsplit("/", 1)[-1].lower() == ref.lower()]
    if base:
        return base
    rx = _pattern(ref)
    return [r for r in rows if rx.search(r["rel"])]


# ---------------------------------------------------------------- rendering

def _axml_to_text(data: bytes) -> str:
    root = engine.build_manifest_tree(data)
    out: List[str] = ["<!-- decoded from compiled binary XML; namespace prefixes and attribute order may differ -->"]

    def walk(n, depth):
        pad = "  " * depth
        attrs = "".join(f" {k}={quoteattr(str(v))}" for k, v in n.attrs.items())
        if n.children:
            out.append(f"{pad}<{n.tag}{attrs}>")
            for c in n.children:
                walk(c, depth + 1)
            out.append(f"{pad}</{n.tag}>")
        else:
            out.append(f"{pad}<{n.tag}{attrs}/>")
    if root is not None:
        walk(root, 0)
    return "\n".join(out) + "\n"


def _hexdump(data: bytes, limit: int) -> str:
    lines = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        lines.append(f"{off:08x}  {hx}  {''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}")
    if len(data) > limit:
        lines.append(f"... {len(data) - limit} more bytes (use --full or --save to get the whole file)")
    return "\n".join(lines) + "\n"


def _plist_text(obj: Any) -> str:
    return plistlib.dumps(obj, fmt=plistlib.FMT_XML, sort_keys=False).decode("utf-8", "replace")


def render(path: str, rel: str, *, full: bool = False, raw: bool = False, hexdump: bool = False) -> Tuple[str, str]:
    """-> (text, how) where how says what was done to the bytes ('plist', 'axml', 'json', 'text', 'hex', ...)."""
    with open(path, "rb") as fh:
        data = fh.read() if full else fh.read(MAX_TEXT * 4)
    cut = None if full else MAX_TEXT
    low = rel.lower()
    if hexdump:
        return _hexdump(data, len(data) if full else HEX_BYTES), "hex"
    if not raw:
        try:
            if data[:6] == b"bplist" or low.endswith(".plist"):
                return _clip(_plist_text(plistlib.loads(data)), cut), "plist"
        except Exception:
            pass
        if low.endswith(".mobileprovision"):
            m = re.search(rb"<\?xml.*?</plist>", data, re.S)
            if m:
                try:
                    return _clip(_plist_text(plistlib.loads(m.group(0))), cut), "plist (CMS signature stripped)"
                except Exception:
                    return _clip(m.group(0).decode("utf-8", "replace"), cut), "plist (CMS signature stripped)"
        if len(data) >= 8 and int.from_bytes(data[:2], "little") == engine.RES_XML_TYPE:
            try:
                return _clip(_axml_to_text(data), cut), "compiled Android XML"
            except Exception:
                pass
    text = _decode_text(data)
    if text is None:
        return _hexdump(data, HEX_BYTES if not full else len(data)), "binary (hex dump)"
    if not raw and (low.endswith(".json") or text.lstrip()[:1] in "{["):
        try:
            return _clip(json.dumps(json.loads(text), indent=2, ensure_ascii=False) + "\n", cut), "json"
        except ValueError:
            pass
    return _clip(text, cut), "text"


def _decode_text(data: bytes) -> Optional[str]:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if b"\x00" in data[:2048]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        sample = data[:4096]
        if sum(1 for b in sample if b < 9 or 13 < b < 32) > len(sample) * 0.05:
            return None
        return data.decode("latin-1")


def _clip(text: str, limit: Optional[int]) -> str:
    if limit is None or len(text) <= limit:
        return text
    return text[:limit] + f"\n... truncated at {limit} characters (use --full or --save for the whole file)\n"


# ---------------------------------------------------------------- search

_SKIP_BINARY = re.compile(r"\.(png|jpe?g|gif|webp|heic|ico|icns|car|mp3|mp4|m4a|mov|wav|caf|ttf|otf|woff2?|nib|storyboardc|mom|momd)$", re.I)
MAX_SEARCH_BYTES = 200 * 1024 * 1024


def compile_term(term: str, *, regex: bool = False, case: bool = False) -> re.Pattern:
    flags = 0 if case else re.I
    return re.compile(term if regex else re.escape(term), flags)


def search_file(path: str, rel: str, rx: re.Pattern, *, term: str, regex: bool, case: bool,
                context: int = 0, max_hits: int = 50) -> List[Tuple[str, str]]:
    """-> [(location, text)]. Decoded text (plist, compiled XML, JSON, source) is searched line by line;
    other binaries are searched as raw ASCII and UTF-16 strings, reported by byte offset."""
    if _size(path) > MAX_SEARCH_BYTES:
        return []
    text, how = render(path, rel, full=True)
    hits: List[Tuple[str, str]] = []
    if not how.startswith("binary"):
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if rx.search(line):
                lo, hi = max(0, i - context), min(len(lines), i + context + 1)
                snippet = "\n".join(l[:300] for l in lines[lo:hi]) if context else line.strip()[:300]
                hits.append((f"{i + 1}", snippet))
                if len(hits) >= max_hits:
                    break
        return hits
    if _SKIP_BINARY.search(rel):
        return []
    with open(path, "rb") as fh:
        data = fh.read()
    pats = [re.compile(rx.pattern.encode("utf-8"), rx.flags & re.I)]
    if not regex:
        pats.append(re.compile(re.escape(term.encode("utf-16-le")), re.I if not case else 0))
    seen = set()
    for bp in pats:
        for m in bp.finditer(data):
            if m.start() in seen:
                continue
            seen.add(m.start())
            utf16 = bp is not pats[0]
            lo, hi = max(0, m.start() - 40 * (2 if utf16 else 1)), m.end() + 40 * (2 if utf16 else 1)
            chunk = data[lo:hi]
            if utf16:
                chunk = chunk.replace(b"\x00", b"")
            snippet = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            hits.append((f"0x{m.start():x}", snippet))
            if len(hits) >= max_hits:
                return hits
    return sorted(hits, key=lambda h: int(h[0], 16))
