"""Audit an app's pulled data container for insecure local storage.

Everything in a data container is attacker-influenced input (the app, a webpage in its
WebView or a server can all write there), so this module reads it defensively:
  * SQLite is opened read-only/immutable with an authorizer that only permits SELECTs
  * XML containing a DOCTYPE/ENTITY is rejected rather than parsed
  * per-file and total size caps; symlinks are never followed
  * found values are shown in full by default (reports are sensitive); pass reveal=False / --redact to mask them
"""
import json
import os
import plistlib
import re
import sqlite3
from collections import Counter
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import engine

MAX_FILE = 8 << 20
MAX_TOTAL = 400 << 20
SQLITE_MAGIC = b"SQLite format 3\x00"

_SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
_PW_WORDS = {"password", "passwd", "pwd", "passcode", "pin"}
_TOKEN_WORDS = {"token", "secret", "credential", "credentials", "otp", "cookie", "bearer", "jwt"}
_COMPACT = ("password", "passwd", "passcode", "accesstoken", "refreshtoken", "idtoken", "authtoken",
            "bearer", "apikey", "secretkey", "privatekey", "clientsecret", "sessiontoken", "sessionid",
            "accesskey", "jwt")
_BOOL_PREFIX = ("is", "has", "should", "enable", "disable", "show", "can", "did", "was")


# ----------------------------------------------------------------- key / value logic

def _words(key: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


def sensitive_key(key: str) -> Optional[str]:
    """Return 'password' / 'token' if the key name suggests a credential, else None."""
    words = _words(str(key))
    if not words:
        return None
    if words[0] in _BOOL_PREFIX and len(words) > 1:
        return None
    if "__" in str(key) or "phenotype" in "".join(words) or str(key).startswith("ph_"):
        return None          # remote-config / feature-flag namespaces (Google "phenotype", `Area__flag_name`), not credentials
    if set(words) & {"count", "enabled", "expires", "expiry", "expiration", "timestamp", "hint", "label",
                     "policy", "length", "type", "url", "uri"}:
        return None
    norm = "".join(words)
    if set(words) & _PW_WORDS or any(c in norm for c in ("password", "passwd", "passcode")):
        return "password"
    if set(words) & _TOKEN_WORDS or any(c in norm for c in _COMPACT):
        return "token"
    return None


_AUTH_WORDS = ("token", "auth", "login", "access", "refresh", "jwt", "cookie", "secret", "password", "bearer")


def is_session_id_key(key: str) -> bool:
    """`session_id`-style keys written by analytics SDKs (Umeng, Facebook, Clarity...). Not credentials
    unless the name also says token/auth/login."""
    norm = "".join(_words(str(key)))
    return "sessionid" in norm and not any(w in norm for w in _AUTH_WORDS)


def classify_value(v: Any) -> Tuple[str, bool]:
    """-> (description, strong). 'strong' means it looks like real credential material."""
    if isinstance(v, (bool, int, float)) or v is None:
        return "scalar", False
    if isinstance(v, (bytes, bytearray)):
        raw = bytes(v)
        try:
            # WebKit localStorage keeps values as UTF-16LE; ASCII text in it has a NUL in every 2nd byte
            if len(raw) >= 2 and len(raw) % 2 == 0 and not any(raw[1::2]):
                v = raw.decode("utf-16-le")
            else:
                v = raw.decode("utf-8")
        except UnicodeDecodeError:
            return f"binary blob, {len(raw)} bytes", len(raw) >= 16
    if isinstance(v, (dict, list)):
        return f"{type(v).__name__} of {len(v)}", False
    s = str(v)
    if not s.strip():
        return "empty", False
    if re.fullmatch(r"eyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]*", s):
        return f"JWT, {len(s)} chars", True
    if re.fullmatch(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", s):
        return "bcrypt hash", False
    if len(s) >= 20 and engine._entropy_candidate(s):
        return f"random token, {len(s)} chars", True
    if len(s) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return f"hex string, {len(s)} chars", True
    if len(s) >= 3:
        return f"string, {len(s)} chars", len(s) >= 6
    return "short string", False


def redact(v: Any, reveal: bool) -> str:
    """The value as text (capped), or a placeholder when masking was requested."""
    if not reveal:
        return "<redacted>"
    if isinstance(v, (bytes, bytearray)):
        raw = bytes(v)
        try:
            v = raw[:400].decode("utf-8")
        except UnicodeDecodeError:
            v = "0x" + raw[:64].hex()
    s = str(v)
    return s if len(s) <= 400 else s[:400] + f"…(+{len(s) - 400} chars)"


# ----------------------------------------------------------------------- walking

def _walk(root: str) -> Iterator[Tuple[str, str]]:
    root = os.path.realpath(root)
    for d, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [x for x in dirs if not os.path.islink(os.path.join(d, x))]
        for fn in sorted(files):
            full = os.path.join(d, fn)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            yield full, os.path.relpath(full, root).replace(os.sep, "/")


def _read(full: str, limit: int = MAX_FILE) -> bytes:
    with open(full, "rb") as fh:
        return fh.read(limit)


def _plist_items(obj: Any, prefix: str = "", depth: int = 0) -> Iterator[Tuple[str, Any]]:
    if depth > 8:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                yield from _plist_items(v, path, depth + 1)
            else:
                yield path, v
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:200]):
            yield from _plist_items(v, f"{prefix}[{i}]", depth + 1)


_XML_ITEM = re.compile(r'<(string|int|long|float|boolean)\s+name="([^"]{1,200})"\s*(?:value="([^"]*)")?\s*/?>([^<]*)')


def _shared_prefs_items(data: bytes) -> Iterator[Tuple[str, Any]]:
    if re.search(rb"<!(DOCTYPE|ENTITY)", data, re.I):
        return
    text = data.decode("utf-8", errors="replace")
    for m in _XML_ITEM.finditer(text):
        kind, name, attr_val, body = m.groups()
        yield name, (attr_val if attr_val is not None else body.strip())


# ---------------------------------------------------------------------- sqlite

def _open_sqlite(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=2)
    conn.execute("PRAGMA trusted_schema=OFF")
    conn.execute("PRAGMA query_only=ON")
    allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}

    def auth(action, arg1=None, *_):
        if action in allowed:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA and str(arg1).lower() == "table_info":   # column names only
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    conn.set_authorizer(auth)
    ops = [0]

    def watchdog():
        ops[0] += 1
        return 1 if ops[0] > 20000 else 0       # abort pathological queries
    conn.set_progress_handler(watchdog, 1000)
    return conn


def _q(ident: str) -> str:
    return '"' + ident.replace('"', '""') + '"'


def _audit_sqlite(path: str, rel: str, add, reveal: bool, meta: Dict[str, Any]):
    with open(path, "rb") as fh:
        head = fh.read(16)
    if head != SQLITE_MAGIC:
        meta.setdefault("encrypted_databases", []).append(rel)
        return
    try:
        conn = _open_sqlite(path)
    except sqlite3.Error:
        return
    hits: List[str] = []
    worst = 0
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 300")]
        meta.setdefault("sqlite_databases", {})[rel] = len(tables)
        low = rel.lower()
        if low.endswith(("cache.db", "cache.db-wal")) or "cfurl_cache_response" in tables:
            try:
                n = conn.execute("SELECT COUNT(*) FROM cfurl_cache_response").fetchone()[0]
            except sqlite3.Error:
                n = "?"
            add("LOW", "HTTP response cache stored on disk (NSURLCache)",
                "Cached API responses persist in the app container in plaintext, including responses to "
                "authenticated requests unless the app opts out per request. Check what the cached "
                "endpoints return and set `Cache-Control: no-store` or a no-cache URLCache for them.",
                evidence=f"{n} cached response(s)", location=rel, confidence="confirmed")
        for t in tables:
            if t == "ItemTable" and "localstorage" in low:                 # WebKit localStorage
                rows = conn.execute('SELECT key, value FROM ItemTable LIMIT 500').fetchall()
                for k, v in rows:
                    cat = sensitive_key(k)
                    desc, strong = classify_value(v)
                    if cat and desc not in ("scalar", "empty"):
                        hits.append(f"localStorage[{k}] = {desc} ({redact(v, reveal)})")
                        worst = max(worst, 2 if strong or cat == "password" else 1)
                continue
            try:
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({_q(t)})")]
            except sqlite3.Error:
                continue
            for c in cols:
                cat = sensitive_key(c)
                if not cat:
                    continue
                try:
                    n = conn.execute(f"SELECT COUNT(*) FROM {_q(t)} WHERE {_q(c)} IS NOT NULL AND {_q(c)} != ''").fetchone()[0]
                    sample = conn.execute(f"SELECT {_q(c)} FROM {_q(t)} WHERE {_q(c)} IS NOT NULL AND {_q(c)} != '' LIMIT 1").fetchone()
                except sqlite3.Error:
                    continue
                if not n:
                    continue
                desc, strong = classify_value(sample[0] if sample else None)
                if desc in ("scalar", "empty", "bcrypt hash"):
                    continue
                hits.append(f"{t}.{c}: {n} row(s), e.g. {desc} ({redact(sample[0], reveal)})")
                worst = max(worst, 3 if cat == "password" and strong else 2 if strong else 1)
    except sqlite3.Error:
        pass
    finally:
        conn.close()
    if hits:
        add(["INFO", "LOW", "MEDIUM", "HIGH"][worst], "Credential-like data in an unencrypted SQLite database",
            "The database file is plain SQLite (no SQLCipher), so anyone who can read the app container "
            "(jailbreak, rooted device, backup, forensic image) can read these columns. Prefer the Keychain / "
            "Android Keystore for credentials, or encrypt the database.",
            evidence="; ".join(hits[:12]), location=rel, confidence="heuristic")


# ------------------------------------------------------------------------ audit

# kSecAttrAccessible, as stored in the keychain's `pdmn` column.
KEYCHAIN_ACCESS = {
    "ak": "kSecAttrAccessibleWhenUnlocked",
    "ck": "kSecAttrAccessibleAfterFirstUnlock",
    "dk": "kSecAttrAccessibleAlways",
    "aku": "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    "cku": "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    "dku": "kSecAttrAccessibleAlwaysThisDeviceOnly",
    "akpu": "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
}


def keychain_access_name(code: str) -> str:
    return KEYCHAIN_ACCESS.get((code or "").strip(), f"unknown ({code})" if code else "unknown")


def keychain_short_name(code: str) -> str:
    """'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly' -> 'AfterFirstUnlockThisDeviceOnly'."""
    return keychain_access_name(code).replace("kSecAttrAccessible", "")


def keychain_item_label(it: Dict[str, Any]) -> str:
    name = it.get("service") or it.get("label") or "(no service)"
    return f"{name} / {it['account']}" if it.get("account") else name


def keychain_lines(kc: Optional[Dict[str, Any]], color=None, value_width: int = 70) -> List[str]:
    """Terminal table of the app's keychain items: one aligned row per item, weakest accessibility first.
    color(text, kind) is optional (cli passes its Term.c); the table is plain text without it."""
    items = (kc or {}).get("items") or []
    if not items:
        return []
    c = color or (lambda text, _kind: text)
    weak = lambda it: it.get("accessible") in ("dk", "dku")
    rows = sorted(items, key=lambda it: (not weak(it), keychain_short_name(it.get("accessible", "")), keychain_item_label(it)))
    groups = sorted({it.get("group", "") for it in rows if it.get("group")})
    have_values = any("value" in it for it in rows)
    w_acc = max(len(keychain_short_name(it.get("accessible", ""))) for it in rows)
    w_cls = max(len(it.get("class", "")) for it in rows)
    head = f"Keychain: {len(rows)} item(s)" + (f" in {groups[0]}" if len(groups) == 1 else "")
    note = ("values decrypted on the device" if have_values else
            "values not read (frida-server missing, or --no-keychain-values)")
    out = [c(head, "id") + c(f"   {note}", "dim")]
    for it in rows:
        acc = keychain_short_name(it.get("accessible", "")).ljust(w_acc)
        acc = c(acc, "MEDIUM") if weak(it) else acc
        line = f"  {acc}  {it.get('class', '').ljust(w_cls)}  {keychain_item_label(it)}"
        if len(groups) > 1 and it.get("group"):
            line += c(f"   [{it['group']}]", "dim")
        out.append(line)
        if "value" in it:
            v = it["value"]
            shown = c("(not readable)", "dim") if v is None else (v if len(v) <= value_width else v[:value_width] + "...")
            out.append("      " + c("value", "dim") + "  " + shown)
    return out


_KC_LOCKED, _KC_NO_ENTITLEMENT = -25308, -34018


def merge_keychain_values(kc: Dict[str, Any], read: Dict[str, Any]) -> Dict[str, Any]:
    """Add values read on the device (runtime.read_keychain_values) to the metadata items.
    Items are matched on class + service + account; ones only the device returned are appended."""
    items = kc.setdefault("items", [])
    index = {(i.get("class"), i.get("service", ""), i.get("account", "")): i for i in items}
    for r in read.get("items", []):
        it = index.get((r.get("class"), r.get("service", ""), r.get("account", "")))
        if it is None:
            it = {k: r.get(k, "") for k in ("class", "service", "account", "label", "group", "accessible")}
            items.append(it)
            index[(it["class"], it["service"], it["account"])] = it
        it["value"] = r.get("value")
        it["value_kind"] = r.get("kind")
        it["value_length"] = r.get("length")
    for it in items:                                    # metadata rows the app could not read
        it.setdefault("value", None)
    locked = [c for c, st in (read.get("status") or {}).items() if st == _KC_LOCKED]
    kc["values_read"] = True
    kc["values_note"] = ("read on the device by the app itself; " + ("unlock the phone and re-run to read: "
                         + ", ".join(locked) if locked else "items outside the app's own access groups are not returned"))
    kc["note"] = "values read with Frida inside the app"
    return kc


def mask_keychain(kc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Copy of the keychain data with each value replaced by its length (for --redact and reports)."""
    if not kc:
        return kc
    out = dict(kc)
    out["items"] = [dict(i, value=(None if i.get("value") is None else f"<{len(i['value'])} chars hidden>"))
                    if "value" in i else dict(i) for i in kc.get("items", [])]
    return out


def _values_in_plaintext(root: str, kc: Dict[str, Any]) -> Dict[str, List[str]]:
    """item label -> container files that contain that item's secret value verbatim."""
    needles = {}
    for it in kc.get("items", []):
        v = it.get("value")
        if isinstance(v, str) and len(v) >= 8 and it.get("value_kind") == "text":
            needles[keychain_item_label(it)] = (v.encode("utf-8"), v.encode("utf-16-le"))
    hits: Dict[str, List[str]] = {}
    if not needles:
        return hits
    for full, rel in _walk(root):
        try:
            if os.path.getsize(full) > 16 << 20:
                continue
            data = open(full, "rb").read()
        except OSError:
            continue
        for label, pats in needles.items():
            if any(p in data for p in pats):
                hits.setdefault(label, []).append(rel)
    return hits


def _keychain_findings(kc: Dict[str, Any], add) -> None:
    items = kc.get("items") or []
    if not items:
        add("INFO", "No keychain items found for this app",
            "The keychain database has no items whose access group matches this bundle id.",
            confidence="confirmed")
        return
    by: Dict[str, List[Dict[str, Any]]] = {}
    for it in items:
        by.setdefault(it.get("accessible", ""), []).append(it)

    def ev(group):
        return "; ".join(f"[{i['class']}] {i.get('service') or i.get('label') or '?'}"
                         f"{' / ' + i['account'] if i.get('account') else ''}" for i in group[:25]) + \
            (f"; ... +{len(group) - 25} more" if len(group) > 25 else "")

    for code, group in sorted(by.items()):
        name = keychain_access_name(code)
        if code in ("dk", "dku"):
            add("MEDIUM", f"Keychain items readable while the device is locked ({name})",
                f"{len(group)} item(s) use {name}: they can be read at any time, even before the first unlock "
                "after boot. This class is deprecated; use WhenUnlocked (or WhenPasscodeSet) for credentials.",
                evidence=ev(group), location="keychain: " + ", ".join(keychain_item_label(i) for i in group[:3])
                + (f" (+{len(group) - 3} more)" if len(group) > 3 else ""), confidence="confirmed")
        else:
            add("INFO", f"Keychain items: {len(group)} with {name}",
                "Accessibility class of keychain items belonging to this app. "
                + ("ThisDeviceOnly items are excluded from backups and device migration. " if code.endswith("u") else "")
                + ("AfterFirstUnlock items stay readable on a locked device until the next reboot." if code in ("ck", "cku") else ""),
                evidence=ev(group), location="keychain-2.db", confidence="confirmed")


def audit_dir(root: str, platform: str = "ios", *, reveal: bool = True,
              manifest: Optional[Dict[str, Any]] = None,
              keychain: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Audit an extracted data container. Returns a scan-style result dict."""
    findings: List[Dict[str, Any]] = []
    meta: Dict[str, Any] = {"platform": platform, "root": os.path.abspath(root)}

    def add(sev, title, detail, evidence=None, location=None, confidence="heuristic"):
        findings.append({"severity": sev, "title": title, "detail": detail, "evidence": evidence,
                         "location": location, "confidence": confidence})

    types: Counter = Counter()
    sizes: List[Tuple[int, str]] = []
    total = 0
    modes = (manifest or {}).get("modes", {})
    world: List[str] = []
    cred_files: Dict[str, List[Tuple[str, str, int]]] = {}
    secret_hits: List[Tuple[str, str, str, str]] = []
    n_files = 0

    for full, rel in _walk(root):
        n_files += 1
        try:
            size = os.path.getsize(full)
        except OSError:
            continue
        total += size
        sizes.append((size, rel))
        low = rel.lower()
        ext = os.path.splitext(low)[1]

        mode = modes.get(rel)
        if platform == "android" and isinstance(mode, int) and mode & 0o006 and not rel.startswith(("cache/", "code_cache/")):
            world.append(f"{rel} ({oct(mode & 0o777)})")

        if size > MAX_FILE or total > MAX_TOTAL:
            continue
        data = None

        # --- structured stores
        try:
            if ext == ".plist":
                types["plist"] += 1
                obj = plistlib.loads(_read(full))
                for k, v in _plist_items(obj):
                    leaf = k.rsplit(".", 1)[-1]
                    cat = sensitive_key(leaf)
                    if cat:
                        desc, strong = classify_value(v)
                        if desc not in ("scalar", "empty", "bcrypt hash"):
                            cred_files.setdefault(rel, []).append((f"{k} = {desc} ({redact(v, reveal)})", cat, 2 if strong and not is_session_id_key(k) else 1))
            elif low.endswith(".xml") and "shared_prefs" in low:
                types["shared_prefs"] += 1
                for k, v in _shared_prefs_items(_read(full)):
                    cat = sensitive_key(k)
                    if cat:
                        desc, strong = classify_value(v)
                        if desc not in ("scalar", "empty", "bcrypt hash"):
                            cred_files.setdefault(rel, []).append((f"{k} = {desc} ({redact(v, reveal)})", cat, 2 if strong and not is_session_id_key(k) else 1))
            elif ext in (".db", ".sqlite", ".sqlite3", ".db3", ".sql", ".localstorage") or "cache.db" in low:
                types["sqlite"] += 1
                _audit_sqlite(full, rel, add, reveal, meta)
            elif ext == ".json":
                types["json"] += 1
                obj = json.loads(_read(full).decode("utf-8", errors="replace"))
                for k, v in _plist_items(obj):
                    leaf = re.sub(r"\[\d+\]", "", k).rsplit(".", 1)[-1]
                    cat = sensitive_key(leaf)
                    if cat:
                        desc, strong = classify_value(v)
                        if desc not in ("scalar", "empty", "bcrypt hash"):
                            cred_files.setdefault(rel, []).append((f"{k} = {desc} ({redact(v, reveal)})", cat, 2 if strong and not is_session_id_key(k) else 1))
        except Exception:
            pass

        # --- raw secret/credential patterns in any text-ish file
        if ext in (".json", ".txt", ".log", ".xml", ".plist", ".js", ".html", ".cfg", ".conf", ".ini", ".env", "") or "log" in low:
            data = _read(full)
            if "\x00" not in data[:512].decode("latin-1"):
                for name, pattern in engine.SECRET_PATTERNS:
                    for m in pattern.finditer(data):
                        v = engine._classify_secret(name, m.group(0), data, m.start())
                        if v and v[0] in ("HIGH", "MEDIUM"):
                            secret_hits.append((rel, v[1], v[0], m.group(0).decode('utf-8', 'replace')))
                am = re.search(rb"(?i)authorization:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}", data)
                if am:
                    add("MEDIUM", "Authorization header written to a file",
                        "A request header with credentials was persisted (often a debug/network log). Remove "
                        "request logging from release builds and redact Authorization/Cookie headers.",
                        evidence=redact(am.group(0), reveal), location=rel, confidence="confirmed")
                pm = re.search(rb"(?i)(password|passwd|pwd)\s*[=:]\s*\S{3,}", data) if "log" in low else None
                if pm:
                    add("HIGH", "Password-like value in a log file",
                        "A log line contains `password=` followed by a value. Credentials should never be logged.",
                        evidence=redact(pm.group(0), reveal), location=rel, confidence="heuristic")

        # --- file-type observations
        if low.endswith(".binarycookies") or low.endswith("cookies.sqlite") or low.endswith("/cookies"):
            types["cookies"] += 1
            raw = _read(full)
            names = sorted({m.decode() for m in re.findall(rb"[A-Za-z][A-Za-z0-9_.-]{2,40}", raw)
                            if sensitive_key(m.decode(errors="ignore")) or m.lower() in (b"sessionid", b"sid", b"jsessionid", b"phpsessid")})
            add("LOW" if names else "INFO", "Persistent cookie store present",
                "Cookies are stored unencrypted in the container. Session cookies that persist across app "
                "launches are equivalent to a stored login." + (" Session-like cookie names were found." if names else ""),
                evidence=", ".join(names[:8]) or None, location=rel, confidence="heuristic")
        if platform == "ios" and re.search(r"(splashboard|snapshots?)/.*\.(ktx|png|jpg|jpeg)$", low):
            types["snapshots"] += 1
    # ---- aggregate findings

    for rel, items in cred_files.items():
        worst = 0
        for _d, cat, strong in items:
            worst = max(worst, 3 if cat == "password" and strong == 2 else 2 if strong == 2 else 1)
        exposed = platform == "ios" and rel.startswith("Documents/")
        if exposed:
            worst = min(3, worst + 1)
        add(["INFO", "LOW", "MEDIUM", "HIGH"][worst], "Credential-like values stored in plaintext configuration",
            "These keys look like passwords, tokens or secrets and are stored in a plain file that anyone with "
            "access to the container can read." +
            (" It sits in Documents/, which is exposed through Files / iTunes file sharing when enabled." if exposed else "") +
            " Use the Keychain (iOS) or Keystore-backed EncryptedSharedPreferences (Android) instead.",
            evidence="; ".join(d for d, _c, _s in items[:12]), location=rel, confidence="heuristic")

    by_title: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
    for rel, title, sev, token in secret_hits:
        if rel in cred_files:          # already reported key-by-key for this file
            continue
        by_title.setdefault((title, sev), []).append((rel, token))
    for (title, sev), hits in by_title.items():
        uniq = sorted(set(hits))
        add(sev, f"{title} found in app data", "A credential-shaped string was written to the app's storage.",
            evidence="; ".join(f"{r}: {redact(t, reveal)}" for r, t in uniq[:6]), location=uniq[0][0], confidence="heuristic")

    if world:
        add("MEDIUM", f"{len(world)} world-readable/writable file(s) in the app's private directory",
            "Files in an app's private directory should not grant access to 'other'. On modern Android the "
            "sandbox still blocks other apps, but on older devices or shared UIDs this exposes the data.",
            evidence="; ".join(world[:10]), confidence="confirmed")
    snaps = types.get("snapshots", 0)
    if snaps:
        add("LOW", f"{snaps} app-switcher snapshot(s) stored",
            "iOS saves screenshots of the app's UI when it is backgrounded. If sensitive screens (balances, "
            "documents, OTPs) are visible at that moment they are stored in the container. Cover the window in "
            "applicationWillResignActive.", confidence="confirmed")
    enc = meta.get("encrypted_databases", [])
    if enc:
        add("INFO", f"{len(enc)} database(s) are not plain SQLite (likely encrypted)",
            "These files have the .db/.sqlite extension but no SQLite header, which is what SQLCipher and "
            "similar encrypted stores look like. This is a positive signal.", evidence=", ".join(enc[:6]),
            confidence="heuristic")

    if keychain is not None:
        meta["keychain"] = keychain if reveal else mask_keychain(keychain)
        _keychain_findings(keychain, add)
        if keychain.get("values_read"):
            for label, files in sorted(_values_in_plaintext(root, keychain).items()):
                add("HIGH", "Keychain secret is also stored in plaintext in the app container",
                    f"The value of keychain item '{label}' appears verbatim in the app's data files, so storing it "
                    "in the keychain adds no protection: anyone who can read the container (jailbreak, backup, "
                    "forensic image) gets it anyway. Remove the plaintext copy.",
                    evidence=f"{label}: " + ", ".join(files[:6]), location=files[0], confidence="confirmed")
    meta.update({"files": n_files, "bytes": total, "by_type": dict(types),
                 "largest": [{"path": r, "bytes": s} for s, r in sorted(sizes, reverse=True)[:8]]})
    findings.sort(key=lambda f: -_SEV[f["severity"]])
    return {"input_file": os.path.abspath(root), "detected_type": f"appdata-{platform}", "meta": meta,
            "findings": findings,
            "summary": {s: sum(1 for f in findings if f["severity"] == s) for s in ("HIGH", "MEDIUM", "LOW", "INFO")}}
