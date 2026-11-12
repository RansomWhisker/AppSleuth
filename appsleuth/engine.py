"""
appsleuth.engine (formerly mobile_scanner.py) — static security triage for Android (APK / APKS-XAPK / AAB) and iOS (IPA) apps.

WHAT THIS IS
    A single-file, dependency-light static analysis tool. It fully parses DEX
    (class/method-level string cross-references), ELF native libraries (NX/RELRO/
    canary/fortify), the binary AndroidManifest.xml, resources.arsc, Info.plist,
    embedded provisioning profiles, Mach-O load commands and embedded code-signature
    entitlements, and greps the compiled code/binaries for well-known risky patterns
    (cleartext traffic, permissive network security config, exported components,
    task-hijacking/App-Links gaps, WebView JS-bridge risk, weak crypto symbols,
    hardcoded-secret-shaped and high-entropy strings, ATS bypass, Hardened Runtime
    opt-outs, debuggable provisioning, etc), then reports it all with class/method
    or file-level attribution wherever the parser (not just a blob grep) found it.
    It also generates a lightweight SBOM (bundled third-party library versions) and
    supports CI workflows via --fail-on, --baseline, --diff-against, and batch mode.

IPA-SPECIFIC CHECKS (added)
    - FairPlay state is verified against the bytes (entropy of the encrypted range), for the
      main binary AND every embedded framework/app extension, so a "decrypted" dump that
      silently failed is reported instead of trusted.
    - Capacitor / Cordova apps: capacitor.config.json / config.xml misconfiguration, and the
      bundled web layer (JS/HTML) is scanned for secrets, cleartext/raw-IP endpoints,
      sensitive values in web storage, source maps, and external hosts.
    - Certificate-chain URLs (OCSP/CRL) are no longer reported as cleartext endpoints.

WHAT THIS IS NOT
    - Not a decompiler. It does not disassemble DEX or Mach-O instructions, so it
      cannot trace data flow or confirm a finding is actually reachable/exploitable.
    - Not a dynamic analysis / exploitation tool. It never talks to a network, a
      device, or a running app; it only reads bytes from the file you give it.
    - A replacement for manual review. Every finding below is a *lead*: a place a
      human reviewer should look, not a proven vulnerability. Treat "HIGH" as
      "look at this first", not "confirmed exploitable".

USAGE
    python3 -m appsleuth <path-to-apk-or-apks-or-aab-or-ipa> [-o OUTDIR]
    python3 -m appsleuth <directory> [-o OUTDIR] [--recursive]      # batch mode

    Produces, inside OUTDIR (default: ./scan_<name>):
        report.json   - full machine-readable findings
        report.md     - human-readable summary report
        report.html   - self-contained, styled HTML report (no external assets)

    Exit code is 0 on a successful scan (regardless of how many findings were made),
    2 on a bad invocation (missing file), 1 on an unrecognised/unreadable input, and
    3 only when --fail-on is given and a finding at/above that severity was found.

CI / WORKFLOW OPTIONS
    --fail-on HIGH|MEDIUM|LOW|INFO
        Exit 3 if any (non-suppressed) finding at or above this severity exists.
    --baseline baseline.json
        Suppress findings already recorded in this baseline (see --write-baseline);
        suppressed items are still listed separately in report.json, never silently
        dropped. --fail-on only considers non-suppressed findings.
    --write-baseline out.json
        After scanning, snapshot every current finding's fingerprint to out.json.
    --diff-against OLD_FILE_OR_OLD_REPORT.json
        Compare this scan against an older build (or a previously saved report.json):
        new/removed permissions, exported components, URL schemes, native libraries,
        SBOM version bumps, and new/resolved findings. Writes diff.md/diff.json.

SUPPORTED INPUTS
    .apk            single Android package
    .apks / .xapk   zip container of split APKs (bundletool output / exported bundle)
    .aab            Android App Bundle (protobuf manifest/resources -- see the .aab
                    section below for what is and isn't analyzed for this format)
    .ipa            iOS app archive (zip of Payload/<Name>.app/...)
    a directory     batch mode: scans every recognised file in it (add --recursive
                    to descend into subdirectories), writing one subfolder per file
                    plus a top-level batch_summary.json/.md sorted by severity.

    Type is detected from file contents, not just the extension, so renamed files
    still work.
"""

import argparse
import hashlib
import html
import json
import math
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------
# Findings model
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass
class Finding:
    severity: str          # INFO | LOW | MEDIUM | HIGH
    title: str
    detail: str
    evidence: Optional[str] = None
    location: Optional[str] = None
    confidence: str = "heuristic"   # "heuristic" (string/pattern based) or "confirmed" (parsed structurally)

    def to_dict(self):
        return asdict(self)


class FindingsBag:
    def __init__(self):
        self.items: List[Finding] = []

    def add(self, severity, title, detail, evidence=None, location=None, confidence="heuristic"):
        self.items.append(Finding(severity, title, detail, evidence, location, confidence))

    def extend(self, other: "FindingsBag"):
        self.items.extend(other.items)

    def sorted(self):
        return sorted(self.items, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))


MAX_UNPACKED_BYTES = 6 << 30      # refuse zip bombs
MAX_UNPACKED_FILES = 250_000


class DamagedZip(ValueError, zipfile.BadZipFile):
    pass


def open_zip(path) -> "zipfile.ZipFile":
    """ZipFile that reads what Android / iOS would read: the 'encrypted' flag bit is
    ignored (Android does; obfuscators set it to break unzip tools)."""
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        name = path if isinstance(path, str) else "archive"
        raise DamagedZip(f"'{name}' is a damaged zip archive ({e}); Android and iOS would also refuse "
                         f"to install it. Re-download or re-pull the file.") from None
    for i in z.infolist():
        i.flag_bits &= ~0x1
    return z


_NAME_MAX = 200          # bytes per path component (APFS/ext4 allow 255)
_PATH_MAX = 900          # whole relative path


_WIN = os.name == "nt"
_WIN_BAD = re.compile(r'[<>:"|?*\x00-\x1f]')
_WIN_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}


def _short(component: str) -> str:
    if _WIN:      # names Windows cannot create (':' '?' '*', CON, aux.xml, trailing dot / space)
        component = _WIN_BAD.sub("_", component).rstrip(" .") or "_"
        if component.split(".", 1)[0].lower() in _WIN_RESERVED:
            component = "_" + component
    if len(component.encode("utf-8", "surrogateescape")) <= _NAME_MAX:
        return component
    h = hashlib.sha1(component.encode("utf-8", "surrogateescape")).hexdigest()[:10]
    stem, ext = os.path.splitext(component)
    ext = ext if len(ext) <= 16 else ""
    return stem[:80] + "~" + h + ext


def _safe_extractall(z: "zipfile.ZipFile", dest: str):
    """Extract entry by entry, the way a device installer tolerates archives:
    '..' / absolute paths are confined to dest, the 'encrypted' flag is ignored,
    over-long names are shortened, names that clash on a case-insensitive disk or
    a file-vs-directory conflict are renamed, and a corrupt entry is skipped
    (counted in z.appsleuth_skipped) instead of aborting the whole extraction.
    Size and entry-count limits stop zip bombs."""
    infos = z.infolist()
    if len(infos) > MAX_UNPACKED_FILES:
        raise ValueError(f"archive has {len(infos)} entries (limit {MAX_UNPACKED_FILES})")
    if sum(i.file_size for i in infos) > MAX_UNPACKED_BYTES:
        raise ValueError("archive expands beyond the size limit (possible zip bomb)")
    dest = os.path.realpath(dest)
    os.makedirs(dest, exist_ok=True)
    # Windows without long-path support stops at 260 characters for the whole path
    path_max = max(60, 240 - len(dest)) if _WIN else _PATH_MAX
    files: Dict[str, str] = {}       # casefolded rel path -> actual rel path (files)
    dirs: Dict[str, str] = {}        # casefolded rel path -> actual rel path (directories)
    skipped: List[str] = []
    written = 0

    def place(parts: List[str], is_dir: bool) -> List[str]:
        """Return a rel path (list of components) that conflicts with nothing already placed."""
        out: List[str] = []
        for k, p in enumerate(parts):
            last = k == len(parts) - 1
            want_dir = is_dir or not last
            cand = p
            n = 0
            while True:
                key = "/".join(out + [cand]).casefold()
                if want_dir:
                    if key in dirs:
                        cand = dirs[key].rsplit("/", 1)[-1]          # reuse the existing dir
                        break
                    if key not in files:
                        dirs[key] = "/".join(out + [cand])
                        break
                else:
                    if key not in dirs and (key not in files or files[key] == "/".join(out + [cand])):
                        files[key] = "/".join(out + [cand])
                        break
                n += 1
                stem, ext = os.path.splitext(p)
                cand = f"{stem}~{n}{ext}"
            out.append(cand)
        return out

    for info in infos:
        info.flag_bits &= ~0x1
        raw = info.filename.replace("\\", "/")
        parts = [_short(p) for p in raw.split("/") if p not in ("", ".", "..")]
        parts = [p for p in parts if p]
        if not parts:
            continue
        if len("/".join(parts).encode("utf-8", "surrogateescape")) > path_max:
            stem, ext = os.path.splitext(parts[-1])          # keep the extension: scanners key on it
            parts = ["_long_paths", hashlib.sha1(raw.encode("utf-8", "surrogateescape")).hexdigest()[:12]
                     + "_" + stem[:30] + (ext if len(ext) <= 16 else "")]
        is_dir = raw.endswith("/")
        rel = place(parts, is_dir)
        target = os.path.join(dest, *rel)
        if not os.path.realpath(target).startswith(dest + os.sep):
            skipped.append(info.filename)
            continue
        try:
            if is_dir:
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as src, open(target, "wb") as dst:
                while True:
                    buf = src.read(1 << 20)
                    if not buf:
                        break
                    written += len(buf)
                    if written > MAX_UNPACKED_BYTES:
                        raise ValueError("archive expands beyond the size limit (possible zip bomb)")
                    dst.write(buf)
        except ValueError:
            raise
        except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError,
                OSError, EOFError, zlib.error, struct.error) as e:
            skipped.append(f"{info.filename} ({type(e).__name__})")
            try:
                if os.path.isfile(target):
                    os.remove(target)
            except OSError:
                pass
    try:
        z.appsleuth_skipped = skipped
    except Exception:
        pass
    if skipped:
        print(f"warning: skipped {len(skipped)} unreadable archive entr{'y' if len(skipped) == 1 else 'ies'} "
              f"(e.g. {skipped[0]})", file=sys.stderr)


def run(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return -1, "", str(e)


# --------------------------------------------------------------------------
# Binary AndroidManifest.xml (AXML) parser
#
# Format reference: Android's ResChunk_header / ResStringPool_header /
# ResXMLTree_node structures. This mirrors what tools like axmlprinter /
# androguard's AXMLPrinter do, trimmed to what a manifest needs.
# --------------------------------------------------------------------------

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180


def _u16(d, o):
    return struct.unpack_from('<H', d, o)[0]


def _u32(d, o):
    return struct.unpack_from('<I', d, o)[0]


def _i32(d, o):
    return struct.unpack_from('<i', d, o)[0]


def _parse_string_pool(data: bytes, chunk_start: int):
    header_size = _u16(data, chunk_start + 2)
    chunk_size = _u32(data, chunk_start + 4)
    string_count = _u32(data, chunk_start + 8)
    flags = _u32(data, chunk_start + 16)
    strings_start = _u32(data, chunk_start + 20)
    is_utf8 = bool(flags & (1 << 8))

    off_base = chunk_start + header_size
    offsets = [_u32(data, off_base + i * 4) for i in range(string_count)]

    strings = []
    data_base = chunk_start + strings_start
    for off in offsets:
        p = data_base + off
        try:
            if is_utf8:
                b0 = data[p]
                p += 2 if (b0 & 0x80) else 1
                b1 = data[p]
                if b1 & 0x80:
                    strlen = ((b1 & 0x7f) << 8) | data[p + 1]
                    p += 2
                else:
                    strlen = b1
                    p += 1
                raw = data[p:p + strlen]
                strings.append(raw.decode('utf-8', errors='replace'))
            else:
                b0 = _u16(data, p)
                if b0 & 0x8000:
                    strlen = ((b0 & 0x7fff) << 16) | _u16(data, p + 2)
                    p += 4
                else:
                    strlen = b0
                    p += 2
                raw = data[p:p + strlen * 2]
                strings.append(raw.decode('utf-16-le', errors='replace'))
        except Exception:
            strings.append(None)
    return strings, chunk_size


def _get_string(strings, idx):
    if idx is None or idx < 0 or idx >= len(strings):
        return None
    return strings[idx]


def parse_axml(data: bytes):
    """Parse a binary XML (AXML) blob into (strings, events).
    events is a list of ('start', tag, attrs, line) / ('end', tag) tuples,
    where attrs is a list of (ns_idx, name_idx, raw_value_idx, data_type, data)."""
    if _u16(data, 0) != RES_XML_TYPE:
        raise ValueError("Not a binary XML chunk (unexpected magic)")
    total_size = _u32(data, 4)
    pos = 8
    strings: List[Optional[str]] = []
    events = []
    while pos < len(data) and pos < total_size:
        chunk_type = _u16(data, pos)
        header_size = _u16(data, pos + 2)
        chunk_size = _u32(data, pos + 4)
        if chunk_size == 0:
            break
        if chunk_type == RES_STRING_POOL_TYPE:
            strings, _ = _parse_string_pool(data, pos)
        elif chunk_type == RES_XML_START_ELEMENT_TYPE:
            line_number = _u32(data, pos + 8)
            sub = pos + header_size
            name_idx = _i32(data, sub + 4)
            attr_start = _u16(data, sub + 8)
            attr_size = _u16(data, sub + 10)
            attr_count = _u16(data, sub + 12)
            attrs = []
            a = sub + attr_start
            for _ in range(attr_count):
                a_ns = _i32(data, a)
                a_name = _i32(data, a + 4)
                a_rawvalue = _i32(data, a + 8)
                a_datatype = data[a + 15]
                a_data = _u32(data, a + 16)
                attrs.append((a_ns, a_name, a_rawvalue, a_datatype, a_data))
                a += attr_size
            events.append(('start', _get_string(strings, name_idx), attrs, line_number))
        elif chunk_type == RES_XML_END_ELEMENT_TYPE:
            sub = pos + header_size
            name_idx = _i32(data, sub + 4)
            events.append(('end', _get_string(strings, name_idx)))
        pos += chunk_size
    return strings, events


def _attr_value(strings, a_rawvalue, a_datatype, a_data):
    """Resolve one manifest attribute to a Python str/bool/int-ish string."""
    if a_datatype == 0x03:  # TYPE_STRING
        return _get_string(strings, a_rawvalue if a_rawvalue >= 0 else a_data)
    if a_datatype == 0x12:  # TYPE_INT_BOOLEAN
        return 'true' if a_data != 0 else 'false'
    if a_datatype == 0x10:  # TYPE_INT_DEC
        return str(a_data)
    if a_datatype == 0x01:  # TYPE_REFERENCE
        return '@0x%08x' % a_data
    if a_datatype == 0x11:  # TYPE_INT_HEX
        return '0x%08x' % a_data
    if a_rawvalue is not None and a_rawvalue >= 0:
        v = _get_string(strings, a_rawvalue)
        if v is not None:
            return v
    return '0x%x (type 0x%02x)' % (a_data, a_datatype)


class ManifestNode:
    """A minimal DOM: enough to walk <manifest>/<application>/components etc."""
    __slots__ = ("tag", "attrs", "children", "parent")

    def __init__(self, tag, attrs, parent=None):
        self.tag = tag
        self.attrs = attrs   # dict[str,str]
        self.children: List["ManifestNode"] = []
        self.parent = parent

    def find_all(self, tag):
        out = []
        if self.tag == tag:
            out.append(self)
        for c in self.children:
            out.extend(c.find_all(tag))
        return out

    def get(self, key, default=None):
        return self.attrs.get(key, default)


def build_manifest_tree(data: bytes) -> ManifestNode:
    strings, events = parse_axml(data)
    root = None
    stack = []
    for ev in events:
        if ev[0] == 'start':
            _, tag, raw_attrs, _line = ev
            attrs = {}
            for (a_ns, a_name, a_rawvalue, a_datatype, a_data) in raw_attrs:
                name = _get_string(strings, a_name)
                if name is None:
                    continue
                attrs[name] = _attr_value(strings, a_rawvalue, a_datatype, a_data)
            node = ManifestNode(tag, attrs, parent=stack[-1] if stack else None)
            if stack:
                stack[-1].children.append(node)
            else:
                root = node
            stack.append(node)
        elif ev[0] == 'end':
            if stack:
                stack.pop()
    return root


# --------------------------------------------------------------------------
# APK v2/v3 Signing Block -> signer certificate extraction
# --------------------------------------------------------------------------

def _read_len_prefixed_list(buf: bytes):
    """buf starts with a 4-byte length of the whole list, followed by that many
    bytes which is itself a sequence of 4-byte-length-prefixed elements."""
    total_len = struct.unpack_from('<I', buf, 0)[0]
    body = buf[4:4 + total_len]
    items = []
    p = 0
    while p < len(body):
        ilen = struct.unpack_from('<I', body, p)[0]
        items.append(body[p + 4:p + 4 + ilen])
        p += 4 + ilen
    return items, 4 + total_len


def extract_apk_signing_certs(apk_bytes: bytes) -> Dict[str, Any]:
    """Locate the APK Signing Block (v2/v3) and pull out signer certificates
    (as DER bytes) plus which scheme IDs are present. Returns a dict:
      {"schemes": [...], "certs_der": [bytes, ...], "v1_present": bool}
    v1 (JAR/META-INF *.RSA|*.DSA|*.EC signing) is detected separately by the
    caller (it just checks for those files in the zip).
    """
    out = {"schemes": [], "certs_der": [], "error": None}
    magic = b'APK Sig Block 42'
    magic_offset = apk_bytes.rfind(magic)
    if magic_offset == -1:
        out["error"] = "No APK Signing Block v2/v3 found"
        return out
    E = magic_offset + 16
    second_size_offset = magic_offset - 8
    try:
        V = struct.unpack_from('<Q', apk_bytes, second_size_offset)[0]
        L = V + 8
        S = E - L
        pos = S + 8
        end = second_size_offset
        pairs = {}
        while pos < end:
            pair_len = struct.unpack_from('<Q', apk_bytes, pos)[0]
            pid = struct.unpack_from('<I', apk_bytes, pos + 8)[0]
            val = apk_bytes[pos + 12:pos + 8 + pair_len]
            pairs[pid] = val
            pos += 8 + pair_len
    except Exception as e:
        out["error"] = f"Malformed signing block: {e}"
        return out

    SCHEME_IDS = {0x7109871a: "v2", 0xf05368c0: "v3", 0x1b93ad61: "v3.1"}
    for pid, val in pairs.items():
        scheme = SCHEME_IDS.get(pid)
        if not scheme:
            continue
        out["schemes"].append(scheme)
        try:
            signers, _ = _read_len_prefixed_list(val)
            for signer in signers:
                sp = 0
                signed_data_len = struct.unpack_from('<I', signer, sp)[0]
                signed_data = signer[sp + 4:sp + 4 + signed_data_len]
                digests, c1 = _read_len_prefixed_list(signed_data)
                certs, _c2 = _read_len_prefixed_list(signed_data[c1:])
                out["certs_der"].extend(certs)
        except Exception as e:
            out["error"] = f"Could not parse signer(s) for {scheme}: {e}"
    return out


def describe_cert_with_openssl(der_bytes: bytes) -> Dict[str, str]:
    """Use the system openssl binary to pull subject/issuer/validity/fingerprint
    out of a DER certificate. Falls back gracefully if openssl is unavailable."""
    info = {}
    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
        f.write(der_bytes)
        path = f.name
    try:
        rc, out, _err = run(["openssl", "x509", "-inform", "der", "-in", path,
                              "-noout", "-subject", "-issuer", "-dates", "-serial"])
        if rc == 0:
            for line in out.splitlines():
                if '=' in line:
                    k, _, v = line.partition('=')
                    info[k.strip()] = v.strip()
        rc, out, _err = run(["openssl", "x509", "-inform", "der", "-in", path,
                              "-noout", "-fingerprint", "-sha256"])
        if rc == 0 and 'Fingerprint=' in out:
            info['sha256_fingerprint'] = out.strip().split('Fingerprint=')[-1]
    finally:
        os.unlink(path)
    return info


# --------------------------------------------------------------------------
# Real DEX parser
#
# Enough of the DEX file format (header, string/type/method IDs, class_defs,
# class_data, code_items) to walk every method's bytecode and find which
# class/method each string constant (const-string / const-string/jumbo) is
# actually referenced from. This turns "somewhere in classes.dex" into
# "Lcom/foo/Bar;->someMethod()".
#
# Simplifications (documented, not silent):
#   - String data is decoded as UTF-8 with errors='replace' rather than fully
#     implementing DEX's "modified UTF-8" (MUTF-8/CESU-8) edge cases (embedded
#     NUL as 0xC0 0x80, surrogate-pair encoding). This only affects the exact
#     rendering of unusual characters, not ASCII/URL/secret-shaped content,
#     which is what the pattern scanners care about.
#   - We only track which *method* references a string via const-string(/jumbo);
#     we don't disassemble semantics beyond that (no data-flow, no call-graph).
# --------------------------------------------------------------------------

# Opcode -> instruction length in 16-bit code units, indexed 0x00-0xff.
# Built from the standard Dalvik bytecode format table (unchanged since the
# original Dalvik spec; ART still uses classes.dex in this exact format on
# disk inside an APK -- "quickened" opcodes only ever appear in on-device
# ODEX/VDEX, never in the classes.dex shipped inside an APK/AAB).
def _build_dex_opcode_lengths():
    L = [1] * 256

    def setr(lo, hi, val):
        for o in range(lo, hi + 1):
            L[o] = val

    L[0x00] = 1  # nop (special-cased for payload pseudo-instructions separately)
    L[0x01], L[0x04], L[0x07] = 1, 1, 1        # move / move-wide / move-object (12x)
    L[0x02], L[0x05], L[0x08] = 2, 2, 2        # */from16 (22x)
    L[0x03], L[0x06], L[0x09] = 3, 3, 3        # */16 (32x)
    setr(0x0a, 0x0d, 1)                        # move-result*, move-exception (11x)
    L[0x0e] = 1                                # return-void (10x)
    setr(0x0f, 0x11, 1)                        # return* (11x)
    L[0x12] = 1                                # const/4 (11n)
    L[0x13] = 2                                # const/16 (21s)
    L[0x14] = 3                                # const (31i)
    L[0x15] = 2                                # const/high16 (21h)
    L[0x16] = 2                                # const-wide/16 (21s)
    L[0x17] = 3                                # const-wide/32 (31i)
    L[0x18] = 5                                # const-wide (51l)
    L[0x19] = 2                                # const-wide/high16 (21h)
    L[0x1a] = 2                                # const-string (21c)         *** tracked
    L[0x1b] = 3                                # const-string/jumbo (31c)   *** tracked
    L[0x1c] = 2                                # const-class (21c)
    setr(0x1d, 0x1e, 1)                        # monitor-enter/exit (11x)
    L[0x1f] = 2                                # check-cast (21c)
    L[0x20] = 2                                # instance-of (22c)
    L[0x21] = 1                                # array-length (12x)
    L[0x22] = 2                                # new-instance (21c)
    L[0x23] = 2                                # new-array (22c)
    L[0x24] = 3                                # filled-new-array (35c)
    L[0x25] = 3                                # filled-new-array/range (3rc)
    L[0x26] = 3                                # fill-array-data (31t)
    L[0x27] = 1                                # throw (11x)
    L[0x28] = 1                                # goto (10t)
    L[0x29] = 2                                # goto/16 (20t)
    L[0x2a] = 3                                # goto/32 (30t)
    L[0x2b] = 3                                # packed-switch (31t)
    L[0x2c] = 3                                # sparse-switch (31t)
    setr(0x2d, 0x31, 2)                        # cmpkind (23x)
    setr(0x32, 0x37, 2)                        # if-test (22t)
    setr(0x38, 0x3d, 2)                        # if-testz (21t)
    setr(0x3e, 0x43, 1)                        # unused
    setr(0x44, 0x51, 2)                        # arrayop (23x)
    setr(0x52, 0x5f, 2)                        # instanceop (22c)
    setr(0x60, 0x6d, 2)                        # staticop (21c)
    setr(0x6e, 0x72, 3)                        # invoke-kind (35c)
    L[0x73] = 1                                # unused
    setr(0x74, 0x78, 3)                        # invoke-kind/range (3rc)
    setr(0x79, 0x7a, 1)                        # unused
    setr(0x7b, 0x8f, 1)                        # unop (12x)
    setr(0x90, 0xaf, 2)                        # binop (23x)
    setr(0xb0, 0xcf, 1)                        # binop/2addr (12x)
    setr(0xd0, 0xd7, 2)                        # binop/lit16 (22s)
    setr(0xd8, 0xe2, 2)                        # binop/lit8 (22b)
    setr(0xe3, 0xf9, 1)                        # unused / quickened (not on-disk in an APK)
    L[0xfa] = 4                                # invoke-polymorphic (45cc)
    L[0xfb] = 3                                # invoke-polymorphic/range (4rcc)
    L[0xfc] = 3                                # invoke-custom (35c)
    L[0xfd] = 3                                # invoke-custom/range (3rc)
    L[0xfe] = 2                                # const-method-handle (21c)
    L[0xff] = 2                                # const-method-type (21c)
    return L


DEX_OPCODE_LENGTHS = _build_dex_opcode_lengths()
OP_CONST_STRING = 0x1a
OP_CONST_STRING_JUMBO = 0x1b


def _read_uleb128(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _read_sleb128(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result -= (1 << shift)
            break
    return result, pos


class DexFile:
    """Parses one classes.dex into strings/types/methods/classes, plus a
    string_id -> [owning "LClass;->method" label, ...] cross-reference built
    by walking every method's bytecode for const-string(/jumbo)."""

    def __init__(self, data: bytes, track_refs: bool = False):
        self.data = data
        self.track = track_refs                 # also record who calls which method / uses which type
        self.callees: Dict[int, Set[int]] = {}  # callee method_idx -> {caller method_idx}
        self.type_users: Dict[int, Set[int]] = {}  # type_idx -> {method_idx} (const-class, new-instance, check-cast, ...)
        self.field_ids: List[Tuple[int, int, int]] = []   # (class_idx, type_idx, name_idx), only with track_refs
        self.field_users: Dict[int, Set[int]] = {}      # field_idx -> {method_idx}
        self.defs: List[Tuple[int, int]] = []   # (class type_idx, method_idx) for every method defined in this dex
        self.strings: List[str] = []
        self.type_ids: List[int] = []          # string_id index per type
        self.method_ids: List[Tuple[int, int, int]] = []  # (class_idx, proto_idx, name_idx)
        self.class_names: Dict[int, str] = {}  # type_idx -> descriptor
        self.string_owners: Dict[int, List[str]] = {}  # string_id -> [labels]
        self.classes: List[Dict[str, Any]] = []
        self._parse()

    def type_name(self, type_idx: int) -> str:
        if 0 <= type_idx < len(self.type_ids):
            s = self.strings[self.type_ids[type_idx]]
            return s if s is not None else "?"
        return "?"

    def method_label(self, method_idx: int) -> str:
        if 0 <= method_idx < len(self.method_ids):
            class_idx, _proto_idx, name_idx = self.method_ids[method_idx]
            cname = self.type_name(class_idx)
            mname = self.strings[name_idx] if 0 <= name_idx < len(self.strings) else "?"
            return f"{cname}->{mname}()"
        return "?"

    def _parse(self):
        d = self.data
        if len(d) < 0x70 or d[:4] != b'dex\n':
            raise ValueError("Not a DEX file (bad magic)")
        (string_ids_size, string_ids_off, type_ids_size, type_ids_off,
         proto_ids_size, _proto_ids_off, field_ids_size, field_ids_off,
         method_ids_size, method_ids_off, class_defs_size, class_defs_off,
         _data_size, _data_off) = struct.unpack_from('<14I', d, 0x38)

        # ---- strings ----
        offsets = struct.unpack_from(f'<{string_ids_size}I', d, string_ids_off) if string_ids_size else ()
        strings = []
        for off in offsets:
            try:
                _utf16_len, p = _read_uleb128(d, off)
                end = d.index(b'\x00', p)
                strings.append(d[p:end].decode('utf-8', errors='replace'))
            except Exception:
                strings.append(None)
        self.strings = strings

        # ---- types ----
        if type_ids_size:
            self.type_ids = list(struct.unpack_from(f'<{type_ids_size}I', d, type_ids_off))

        # ---- methods ----
        methods = []
        for i in range(method_ids_size):
            off = method_ids_off + i * 8
            class_idx, proto_idx = struct.unpack_from('<HH', d, off)
            name_idx = struct.unpack_from('<I', d, off + 4)[0]
            methods.append((class_idx, proto_idx, name_idx))
        self.method_ids = methods
        if self.track:
            self.field_ids = [struct.unpack_from('<HHI', d, field_ids_off + i * 8) for i in range(field_ids_size)]

        # ---- class_defs + class_data (direct/virtual methods -> code_item) ----
        for i in range(class_defs_size):
            off = class_defs_off + i * 32
            (class_idx, access_flags, superclass_idx, _interfaces_off,
             source_file_idx, _annotations_off, class_data_off, _static_values_off) = \
                struct.unpack_from('<8I', d, off)
            cname = self.type_name(class_idx)
            class_entry = {"name": cname, "class_idx": class_idx,
                            "superclass": self.type_name(superclass_idx) if superclass_idx != 0xffffffff else None,
                            "access_flags": access_flags,
                            "source_file": (self.strings[source_file_idx]
                                            if source_file_idx != 0xffffffff and 0 <= source_file_idx < len(strings)
                                            else None),
                            "method_count": 0}
            self.classes.append(class_entry)
            if not class_data_off:
                continue
            try:
                self._parse_class_data(class_data_off, class_entry)
            except Exception:
                # Malformed/unexpected class_data for this one class shouldn't
                # abort parsing the rest of the file.
                continue

    def _parse_class_data(self, off: int, class_entry: Dict[str, Any]):
        d = self.data
        static_count, off = _read_uleb128(d, off)
        instance_count, off = _read_uleb128(d, off)
        direct_count, off = _read_uleb128(d, off)
        virtual_count, off = _read_uleb128(d, off)

        # fields: (field_idx_diff, access_flags) -- skip, we don't need field names
        for _ in range(static_count):
            _diff, off = _read_uleb128(d, off)
            _flags, off = _read_uleb128(d, off)
        for _ in range(instance_count):
            _diff, off = _read_uleb128(d, off)
            _flags, off = _read_uleb128(d, off)

        method_count_total = 0
        for section_count in (direct_count, virtual_count):
            prev_idx = 0
            for _ in range(section_count):
                diff, off = _read_uleb128(d, off)
                _access, off = _read_uleb128(d, off)
                code_off, off = _read_uleb128(d, off)
                method_idx = prev_idx + diff
                prev_idx = method_idx
                method_count_total += 1
                if self.track:
                    self.defs.append((class_entry["class_idx"], method_idx))
                if code_off:
                    try:
                        self._walk_code_item(code_off, method_idx)
                    except Exception:
                        continue
        class_entry["method_count"] = method_count_total

    def _walk_code_item(self, off: int, method_idx: int):
        d = self.data
        insns_size = struct.unpack_from('<I', d, off + 12)[0]  # number of 16-bit code units
        insns_start = off + 16
        label = self.method_label(method_idx)
        i = 0
        n = insns_size
        while i < n:
            unit_off = insns_start + i * 2
            unit = struct.unpack_from('<H', d, unit_off)[0]
            low_byte = unit & 0xff

            if low_byte == 0x00 and unit != 0x0000:
                # payload pseudo-instruction: 0x0100 / 0x0200 / 0x0300
                if unit == 0x0100:      # packed-switch-payload
                    size = struct.unpack_from('<H', d, unit_off + 2)[0]
                    i += 4 + 2 * size
                    continue
                elif unit == 0x0200:    # sparse-switch-payload
                    size = struct.unpack_from('<H', d, unit_off + 2)[0]
                    i += 2 + 4 * size
                    continue
                elif unit == 0x0300:    # fill-array-data-payload
                    element_width = struct.unpack_from('<H', d, unit_off + 2)[0]
                    size = struct.unpack_from('<I', d, unit_off + 4)[0]
                    data_units = (size * element_width + 1) // 2
                    i += 4 + data_units
                    continue
                # else: plain nop (0x0000) or an unrecognised 0x00-opcode unit
            length = DEX_OPCODE_LENGTHS[low_byte]

            if low_byte == OP_CONST_STRING:
                str_idx = struct.unpack_from('<H', d, unit_off + 2)[0]
                self.string_owners.setdefault(str_idx, [])
                if label not in self.string_owners[str_idx]:
                    self.string_owners[str_idx].append(label)
            elif low_byte == OP_CONST_STRING_JUMBO:
                str_idx = struct.unpack_from('<I', d, unit_off + 2)[0]
                self.string_owners.setdefault(str_idx, [])
                if label not in self.string_owners[str_idx]:
                    self.string_owners[str_idx].append(label)

            elif self.track:
                if 0x6e <= low_byte <= 0x72 or 0x74 <= low_byte <= 0x78:
                    self.callees.setdefault(struct.unpack_from('<H', d, unit_off + 2)[0], set()).add(method_idx)
                elif 0x52 <= low_byte <= 0x6d:
                    self.field_users.setdefault(struct.unpack_from('<H', d, unit_off + 2)[0], set()).add(method_idx)
                elif low_byte in (0x1c, 0x1f, 0x20, 0x22, 0x23):
                    self.type_users.setdefault(struct.unpack_from('<H', d, unit_off + 2)[0], set()).add(method_idx)

            i += length

    def owners_for_text(self, text: str) -> List[str]:
        """Best-effort reverse lookup: given a decoded string's exact text,
        return the method label(s) that reference it via const-string."""
        out = []
        for idx, s in enumerate(self.strings):
            if s == text:
                out.extend(self.string_owners.get(idx, []))
        return out


def parse_dex_files(extract_dir: str, dex_names: List[str]) -> Optional[DexFile]:
    """Parses one or more classes*.dex files and merges them into a single
    logical DexFile-like view (multidex apps split classes across files;
    for our purposes -- string/location lookups -- we just need the union)."""
    merged = None
    for name in dex_names:
        path = os.path.join(extract_dir, name)
        try:
            data = open(path, 'rb').read()
            dexf = DexFile(data)
        except Exception:
            continue
        if merged is None:
            merged = dexf
        else:
            # Merge secondary dex string/owner tables in, offsetting nothing
            # (we key owners_for_text by *text*, not by raw index, so a
            # simple list-merge of strings/classes/owners-by-text is safe).
            base_len = len(merged.strings)
            merged.strings.extend(dexf.strings)
            merged.classes.extend(dexf.classes)
            for local_idx, owners in dexf.string_owners.items():
                merged.string_owners.setdefault(base_len + local_idx, []).extend(owners)
    return merged


# --------------------------------------------------------------------------
# Shared string-pattern scanning (used for both DEX and Mach-O binaries)
# --------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("AWS Access Key ID",        re.compile(rb'AKIA[0-9A-Z]{16}')),
    ("Google API Key",           re.compile(rb'AIza[0-9A-Za-z_\-]{35}')),
    ("Google OAuth Client ID",   re.compile(rb'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com')),
    ("Firebase Cloud Messaging", re.compile(rb'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}')),
    ("Slack Token",              re.compile(rb'xox[baprs]-[0-9A-Za-z\-]{10,}')),
    ("Generic Private Key",      re.compile(rb'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')),
    ("JWT-looking token",        re.compile(rb'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')),
    ("Razorpay live key",        re.compile(rb'rzp_live_[A-Za-z0-9]+')),
    ("Stripe live key",          re.compile(rb'sk_live_[A-Za-z0-9]{10,}')),
]

WEAK_CRYPTO_TOKENS = [b'DES', b'RC4', b'MD5', b'ECB', b'CC_MD5', b'CC_DES', b'CC_RC4', b'Cipher.getInstance("AES/ECB']

WEBVIEW_RISK_TOKENS = [
    b'addJavascriptInterface', b'setAllowUniversalAccessFromFileURLs',
    b'setAllowFileAccessFromFileURLs', b'setJavaScriptEnabled',
]

TLS_BYPASS_CLASS_TOKENS = [
    b'AllowAllHostnameVerifier', b'NoopHostnameVerifier', b'ALLOW_ALL_HOSTNAME_VERIFIER',
    b'TrustAllCerts', b'X509TrustManager',
]

JAILBREAK_ROOT_DETECTION_TOKENS = [
    b'RootBeer', b'rootbeer', b'Cydia.app', b'MobileSubstrate', b'/system/xbin/su', b'/system/bin/su',
    b'com.topjohnwu.magisk', b'isJailbroken', b'jailbreakDetect', b'JailbreakDetection',
]


_WEAK_CIPHER_RES = [
    ("DES", re.compile(rb'(?<![A-Za-z0-9])(?:DES|DESede)(?:/(?:CBC|ECB|CFB|OFB)(?:/[A-Za-z0-9]+)?)?(?![A-Za-z0-9])')),
    ("RC4", re.compile(rb'(?<![A-Za-z0-9])(?:RC4|ARC4|ARCFOUR)(?![A-Za-z0-9])')),
    ("ECB mode", re.compile(rb'(?:AES|DES|DESede|Blowfish)/ECB(?:/[A-Za-z0-9]+)?')),
    ("CC_DES/CC_RC4", re.compile(rb'\b(?:CC_DES|CC_RC4|kCCAlgorithmDES|kCCAlgorithmRC4)\b')),
]
_MD5_RE = re.compile(rb'(?<![A-Za-z0-9])(?:MD5|CC_MD5)(?![A-Za-z0-9])')


def _weak_crypto_hits(blob: bytes):
    """Whole-word matching only: the old substring check fired on 'DESCRIPTION'."""
    strong = sorted({m.group(0).decode(errors="replace") for _n, rx in _WEAK_CIPHER_RES for m in rx.finditer(blob)})
    md5 = ["MD5"] if _MD5_RE.search(blob) else []
    return strong[:8], md5


def _resolve_dex_location(dexfile: Optional["DexFile"], snippet: str, source_label: str) -> str:
    """Best-effort: turn a matched snippet into 'source_label [Lcom/x;->m()]'
    by looking up which dex string(s) contain it and who references them."""
    if dexfile is None or not snippet:
        return source_label
    owners: List[str] = []
    # Exact match first (cheap, and the common case for key/token-shaped matches).
    owners.extend(dexfile.owners_for_text(snippet))
    if not owners:
        # Fall back to substring scan (snippet may be part of a larger literal).
        for idx, s in enumerate(dexfile.strings):
            if s and snippet in s:
                owners.extend(dexfile.string_owners.get(idx, []))
                if len(owners) >= 5:
                    break
    if owners:
        uniq = sorted(set(owners))[:3]
        more = f" (+{len(set(owners)) - 3} more)" if len(set(owners)) > 3 else ""
        return f"{source_label} [{', '.join(uniq)}{more}]"
    return source_label


# Hosts/paths whose http:// URLs are standards plumbing, not app endpoints: XML/schema
# namespaces and certificate-chain URLs (CRL/OCSP/CA-issuer) that live inside every
# signed binary's embedded certificates. Reporting these as "cleartext endpoints" is
# a false positive (revocation checks are deliberately plain HTTP and integrity-protected).
_NOISE_URL_HOST_SUFFIXES = (
    "w3.org", "xml.org", "xmlsoap.org", "purl.org", "openxmlformats.org", "ns.adobe.com",
    "schemas.android.com", "schemas.microsoft.com", "apple.com/dtds", "example.com",
    "example.org", "example.net", "localhost", "digicert.com", "sectigo.com", "comodoca.com",
    "globalsign.com", "entrust.net", "identrust.com", "letsencrypt.org", "usertrust.com",
    "verisign.com", "symcb.com", "symcd.com", "godaddy.com", "starfieldtech.com",
    # documentation / project-homepage hosts that appear in library comments and error strings
    "github.com", "github.io", "githubusercontent.com", "fb.me", "reactjs.org", "react.dev",
    "redux.js.org", "jsperf.com", "momentjs.com", "ionic.io", "drifty.com", "apache.org",
    "mozilla.org", "stackoverflow.com", "npmjs.com", "wikipedia.org", "developer.apple.com",
    "developer.android.com", "android.com", "angular.io", "angular.dev", "nodejs.org", "gnu.org",
    "opensource.org", "creativecommons.org", "json.org", "xmlpull.org", "sun.com", "oracle.com",
    "sourceforge.net", "w3schools.com", "jquery.com", "lodash.com", "mit.edu", "bit.ly",
    "goo.gl", "ietf.org", "rfc-editor.org", "unicode.org", "iana.org",
)
_NOISE_URL_HOST_PREFIXES = ("ocsp.", "crl.", "crl3.", "crl4.", "cacerts.", "certs.", "pki.")
_NOISE_URL_EXACT_HOSTS = {"127.0.0.1", "0.0.0.0", "10.0.2.2"}


def _is_noise_cleartext_url(url: bytes) -> bool:
    try:
        text = url.decode("ascii", errors="ignore").lower()
    except Exception:
        return False
    rest = text[len("http://"):]
    host = rest.split("/", 1)[0].split(":", 1)[0]
    # not a hostname at all (format strings like "http://%@", "http://{host}"), or a reserved
    # TLD that can never be a real endpoint (RFC 2606 / 6761)
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", host) or host.endswith((".invalid", ".example", ".test")):
        return True
    if host in _NOISE_URL_EXACT_HOSTS or host.startswith(_NOISE_URL_HOST_PREFIXES):
        return True
    if host.endswith(("apple.com",)) and any(
            rest.startswith(h) for h in ("www.apple.com/appleca", "www.apple.com/certificateauthority",
                                         "www.apple.com/dtds", "ocsp.", "crl.")):
        return True
    full = host + rest[len(host):]
    return any(host == suf or host.endswith("." + suf) or full.startswith(suf)
               for suf in _NOISE_URL_HOST_SUFFIXES)


_PLACEHOLDER_RE = re.compile(rb'(?i)(example|sample|dummy|placeholder|your[_-]?(?:api|key|token|secret)|x{6,}|'
                             rb'0{8,}|1234567890|changeme|test[_-]?key|<[a-z_ -]+>)')
_JWT_DOC_SAMPLE = b"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"


def _b64json(part: bytes):
    import base64
    try:
        raw = base64.urlsafe_b64decode(part + b"=" * (-len(part) % 4))
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _classify_secret(name: str, token: bytes, blob: bytes, pos: int):
    """Decide whether a regex hit is worth reporting, and how loudly.
    Returns (severity, title, extra_detail, confidence) or None to drop it.
    The goal is precision: public identifiers are not secrets, docs/sample values are
    not leaks, and a PEM *marker* string is not a private key."""
    if _PLACEHOLDER_RE.search(token) or token.upper().endswith(b"EXAMPLE"):
        return None
    if name == "AWS Access Key ID":
        before = blob[pos - 1:pos] if pos else b""
        after = blob[pos + len(token): pos + len(token) + 1]
        if re.match(rb"[A-Za-z0-9+/_-]", before) or re.match(rb"[A-Za-z0-9+/_=-]", after):
            return None          # a slice of a longer base32/base64 run (cached asset, blob), not a key
        if _shannon_entropy(token[4:].decode("ascii", "replace")) < 3.0:
            return None          # e.g. AAAAAAAAAAAAAAAA; real key IDs are random
        window = blob[max(0, pos - 300): pos + len(token) + 300]
        paired = any(c != token for c in re.findall(rb'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', window))
        if paired:
            return ("HIGH", "Possible hardcoded secret: AWS access key pair",
                    " A 40-character string that could be the matching secret key sits right next to it.", "heuristic")
        return ("MEDIUM", "AWS Access Key ID embedded (no secret key found alongside)",
                " An access key ID alone cannot authenticate, but it identifies a real account and "
                "usually means the secret is somewhere nearby (config, backend, or another build).", "heuristic")
    if name in ("Google API Key", "Google OAuth Client ID", "Razorpay live key"):
        what = {"Google API Key": "Google API key", "Google OAuth Client ID": "Google OAuth client ID",
                "Razorpay live key": "Razorpay live key ID"}[name]
        return ("INFO", f"Client-side identifier: {what}",
                " This kind of value is designed to ship inside client apps; it is not a secret by itself. "
                "What matters is server-side restriction (API key restrictions / bundle-ID or package "
                "binding / key secret kept on the server).", "heuristic")
    if name == "Slack Token":
        if not re.match(rb'xox[baprs]-\d{8,}-', token):
            return None
        return ("HIGH", "Possible hardcoded secret: Slack Token", "", "heuristic")
    if name == "Generic Private Key":
        tail = blob[pos + len(token): pos + len(token) + 4000]
        body = tail.split(b"-----END", 1)[0]
        body = re.sub(rb'(\\n|\\r|\s)', b'', body)
        if re.fullmatch(rb'[A-Za-z0-9+/=]{100,}', body or b"-"):
            return ("HIGH", "Embedded private key material", "", "heuristic")
        return ("INFO", "PEM private-key marker string (no key body)",
                " Only the '-----BEGIN ... PRIVATE KEY-----' marker was found, with no base64 key data "
                "after it. This is the normal signature of a crypto/TLS library that parses PEM files, "
                "not a leaked key.", "heuristic")
    if name == "JWT-looking token":
        parts = token.split(b".")
        header, payload = _b64json(parts[0]), _b64json(parts[1]) if len(parts) > 1 else None
        if not header or "alg" not in header or payload is None or parts[1] == _JWT_DOC_SAMPLE:
            return None
        import time as _t
        exp = payload.get("exp")
        if isinstance(exp, (int, float)) and exp < _t.time():
            return ("LOW", "Expired JWT embedded in the app",
                    " The token decodes correctly but its 'exp' claim is in the past, so it is not a "
                    "live credential; check whether it exposes personal data or tooling details.", "confirmed")
        return ("HIGH", "Possible hardcoded secret: JWT (decodes as a valid token)",
                " Header and payload both decode as JSON. Check its claims and whether it is still accepted.",
                "confirmed")
    return ("HIGH", f"Possible hardcoded secret: {name}", "", "heuristic")


def scan_bytes_for_patterns(blob: bytes, source_label: str, findings: FindingsBag,
                             dexfile: Optional["DexFile"] = None, web_layer: bool = False):
    """web_layer=True when scanning bundled JavaScript/HTML: skips checks built on short
    native-binary substrings that mean nothing in JS."""
    seen_tokens = set()
    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(blob):
            token = m.group(0)
            if (name, token) in seen_tokens:
                continue
            seen_tokens.add((name, token))
            verdict = _classify_secret(name, token, blob, m.start())
            if verdict is None:
                continue
            sev, title, extra, conf = verdict
            snippet = token[:60].decode('utf-8', errors='replace')
            findings.add(sev, title,
                          f"A string matching the shape of a {name} was found embedded in {source_label}. "
                          f"Client binaries can always be extracted and read, so anything credential-like "
                          f"here should be treated as exposed (rotate it and move it server-side)." + extra
                          if sev in ("HIGH", "MEDIUM") else
                          f"A string matching the shape of a {name} was found in {source_label}." + extra,
                          evidence=snippet, location=_resolve_dex_location(dexfile, snippet, source_label),
                          confidence=conf if dexfile is None else ("confirmed" if conf == "confirmed" or dexfile is not None else conf))

    strong_weak, md_only = _weak_crypto_hits(blob)
    if strong_weak:
        findings.add("LOW", "Weak/legacy cipher identifiers present (DES / RC4 / ECB)",
                      "Whole-word references to broken ciphers or ECB mode were found. This is common in "
                      "bundled third-party libraries and does not by itself mean the app uses them "
                      "insecurely; confirm none is used for anything security-sensitive (token generation, "
                      "encrypting stored data, key derivation).",
                      evidence=", ".join(strong_weak), location=source_label, confidence="heuristic")
    elif md_only:
        findings.add("INFO", "MD5 hash identifier present",
                      "MD5 is broken for security use (passwords, signatures) but is routinely used for "
                      "non-security purposes such as cache keys and checksums, so this is only a prompt "
                      "to check how it is used.",
                      evidence=", ".join(md_only), location=source_label, confidence="heuristic")

    webview_hits = sorted({t for t in WEBVIEW_RISK_TOKENS if t in blob}, key=lambda x: x)
    if webview_hits:
        findings.add("MEDIUM" if b'addJavascriptInterface' in blob else "LOW",
                      "WebView APIs with historical risk in use",
                      "The binary references WebView configuration calls that are frequently involved in "
                      "app vulnerabilities: addJavascriptInterface() (JS-bridge exposure), and/or the file-access "
                      "flags that let JavaScript reach local files. Confirm that any WebView using these only "
                      "ever loads content from your own trusted, allow-listed origins, and that the allow-list "
                      "logic is anchored correctly (see any URL-validation-regex finding below).",
                      evidence=", ".join(h.decode() for h in webview_hits), location=source_label)

    tls_hits = sorted({t for t in TLS_BYPASS_CLASS_TOKENS if t in blob}, key=lambda x: x)
    if tls_hits:
        findings.add("INFO", "TLS/hostname-verification classes referenced",
                      "Class names related to custom TrustManagers/HostnameVerifiers were found. These are "
                      "frequently just part of a bundled HTTP library's full class set (e.g. Apache HttpClient "
                      "ships an AllowAllHostnameVerifier whether or not it's ever instantiated). This is not "
                      "proof of a certificate-validation bypass -- it just flags where to look with a decompiler.",
                      evidence=", ".join(h.decode() for h in tls_hits), location=source_label)

    # Cleartext http:// URLs (excluding common XML-namespace / schema noise)
    urls = set(re.findall(rb'http://[A-Za-z0-9.\-_/%]+', blob))
    noise = {b'http://schemas.android.com/apk/res/android', b'http://schemas.android.com/apk/res-auto',
             b'http://www.w3.org/', b'http://xml.org/', b'http://www.apple.com/DTDs/'}
    urls = {u for u in urls if not any(u.startswith(n) for n in noise) and not _is_noise_cleartext_url(u)}
    ip_urls = sorted(u.decode(errors='replace') for u in urls
                     if re.match(rb'http://\d{1,3}(?:\.\d{1,3}){3}(?:[:/]|$)', u)
                     and not re.match(rb'http://(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)', u))
    if ip_urls:
        findings.add("MEDIUM", "Cleartext HTTP URL pointing at a raw public IP address",
                      "A hardcoded http:// URL targets a bare IP address. That is unusual for a production "
                      "endpoint: it means no TLS, no certificate identity, and a server the developer may not "
                      "be able to move or rotate. Check whether the app actually calls it.",
                      evidence=", ".join(ip_urls[:10]), location=source_label, confidence="heuristic")
    if urls:
        url_list = sorted(u.decode(errors='replace') for u in urls)[:15]
        loc = source_label
        if dexfile is not None and url_list:
            loc = _resolve_dex_location(dexfile, url_list[0], source_label)
        findings.add("MEDIUM", "Cleartext (http://) URLs embedded in binary",
                      "These plaintext HTTP URLs were found in the code/binary. If any are live API endpoints "
                      "(as opposed to XML namespaces, comments, or example/placeholder values), traffic to them "
                      "can be read or modified by a network-level attacker.",
                      evidence=", ".join(url_list), location=loc,
                      confidence="confirmed" if dexfile is not None else "heuristic")

    root_hits = [] if web_layer else sorted({t for t in JAILBREAK_ROOT_DETECTION_TOKENS if t in blob}, key=lambda x: x)
    if root_hits:
        findings.add("INFO", "Root/jailbreak detection present",
                      "The app appears to include root/jailbreak or tamper detection. This is a positive "
                      "control, listed here for completeness rather than as a problem.",
                      evidence=", ".join(h.decode() for h in root_hits), location=source_label)

    # Loose "domain allow-list" regexes with no end anchor are a classic bypass pattern:
    # something ending in a TLD-looking group immediately followed by "any characters".
    for m in re.finditer(rb'\^\(https?[^\x00]{0,200}?\[\\s\\S\]\+', blob):
        snippet = m.group(0)[:200].decode('utf-8', errors='replace')
        findings.add("MEDIUM", "Possible unanchored URL/domain allow-list regex",
                      "Found a regular expression that appears to validate a URL/hostname but that ends in an "
                      "unanchored 'match anything' token ([\\s\\S]+) with no trailing '$' or boundary check. "
                      "If this is used to decide whether a URL is trusted (e.g. before loading it in a WebView "
                      "or handling a deep link), it likely accepts attacker-controlled hosts such as "
                      "'https://trusted-domain.com.attacker.example/...' because the check only looks for the "
                      "trusted domain as a *prefix*, not as the actual host. Confirm by finding the call site.",
                      evidence=snippet, location=_resolve_dex_location(dexfile, snippet, source_label),
                      confidence="confirmed" if dexfile is not None else "heuristic")


# --------------------------------------------------------------------------
# APK analysis
# --------------------------------------------------------------------------

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.READ_CALL_LOG",
    "android.permission.CALL_PHONE", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_LOGS",
}

EXPORTABLE_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}


def _manifest_component_findings(app_node: ManifestNode, findings: FindingsBag, package: str) -> List[Dict[str, Any]]:
    exported_components = []
    for tag in EXPORTABLE_TAGS:
        for comp in app_node.find_all(tag):
            name = comp.get("name", "?")
            exported_attr = comp.get("exported")
            has_intent_filter = len(comp.find_all("intent-filter")) > 0
            permission = comp.get("permission")
            # Per Android rules: if exported isn't set explicitly, a component with an
            # intent-filter is exported by default on API < 31, and it's *mandatory* to
            # declare exported explicitly once any component has an intent-filter on API 31+.
            is_exported = (exported_attr == "true") or (exported_attr is None and has_intent_filter)
            if is_exported:
                exported_components.append({
                    "type": tag, "name": name, "permission": permission,
                    "has_intent_filter": has_intent_filter,
                    "launcher": _is_launcher(comp),
                })
    # The launcher activity is exported by design; listing it is noise.
    exported_components_all = exported_components
    exported_components = [c for c in exported_components_all if not c["launcher"]]

    if exported_components:
        listing = "; ".join(f"{c['type']}:{c['name']}"
                             + (f" (permission={c['permission']})" if c['permission'] else " (no permission)")
                             for c in exported_components)
        findings.add("LOW", f"{len(exported_components)} exported component(s)",
                      "These activities/services/receivers/providers are reachable by other apps on the "
                      "device (exported=true, or implicitly exported via an intent-filter). This is often "
                      "intentional (deep links, share targets, SDK entry points) but each one that accepts "
                      "input (Intent extras, data URIs) should validate that input as untrusted. Components "
                      "with no 'permission' attribute can be invoked by *any* installed app.",
                      evidence=listing, location="AndroidManifest.xml", confidence="confirmed")
    return exported_components_all


def _is_launcher(comp: "ManifestNode") -> bool:
    for f in comp.find_all("intent-filter"):
        acts = {a.get("name") for a in f.find_all("action")}
        cats = {c.get("name") for c in f.find_all("category")}
        if "android.intent.action.MAIN" in acts and "android.intent.category.LAUNCHER" in cats:
            return True
    return False


_LAUNCH_MODE_NAMES = {"0": "standard", "1": "singleTop", "2": "singleTask", "3": "singleInstance"}
_HIJACKABLE_LAUNCH_MODES = {"2", "singleTask", "3", "singleInstance"}


def _task_hijack_findings(app_node: ManifestNode, findings: FindingsBag, package: str):
    """StrandHogg-style task-hijacking surface: an activity (especially the
    launcher) using singleTask/singleInstance without explicitly opting out
    of the default (package-name) taskAffinity via taskAffinity=\"\"."""
    for act in app_node.find_all("activity"):
        launch_mode = act.get("launchMode")
        if launch_mode not in _HIJACKABLE_LAUNCH_MODES:
            continue
        task_affinity = act.get("taskAffinity")
        allow_reparenting = act.get("allowTaskReparenting") == "true"
        is_launcher = any(
            c.get("name") == "android.intent.category.LAUNCHER"
            for f in act.find_all("intent-filter") for c in f.find_all("category")
        )
        # Safe only if taskAffinity is explicitly the empty string ("" opts the
        # activity out of task affinity entirely). Unset (defaults to the
        # package name) or any non-empty custom value keeps the risk surface.
        if task_affinity == "":
            continue
        mode_name = _LAUNCH_MODE_NAMES.get(launch_mode, launch_mode)
        findings.add(
            "MEDIUM" if is_launcher else "LOW",
            "Possible task-hijacking (StrandHogg-style) surface",
            f"Activity '{act.get('name', '?')}' uses launchMode=\"{mode_name}\" but does not set "
            f"android:taskAffinity=\"\" (empty). With this combination, a malicious app that declares an "
            f"activity sharing this app's default task affinity (which defaults to the package name, "
            f"'{package}', when unset) and also uses singleTask can, on vulnerable/older platform versions, "
            f"insert itself into this app's task and appear on top while impersonating it -- a classic "
            f"task-hijacking / StrandHogg-style attack. Setting android:taskAffinity=\"\" on sensitive "
            f"activities (particularly the launcher) removes this specific vector."
            + (" This activity also sets allowTaskReparenting=\"true\", which independently increases "
               "how easily other tasks can move activities into/out of this app's task." if allow_reparenting else ""),
            location=f"AndroidManifest.xml <activity name=\"{act.get('name', '?')}\">",
            confidence="heuristic",
        )


def _applink_findings(app_node: ManifestNode, findings: FindingsBag):
    """Flags http(s)+BROWSABLE+VIEW intent-filters that don't set
    android:autoVerify=\"true\" -- i.e. deep links that rely on Android's
    disambiguation dialog rather than verified (Android/iOS) App Links,
    and so are easier for another app to also register and intercept."""
    for comp in list(app_node.find_all("activity")) + list(app_node.find_all("activity-alias")):
        for intent_filter in comp.find_all("intent-filter"):
            has_view = any(a.get("name") == "android.intent.action.VIEW" for a in intent_filter.find_all("action"))
            has_browsable = any(c.get("name") == "android.intent.category.BROWSABLE"
                                 for c in intent_filter.find_all("category"))
            http_hosts = [d.get("host") for d in intent_filter.find_all("data")
                          if d.get("scheme") in ("http", "https") and d.get("host")]
            if not (has_view and has_browsable and http_hosts):
                continue
            auto_verify = intent_filter.get("autoVerify")
            if auto_verify != "true":
                findings.add(
                    "LOW", "Deep link without Android App Links verification (autoVerify missing)",
                    f"Activity '{comp.get('name', '?')}' handles http(s) links for host(s) "
                    f"{', '.join(sorted(set(h for h in http_hosts if h)))} but its intent-filter does not set "
                    f"android:autoVerify=\"true\". Without verified App Links (autoVerify + a matching "
                    f"/.well-known/assetlinks.json on the host), Android may show a disambiguation dialog "
                    f"letting the user pick a different, possibly malicious, app that has registered the same "
                    f"host pattern -- or on some flows silently prefer another handler. Consider enabling "
                    f"autoVerify and publishing a Digital Asset Links file for these hosts.",
                    location=f"AndroidManifest.xml <activity name=\"{comp.get('name', '?')}\">",
                    confidence="confirmed",
                )


HARDENING_MITIGATIONS_DOC = (
    "NX (non-executable stack), RELRO (read-only relocations after load), and stack canaries are "
    "standard compiler/linker exploit mitigations. Their absence doesn't mean the library is "
    "vulnerable, but it does mean one fewer layer of defense if a memory-corruption bug is ever "
    "found in it."
)


# --------------------------------------------------------------------------
# Native library (ELF) hardening checks -- a pure-Python "checksec" for .so
# --------------------------------------------------------------------------

PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552
DT_NULL = 0
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6ffffffb
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

_ELF_MACHINE_NAMES = {0x03: "x86", 0x28: "ARM", 0x3e: "x86-64", 0xb7: "ARM64"}


def analyze_elf_hardening(path: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {"error": None}
    try:
        data = open(path, 'rb').read()
        if len(data) < 20 or data[:4] != b'\x7fELF':
            info["error"] = "not an ELF file"
            return info
        ei_class = data[4]     # 1=32-bit, 2=64-bit
        ei_data = data[5]      # 1=little, 2=big
        is64 = ei_class == 2
        endian = '<' if ei_data == 1 else '>'

        e_type, e_machine = struct.unpack_from(endian + 'HH', data, 16)
        info["e_type"] = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}.get(e_type, hex(e_type))
        info["arch"] = _ELF_MACHINE_NAMES.get(e_machine, hex(e_machine))

        if is64:
            e_phoff = struct.unpack_from(endian + 'Q', data, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + 'HH', data, 54)
        else:
            e_phoff = struct.unpack_from(endian + 'I', data, 28)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + 'HH', data, 42)

        has_gnu_stack = False
        stack_exec = False
        has_gnu_relro = False
        dyn_off = dyn_size = None

        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + e_phentsize > len(data):
                break
            if is64:
                p_type, p_flags = struct.unpack_from(endian + 'II', data, off)
                p_offset, _p_vaddr, _p_paddr, p_filesz = struct.unpack_from(endian + 'QQQQ', data, off + 8)
            else:
                p_type = struct.unpack_from(endian + 'I', data, off)[0]
                p_offset, _p_vaddr, _p_paddr, p_filesz = struct.unpack_from(endian + 'IIII', data, off + 4)
                p_flags = struct.unpack_from(endian + 'I', data, off + 24)[0]

            if p_type == PT_GNU_STACK:
                has_gnu_stack = True
                stack_exec = bool(p_flags & 0x1)
            elif p_type == PT_GNU_RELRO:
                has_gnu_relro = True
            elif p_type == PT_DYNAMIC:
                dyn_off, dyn_size = p_offset, p_filesz

        info["nx_stack"] = has_gnu_stack and not stack_exec
        info["has_gnu_stack_segment"] = has_gnu_stack

        bind_now = False
        if dyn_off is not None:
            entsize = 16 if is64 else 8
            n = dyn_size // entsize if dyn_size else 0
            for i in range(n):
                off = dyn_off + i * entsize
                if is64:
                    tag, val = struct.unpack_from(endian + 'qQ', data, off)
                else:
                    tag, val = struct.unpack_from(endian + 'iI', data, off)
                if tag == DT_NULL:
                    break
                if tag == DT_BIND_NOW:
                    bind_now = True
                elif tag == DT_FLAGS and (val & DF_BIND_NOW):
                    bind_now = True
                elif tag == DT_FLAGS_1 and (val & DF_1_NOW):
                    bind_now = True

        if has_gnu_relro and bind_now:
            info["relro"] = "full"
        elif has_gnu_relro:
            info["relro"] = "partial"
        else:
            info["relro"] = "none"

        # Symbol-name presence is checked via a raw byte search of the dynamic
        # string table's usual contents rather than fully walking .dynsym --
        # these names only ever appear as identifiers in dynstr, so a plain
        # substring search is reliable and much simpler than resolving
        # SHT_DYNSYM/SHT_STRTAB section headers.
        info["stack_canary"] = b'__stack_chk_fail' in data
        fortify_symbols = [s for s in (b'__strcpy_chk', b'__memcpy_chk', b'__memmove_chk', b'__snprintf_chk',
                                        b'__vsnprintf_chk', b'__sprintf_chk', b'__strcat_chk')
                            if s in data]
        info["fortify_source"] = bool(fortify_symbols)
    except Exception as e:
        info["error"] = str(e)
    return info


def native_lib_hardening_findings(lib_dir: str, natives: List[str], findings: FindingsBag) -> List[Dict[str, Any]]:
    reports = []
    weak = []
    for rel in natives:
        full = os.path.join(lib_dir, *rel.split('/'))
        if not os.path.exists(full):
            continue
        hinfo = analyze_elf_hardening(full)
        hinfo["library"] = rel
        reports.append(hinfo)
        if hinfo.get("error"):
            continue
        issues = []
        if not hinfo.get("nx_stack", True):
            issues.append("executable stack (no NX)")
        if hinfo.get("relro") == "none":
            issues.append("no RELRO")
        if not hinfo.get("stack_canary"):
            issues.append("no stack canary")
        if issues:
            weak.append(f"{rel} ({', '.join(issues)})")

    if weak:
        findings.add("LOW", "Native libraries missing standard hardening flags",
                      HARDENING_MITIGATIONS_DOC + " The following libraries are missing one or more of "
                      "NX/RELRO/stack-canary. This is common for libraries built with an older or "
                      "third-party (non-Android-NDK-default) toolchain; if you control the build, enabling "
                      "these is generally a free/low-cost hardening improvement.",
                      evidence="; ".join(weak[:20]) + (f" (+{len(weak) - 20} more)" if len(weak) > 20 else ""),
                      location="lib/", confidence="confirmed")
    return reports


# --------------------------------------------------------------------------
# resources.arsc parser -- resolves @0x7fRRTTEE-style resource references
# (manifest attributes, and Firebase/Google config string lookups) to their
# actual string values.
# --------------------------------------------------------------------------

RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_SPEC_TYPE = 0x0202
RES_TABLE_TYPE_TYPE = 0x0201
TYPE_STRING = 0x03


class ResourceTable:
    """Best-effort parser for resources.arsc: enough to resolve a simple
    (non-'bag'/complex) resource ID to a human-readable value, and to list
    every string-typed resource's key name + value (used to spot Firebase/
    Google config keys like 'google_api_key' by name)."""

    def __init__(self, data: bytes):
        self.global_strings: List[Optional[str]] = []
        # resource_id -> (type_name, key_name, resolved_value_or_None)
        self.entries: Dict[int, Tuple[str, str, Optional[str]]] = {}
        self.refs: Dict[int, int] = {}          # resource_id -> id it points to (value is another resource)
        self._parse(data)

    def resolve(self, res_id) -> Optional[str]:
        if isinstance(res_id, str):
            m = re.match(r'@?0x([0-9a-fA-F]+)', res_id)
            if not m:
                return None
            res_id = int(m.group(1), 16)
        for _ in range(6):                       # follow @string/... -> @string/... chains
            entry = self.entries.get(res_id)
            if entry is None:
                return None
            if entry[2] is not None:
                return entry[2]
            if res_id not in self.refs:
                return None
            res_id = self.refs[res_id]
        return None

    def describe(self, res_id) -> Optional[str]:
        if isinstance(res_id, str):
            m = re.match(r'@?0x([0-9a-fA-F]+)', res_id)
            if not m:
                return None
            res_id = int(m.group(1), 16)
        entry = self.entries.get(res_id)
        if not entry:
            return None
        type_name, key_name, value = entry
        return f"R.{type_name}.{key_name}" + (f" = \"{value}\"" if value is not None else "")

    def string_entries_by_key(self) -> Dict[str, str]:
        """key_name -> value, for every string-typed resource that resolved
        to a plain value. Later duplicates (e.g. across locales) don't
        overwrite an existing entry."""
        out = {}
        for _rid, (type_name, key_name, value) in self.entries.items():
            if type_name == "string" and value is not None and key_name not in out:
                out[key_name] = value
        return out

    def _parse(self, data: bytes):
        if len(data) < 8 or _u16(data, 0) != RES_TABLE_TYPE:
            raise ValueError("Not a resource table (bad magic)")
        total_size = _u32(data, 4)
        header_size = _u16(data, 2)  # header(8) + package_count(4) == 12 for a standard RES_TABLE_TYPE header
        pos = header_size
        while pos < len(data) and pos < total_size:
            if pos + 8 > len(data):
                break
            chunk_type = _u16(data, pos)
            c_header_size = _u16(data, pos + 2)
            chunk_size = _u32(data, pos + 4)
            if chunk_size <= 0:
                break
            if chunk_type == RES_STRING_POOL_TYPE:
                self.global_strings, _ = _parse_string_pool(data, pos)
            elif chunk_type == RES_TABLE_PACKAGE_TYPE:
                try:
                    self._parse_package(data, pos, chunk_size, c_header_size)
                except Exception:
                    pass
            pos += chunk_size

    def _parse_package(self, data: bytes, pkg_start: int, pkg_size: int, header_size: int):
        package_id = _u32(data, pkg_start + 8)
        type_strings_off = _u32(data, pkg_start + 8 + 4 + 256)
        key_strings_off = _u32(data, pkg_start + 8 + 4 + 256 + 8)
        type_strings, _ = _parse_string_pool(data, pkg_start + type_strings_off)
        key_strings, _ = _parse_string_pool(data, pkg_start + key_strings_off)

        pos = pkg_start + header_size
        end = pkg_start + pkg_size
        # type_id (1-based) -> {config_key -> (entry_offsets, entries_start, entries_data_base)}
        # We only need *a* value per (type,entry), so first-seen wins.
        while pos < end and pos + 8 <= len(data):
            chunk_type = _u16(data, pos)
            c_header_size = _u16(data, pos + 2)
            chunk_size = _u32(data, pos + 4)
            if chunk_size <= 0:
                break
            if chunk_type == RES_TABLE_TYPE_TYPE:
                try:
                    self._parse_type_chunk(data, pos, c_header_size, package_id, type_strings, key_strings)
                except Exception:
                    pass
            pos += chunk_size

    def _parse_type_chunk(self, data: bytes, chunk_start: int, header_size: int,
                           package_id: int, type_strings: List[Optional[str]], key_strings: List[Optional[str]]):
        type_id = data[chunk_start + 8]
        entry_count = _u32(data, chunk_start + 12)
        entries_start = _u32(data, chunk_start + 16)
        # header_size already accounts for the variable-length ResTable_config
        # that follows the fixed fields, so entry offsets begin right after
        # this chunk's own declared header.
        offsets_base = chunk_start + header_size
        entries_base = chunk_start + entries_start
        type_name = type_strings[type_id - 1] if 0 < type_id <= len(type_strings) else f"type{type_id}"

        type_flags = data[chunk_start + 9]
        sparse = bool(type_flags & 0x01)         # ResTable_type::FLAG_SPARSE: (idx, offset/4) pairs
        offset16 = bool(type_flags & 0x02)       # ResTable_type::FLAG_OFFSET16: 16-bit offsets, in units of 4
        for slot in range(entry_count):
            if sparse:
                pos_ = offsets_base + slot * 4
                if pos_ + 4 > len(data):
                    break
                packed = _u32(data, pos_)
                entry_idx, entry_off = packed & 0xFFFF, (packed >> 16) * 4
            elif offset16:
                pos_ = offsets_base + slot * 2
                if pos_ + 2 > len(data):
                    break
                o16 = _u16(data, pos_)
                if o16 == 0xFFFF:
                    continue
                entry_idx, entry_off = slot, o16 * 4
            else:
                pos_ = offsets_base + slot * 4
                if pos_ + 4 > len(data):
                    break
                entry_off = _u32(data, pos_)
                if entry_off == 0xffffffff:
                    continue  # NO_ENTRY for this configuration
                entry_idx = slot
            res_id = (package_id << 24) | (type_id << 16) | entry_idx
            if res_id in self.entries:
                continue  # first config we see for a given id wins
            e_start = entries_base + entry_off
            if e_start + 8 > len(data):
                continue
            entry_size, _flags = struct.unpack_from('<HH', data, e_start)
            key_idx = _u32(data, e_start + 4)
            key_name = key_strings[key_idx] if 0 <= key_idx < len(key_strings) else "?"
            value = None
            if entry_size == 8:  # simple entry -> one Res_value follows
                vpos = e_start + 8
                if vpos + 8 <= len(data):
                    _vsize, _vres0, vtype, vdata = struct.unpack_from('<HBBI', data, vpos)
                    if vtype == TYPE_STRING:
                        value = _get_string(self.global_strings, vdata)
                    elif vtype == 0x12:  # boolean
                        value = 'true' if vdata else 'false'
                    elif vtype in (0x10, 0x11):  # dec / hex int
                        value = str(vdata)
                    elif vtype == 0x01:          # reference to another resource
                        self.refs.setdefault(res_id, vdata)
            # complex ("bag") entries (styles/arrays/attrs) are left unresolved (value stays None)
            self.entries[res_id] = (type_name, key_name, value)


def parse_resources_arsc(extract_dir: str) -> Optional[ResourceTable]:
    path = os.path.join(extract_dir, "resources.arsc")
    if not os.path.exists(path):
        return None
    try:
        return ResourceTable(open(path, 'rb').read())
    except Exception:
        return None


# --------------------------------------------------------------------------
# SBOM: third-party library inventory from META-INF/*.version and root
# *.properties files that common Android build tooling leaves behind.
# --------------------------------------------------------------------------

def collect_android_sbom(extract_dir: str, names: List[str]) -> List[Dict[str, str]]:
    sbom = []
    for n in names:
        base = os.path.basename(n)
        if n.startswith("META-INF/") and base.endswith(".version"):
            # e.g. "androidx.core_core-ktx.version" -> "androidx.core:core-ktx"
            lib = base[:-len(".version")]
            if "_" in lib:
                group, artifact = lib.rsplit("_", 1)
                lib_name = f"{group}:{artifact}"
            else:
                lib_name = lib
            try:
                version = open(os.path.join(extract_dir, n), encoding="utf-8", errors="replace").read().strip()
            except Exception:
                version = None
            # Some androidx .version files ship an unresolved Gradle lazy-property
            # placeholder instead of a real version string when the upstream
            # library's build didn't stamp it -- surface that as unknown rather
            # than a confusing pseudo-version.
            if version and (len(version) > 60 or "property" in version.lower() or "task " in version.lower()):
                version = None
            if version:
                sbom.append({"name": lib_name, "version": version, "source": n})
        elif "/" not in n and base.endswith(".properties"):
            try:
                text = open(os.path.join(extract_dir, n)).read()
            except Exception:
                continue
            props = {}
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                props[k.strip()] = v.strip()
            version = props.get("version") or props.get("client_version")
            lib_name = base[:-len(".properties")]
            sbom.append({"name": lib_name, "version": version, "source": n, "raw": props})
    return sbom


# --------------------------------------------------------------------------
# Entropy-based generic secret detection
# --------------------------------------------------------------------------

_ENTROPY_TOKEN_RE = re.compile(r'[A-Za-z0-9+/_\-]{24,}')


def _is_sequential_charset_table(token: str) -> bool:
    """True for literal alphabet/charset-table constants (e.g. the base64,
    base32, or hex alphabets embedded in encoder/decoder classes) -- these
    have high character-frequency entropy just like a real secret would, but
    are built from long runs of consecutive ascending code points, which a
    genuinely random token essentially never has."""
    if len(token) < 8:
        return False
    ascending_pairs = sum(1 for a, b in zip(token, token[1:]) if ord(b) == ord(a) + 1)
    return (ascending_pairs / (len(token) - 1)) >= 0.6


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


_UUID_RE = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
_WORDY_RE = re.compile(r'[a-z0-9]+(?:[_-][a-z0-9]+)+')


def _is_encoded_text(token: str) -> bool:
    """Base64 of ordinary text (JSON, XML, a sentence) is not random key material."""
    import base64
    t = token.replace('-', '+').replace('_', '/')
    try:
        raw = base64.b64decode(t + '=' * (-len(t) % 4), validate=False)
    except Exception:
        return False
    if len(raw) < 12:
        return False
    printable = sum(1 for c in raw if 32 <= c < 127 or c in (9, 10, 13))
    return printable / len(raw) >= 0.9


def _entropy_candidate(token: str) -> Optional[float]:
    """Entropy of `token` if it still looks like a key/token after all the noise filters, else None."""
    if token.count('.') > 2 or token.startswith('/'):
        return None
    if token.count('/') >= 2:
        # Class/file paths (com/google/android/Foo) are lowercase-ish and digit-free; real keys
        # that contain '/' (e.g. AWS secrets) mix digits with a high share of capitals.
        letters = [c for c in token if c.isalpha()]
        upper_ratio = sum(c.isupper() for c in letters) / max(1, len(letters))
        if not any(c.isdigit() for c in token) or upper_ratio < 0.2:
            return None
    if _UUID_RE.fullmatch(token) or _WORDY_RE.fullmatch(token) or _is_sequential_charset_table(token):
        return None
    is_hex = re.fullmatch(r'[0-9a-fA-F]+', token) is not None
    if is_hex and len(token) in (32, 40, 56, 64, 96, 128):
        return None                      # almost certainly a digest, not a credential
    if len(token) in (27, 43, 86) and re.fullmatch(r'[A-Za-z0-9_-]+', token):
        return None                      # unpadded base64url of a SHA-1 / SHA-256 / SHA-512 digest
    if token.isalpha() or (not any(c.isalpha() for c in token)):
        return None                      # identifiers and numbers are not keys
    if not is_hex and not any(c.isdigit() for c in token):
        return None
    if _is_encoded_text(token):
        return None
    ent = _shannon_entropy(token)
    if ent >= 4.5 or (is_hex and ent >= 3.5 and len(token) >= 24):
        return ent
    return None


def entropy_scan_strings(strings_iterable, source_label: str, findings: FindingsBag,
                          dexfile: Optional["DexFile"] = None, max_report: int = 15):
    """Looks for high-entropy, key/token-shaped substrings that the format-specific
    SECRET_PATTERNS do not recognise. This is the noisiest check, so it only reports at
    LOW and drops digests, UUIDs, identifiers, paths, wordy slugs and encoded text first."""
    seen, hits = set(), []
    for s in strings_iterable:
        if not s or len(s) > 4000:
            continue
        for m in _ENTROPY_TOKEN_RE.finditer(s):
            token = m.group(0)
            if token in seen:
                continue
            seen.add(token)
            ent = _entropy_candidate(token)
            if ent is not None:
                hits.append((token, ent))
    if not hits:
        return
    hits.sort(key=lambda t: -t[1])
    shown = hits[:max_report]
    evidence_parts = [f"{tok[:40]}{'…' if len(tok) > 40 else ''} (entropy={ent:.1f})" for tok, ent in shown]
    loc = source_label
    if dexfile is not None and shown:
        loc = _resolve_dex_location(dexfile, shown[0][0], source_label)
    findings.add("LOW", f"{len(hits)} high-entropy string(s) that may be keys or tokens (review list)",
                 "These strings match no known credential format, but after removing digests, UUIDs, "
                 "identifiers, paths and encoded text they still look random enough to be a key or token. "
                 "Treat this as a short list to skim, not a list of confirmed secrets.",
                 evidence="; ".join(evidence_parts) + (f" … and {len(hits) - max_report} more" if len(hits) > max_report else ""),
                 location=loc, confidence="heuristic")


def analyze_apk(apk_path: str, workdir: str, label: str = None) -> Tuple[FindingsBag, Dict[str, Any]]:
    label = label or os.path.basename(apk_path)
    findings = FindingsBag()
    meta: Dict[str, Any] = {"file": label}

    apk_bytes = open(apk_path, 'rb').read()
    extract_dir = os.path.join(workdir, "extract_" + re.sub(r'\W+', '_', label))
    os.makedirs(extract_dir, exist_ok=True)
    try:
        with open_zip(apk_path) as z:
            names = z.namelist()
            _safe_extractall(z, extract_dir)
    except zipfile.BadZipFile:
        findings.add("HIGH", "Not a valid ZIP/APK", f"{label} could not be opened as a ZIP archive.")
        return findings, meta

    manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        findings.add("HIGH", "No AndroidManifest.xml found", f"{label} does not look like a valid APK.")
        return findings, meta

    # ---- resources.arsc (parsed early so manifest @0x7f... refs can be resolved) ----
    restable = parse_resources_arsc(extract_dir)
    if restable is None and os.path.exists(os.path.join(extract_dir, "resources.arsc")):
        findings.add("LOW", "Could not parse resources.arsc",
                      "The resource table is present but this tool's parser could not read it; "
                      "resource-reference resolution below will be skipped.")

    def resolve_ref(value: Optional[str]) -> Optional[str]:
        if value and value.startswith('@0x') and restable is not None:
            return restable.describe(value)
        return None

    def resolve_label(value: Optional[str]) -> Optional[str]:
        """The app's display name: the string itself, not a debug description of the resource."""
        if not value:
            return None
        if value.startswith('@0x'):
            if restable is None:
                return None
            label = restable.resolve(value)
            if label is None:       # reference to a resource whose own value is a further reference: look it up by key
                m = re.match(r'@?0x([0-9a-fA-F]+)', value)
                entry = restable.entries.get(int(m.group(1), 16)) if m else None
                if entry and entry[0] == "string":
                    label = restable.string_entries_by_key().get(entry[1])
            return label
        if value.startswith('@'):
            return None
        return value                # a literal android:label="Docs"

    # ---- Manifest ----
    try:
        root = build_manifest_tree(open(manifest_path, 'rb').read())
    except Exception as e:
        findings.add("MEDIUM", "Could not parse AndroidManifest.xml",
                      f"Binary XML parsing failed ({e}); manifest-derived findings below are skipped.")
        root = None

    permissions = []
    if root is not None:
        package = root.get("package", "?")
        version_name = root.get("versionName")
        version_code = root.get("versionCode")
        meta.update({"package": package, "versionName": version_name, "versionCode": version_code})

        uses_sdk = root.find_all("uses-sdk")
        if uses_sdk:
            meta["minSdkVersion"] = uses_sdk[0].get("minSdkVersion")
            meta["targetSdkVersion"] = uses_sdk[0].get("targetSdkVersion")
            try:
                if int(meta["targetSdkVersion"]) < 28:
                    findings.add("MEDIUM", "Low targetSdkVersion",
                                  f"targetSdkVersion={meta['targetSdkVersion']} predates several Android "
                                  f"platform security hardening defaults (network security config default, "
                                  f"exported-component enforcement, etc.). Consider raising it.",
                                  location="AndroidManifest.xml", confidence="confirmed")
            except (TypeError, ValueError):
                pass

        for p in root.find_all("uses-permission"):
            name = p.get("name")
            if name:
                permissions.append(name)
        meta["permissions"] = permissions
        dangerous_used = sorted(set(permissions) & DANGEROUS_PERMISSIONS)
        if dangerous_used:
            findings.add("INFO", "Sensitive/dangerous permissions requested",
                          "These are runtime-dangerous or otherwise sensitive permissions. Not a vulnerability "
                          "by itself -- confirm each is actually needed for the app's function (principle of "
                          "least privilege) and that the data collected under it is handled per your privacy "
                          "policy / applicable law.",
                          evidence=", ".join(dangerous_used), location="AndroidManifest.xml",
                          confidence="confirmed")

        app_nodes = root.find_all("application")
        if app_nodes:
            app = app_nodes[0]
            if app.get("debuggable") == "true":
                findings.add("HIGH", "android:debuggable=\"true\"",
                              "The app is debuggable in this build. Any installed app (or anyone with USB "
                              "access) can attach a debugger and read/modify memory, bypass logic, or dump "
                              "secrets at runtime. This should never be true in a release build.",
                              location="AndroidManifest.xml <application>", confidence="confirmed")
            if app.get("allowBackup", "true") == "true":
                has_rules = bool(app.get("fullBackupContent") or app.get("dataExtractionRules"))
                findings.add("LOW" if has_rules else "MEDIUM", "android:allowBackup not disabled",
                              "allowBackup is true (or unset, which defaults to true). On devices where ADB "
                              "backup / auto-backup applies, this can allow extraction of the app's private "
                              "data directory without root." +
                              (" Backup rules (fullBackupContent / dataExtractionRules) are declared, so "
                               "check that they exclude tokens, databases and other sensitive files."
                               if has_rules else ""),
                              location="AndroidManifest.xml <application>", confidence="confirmed")
            if app.get("usesCleartextTraffic") == "true":
                findings.add("HIGH", "android:usesCleartextTraffic=\"true\"",
                              "The app explicitly allows plaintext (non-TLS) network traffic by default. "
                              "Any network attacker (rogue Wi-Fi, ARP spoofing, etc.) can read or tamper "
                              "with unencrypted requests.",
                              location="AndroidManifest.xml <application>", confidence="confirmed")
            nsc_ref = app.get("networkSecurityConfig")
            meta["networkSecurityConfig_ref"] = nsc_ref
            meta["networkSecurityConfig_resolved"] = resolve_ref(nsc_ref)
            if not nsc_ref:
                findings.add("LOW", "No Network Security Config declared",
                              "No android:networkSecurityConfig is set, so the platform defaults apply "
                              "(cleartext blocked by default on API 28+, system CAs only). Consider adding "
                              "one explicitly with certificate pinning for sensitive endpoints.",
                              location="AndroidManifest.xml <application>", confidence="confirmed")

            meta["app_label_resolved"] = resolve_label(app.get("label"))

            meta["exported_components"] = _manifest_component_findings(app, findings, package)
            _task_hijack_findings(app, findings, package)
            _applink_findings(app, findings)

    # ---- Network Security Config ----
    # Prefer resolving the manifest's networkSecurityConfig reference through
    # the parsed resource table (gives us the exact res/xxx.xml path directly,
    # since a compiled xml/raw resource's value IS that in-APK path); fall
    # back to a keyword scan across every compiled res/*.xml if that fails
    # (corrupt/unparsable resources.arsc, or an edge case in our arsc parser).
    res_dir = os.path.join(extract_dir, "res")
    nsc_candidate_files = []
    resolved_nsc_path = restable.resolve(nsc_ref) if (root is not None and restable is not None and
                                                       app_nodes and nsc_ref) else None
    if resolved_nsc_path and os.path.exists(os.path.join(extract_dir, resolved_nsc_path)):
        nsc_candidate_files = [os.path.basename(resolved_nsc_path)]
        findings.add("INFO", "Network Security Config located via resources.arsc",
                      f"Resolved android:networkSecurityConfig=\"{nsc_ref}\" to {resolved_nsc_path} directly "
                      f"through the parsed resource table (rather than a keyword guess).",
                      location=resolved_nsc_path, confidence="confirmed")
    elif os.path.isdir(res_dir):
        nsc_candidate_files = [fn for fn in os.listdir(res_dir) if fn.endswith(".xml")]

    if os.path.isdir(res_dir):
        for fn in nsc_candidate_files:
            fp = os.path.join(res_dir, fn)
            if not os.path.isfile(fp):
                continue
            try:
                data = open(fp, 'rb').read()
                if len(data) < 8 or _u16(data, 0) != RES_XML_TYPE:
                    continue
                strings, _events = parse_axml(data)
                joined = " ".join(s for s in strings if s).lower()
                if "network-security-config" in joined or "trust-anchors" in joined or resolved_nsc_path:
                    nsc_tree = build_manifest_tree(data)
                    certs = nsc_tree.find_all("certificates")
                    trusts_user_ca = any(c.get("src") == "user" for c in certs)
                    if trusts_user_ca:
                        findings.add("MEDIUM", "Network Security Config trusts user-installed CAs",
                                      "res/" + fn + " includes <certificates src=\"user\"/> in a trust-anchors "
                                      "block. This means any CA certificate a user (or an attacker/MDM profile) "
                                      "installs on the device will be trusted for the domains this config "
                                      "applies to, weakening protection against TLS interception (e.g. via "
                                      "Burp/mitmproxy or a malicious profile).",
                                      location=f"res/{fn}", confidence="confirmed")
                    pins = nsc_tree.find_all("pin-set")
                    if not pins:
                        findings.add("LOW", "No certificate pinning configured",
                                      "No <pin-set> was found in the network security config. Certificate "
                                      "pinning isn't mandatory, but its absence means validation relies "
                                      "entirely on the CA trust store above.",
                                      location=f"res/{fn}", confidence="confirmed")
                    cleartext_domains = [d.get("cleartextTrafficPermitted")
                                          for d in nsc_tree.find_all("domain-config")]
                    if any(v == "true" for v in cleartext_domains):
                        findings.add("HIGH", "Cleartext traffic permitted for specific domain(s)",
                                      f"res/{fn} has a <domain-config> with cleartextTrafficPermitted=\"true\".",
                                      location=f"res/{fn}", confidence="confirmed")
            except Exception:
                continue

    # ---- Signing certificate ----
    v1_sig_present = any(n.startswith("META-INF/") and (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC"))
                          for n in names)
    sig_info = extract_apk_signing_certs(apk_bytes)
    meta["signing_schemes"] = sig_info["schemes"] + (["v1"] if v1_sig_present else [])
    if not sig_info["schemes"] and not v1_sig_present:
        findings.add("HIGH", "No recognizable APK signature found",
                      "Neither a v1 (JAR/META-INF) nor a v2/v3 APK Signing Block signature was found. "
                      "This APK may be corrupt, unsigned, or use a scheme this tool doesn't recognise.",
                      confidence="heuristic")
    certs_summary = []
    for der in sig_info.get("certs_der", []):
        info = describe_cert_with_openssl(der)
        certs_summary.append(info)
    meta["signing_certs"] = certs_summary
    if len(certs_summary) > 1:
        findings.add("INFO", "APK signed by multiple certificates",
                      "More than one signer certificate was found in the signing block.",
                      evidence=json.dumps(certs_summary), confidence="confirmed")

    # ---- DEX: real parse (class/method-level location for findings) with a
    # raw-blob-scan fallback if parsing fails on any/all dex files ----
    dex_files = sorted(f for f in names if re.match(r'^classes\d*\.dex$', f))
    dexfile = parse_dex_files(extract_dir, dex_files) if dex_files else None
    meta["dex_files"] = dex_files
    if dexfile is not None:
        meta["dex_class_count"] = len(dexfile.classes)
        meta["dex_string_count"] = len(dexfile.strings)
        scan_bytes_for_patterns("\x00".join(s for s in dexfile.strings if s).encode('utf-8', errors='replace'),
                                 f"{label}:dex ({', '.join(dex_files)})", findings, dexfile=dexfile)
        entropy_scan_strings(dexfile.strings, f"{label}:dex ({', '.join(dex_files)})", findings, dexfile=dexfile)
    elif dex_files:
        # Structured parse failed (unexpected dex variant/corruption) -- fall
        # back to the coarser whole-file byte scan so we still get findings.
        combined_dex = b""
        for f in dex_files:
            combined_dex += open(os.path.join(extract_dir, f), 'rb').read()
        findings.add("LOW", "DEX structural parse failed, used raw-byte fallback scan",
                      "Findings below from the DEX are blob-wide matches without class/method attribution.")
        scan_bytes_for_patterns(combined_dex, f"{label}:dex ({', '.join(dex_files)})", findings)
    else:
        findings.add("MEDIUM", "No classes.dex found", f"{label} contains no DEX files.")

    # ---- Native libraries: inventory + ELF hardening (NX/RELRO/canary/fortify) ----
    lib_dir = os.path.join(extract_dir, "lib")
    natives = []
    if os.path.isdir(lib_dir):
        for abi in os.listdir(lib_dir):
            for so in os.listdir(os.path.join(lib_dir, abi)):
                natives.append(f"{abi}/{so}")
    meta["native_libraries"] = sorted(set(re.sub(r'^[^/]+/', '', n) for n in natives))
    if natives:
        meta["native_library_hardening"] = native_lib_hardening_findings(lib_dir, natives, findings)
        seen_banners = set()
        for n in natives[:40]:
            try:
                data = open(os.path.join(lib_dir, *n.split('/')), 'rb').read()
            except Exception:
                continue
            for m in re.finditer(rb'OpenSSL [0-9][^\x00]{0,20}', data):
                seen_banners.add(m.group(0))
        if seen_banners:
            findings.add("INFO", "Embedded OpenSSL version banner(s) found in native libraries",
                          "Confirm the bundled OpenSSL/BoringSSL build is a currently-supported version.",
                          evidence=", ".join(b.decode(errors='replace') for b in sorted(seen_banners)))

    # ---- SBOM: META-INF/*.version + root *.properties ----
    sbom = collect_android_sbom(extract_dir, names)
    meta["sbom"] = sbom
    if sbom:
        findings.add("INFO", f"{len(sbom)} third-party library version marker(s) found (SBOM)",
                      "Inventory of bundled library versions derived from META-INF/*.version and root "
                      "*.properties files left behind by common Android build tooling. Cross-reference "
                      "these against a CVE/advisory feed (e.g. OSV.dev, Sonatype OSS Index, GitHub "
                      "Advisories) for known-vulnerable versions -- this tool does not have network "
                      "access to do that lookup itself and does not guess at CVEs.",
                      evidence="; ".join(f"{e['name']}={e.get('version')}" for e in sbom[:40]
                                         if e.get('version')) + (f" (+{len(sbom)-40} more)" if len(sbom) > 40 else ""))

    # ---- Google/Firebase config surfaced via resources.arsc string entries ----
    if restable is not None:
        string_res = restable.string_entries_by_key()
        interesting_keys = ["google_api_key", "google_app_id", "gcm_defaultSenderId", "default_web_client_id",
                             "firebase_database_url", "google_crash_reporting_api_key", "project_id"]
        found_cfg = {k: string_res[k] for k in interesting_keys if k in string_res}
        if found_cfg:
            meta["google_firebase_config"] = found_cfg
            findings.add("INFO", "Firebase/Google config values found in resources",
                          "These client-side Firebase/Google Play Services config values are meant to be "
                          "embedded in the app (they identify your project to Google's backend, they aren't "
                          "secrets in the traditional sense) -- but confirm the corresponding Firebase Security "
                          "Rules / API key restrictions are configured server-side, since that's the control "
                          "that actually protects the backend, not hiding these values.",
                          evidence=json.dumps(found_cfg))

    return findings, meta


# --------------------------------------------------------------------------
# APKS / XAPK (zip container of one or more split APKs)
# --------------------------------------------------------------------------

def analyze_apks(path: str, workdir: str) -> Tuple[FindingsBag, Dict[str, Any]]:
    findings = FindingsBag()
    meta: Dict[str, Any] = {"file": os.path.basename(path), "type": "APKS/XAPK", "splits": []}

    extract_dir = os.path.join(workdir, "apks_container")
    os.makedirs(extract_dir, exist_ok=True)
    with open_zip(path) as z:
        _safe_extractall(z, extract_dir)

    apk_entries = []
    for dirpath, _dirs, files in os.walk(extract_dir):
        for f in files:
            if f.endswith(".apk"):
                apk_entries.append(os.path.join(dirpath, f))

    if not apk_entries:
        findings.add("HIGH", "No .apk entries found inside container",
                      f"{os.path.basename(path)} does not contain any split APKs; it may not really be an "
                      f"APKS/XAPK bundle.")
        return findings, meta

    # Heuristic: the "base" split usually carries the full manifest/app metadata and the DEX.
    def score(p):
        n = os.path.basename(p).lower()
        s = 0
        if 'base' in n:
            s += 100
        s += os.path.getsize(p) / (1024 * 1024)  # bigger splits more likely to carry code
        return s

    apk_entries.sort(key=score, reverse=True)
    all_signers = []

    for i, apk_path in enumerate(apk_entries):
        label = os.path.relpath(apk_path, extract_dir).replace(os.sep, "/")
        sub_findings, sub_meta = analyze_apk(apk_path, workdir, label=label)
        meta["splits"].append({"name": label, "size_bytes": os.path.getsize(apk_path), "meta": sub_meta})
        for c in sub_meta.get("signing_certs", []):
            fp = c.get("sha256_fingerprint")
            if fp:
                all_signers.append((label, fp))
        if i == 0:
            # Treat the primary/base split's findings as the headline results.
            findings.extend(sub_findings)
            meta["base_split"] = label
        else:
            # For non-base splits, only keep MEDIUM+ findings to avoid drowning the
            # report in duplicated boilerplate (every split re-declares uses-sdk etc).
            for f in sub_findings.items:
                if SEVERITY_ORDER.get(f.severity, 0) >= SEVERITY_ORDER["MEDIUM"]:
                    f.location = f"[{label}] {f.location or ''}"
                    findings.items.append(f)

    if len(apk_entries) > 1:
        findings.add("INFO", f"{len(apk_entries)} split APKs found in bundle",
                      "This is a multi-split app bundle (base + config splits for ABI/density/language). "
                      "Analysis above focuses on the split most likely to be the base/master APK "
                      f"({meta.get('base_split')}); MEDIUM+ findings from other splits are also included, "
                      "each tagged with its split name.",
                      evidence=", ".join(os.path.relpath(p, extract_dir).replace(os.sep, "/") for p in apk_entries))

    # Key rotation puts the old cert (v2 block) and the new cert (v3 block) in the same APK, so one
    # split can legitimately list several certs. Splits are consistent if every split shares at
    # least one certificate with the others (the rotation lineage); flag only disjoint signer sets.
    per_split: Dict[str, set] = {}
    for _label, fp in all_signers:
        per_split.setdefault(_label, set()).add(fp)
    sets = list(per_split.values())
    common = set.intersection(*sets) if sets else set()
    disjoint = len(sets) > 1 and not common and any(
        not (a & b) for i, a in enumerate(sets) for b in sets[i + 1:])
    if disjoint:
        findings.add("HIGH", "Splits are signed with different certificates",
                      "Not all APK splits in this bundle share the same signer certificate. Android requires "
                      "all splits of an installed app to share a signer; a mismatch here suggests either a "
                      "corrupted/tampered bundle or that unrelated APKs were zipped together.",
                      evidence=json.dumps(all_signers))

    return findings, meta


# --------------------------------------------------------------------------
# iOS IPA analysis
# --------------------------------------------------------------------------

def _load_plist(path: str) -> Optional[dict]:
    try:
        with open(path, 'rb') as f:
            return plistlib.load(f)
    except Exception:
        return None


def _extract_mobileprovision_plist(raw: bytes) -> Optional[dict]:
    """embedded.mobileprovision is a CMS/PKCS7 blob wrapping an XML plist.
    We don't verify the signature (no code-signing verification is attempted);
    we just pull out the embedded <plist>...</plist> XML for its metadata."""
    start = raw.find(b'<?xml')
    end = raw.find(b'</plist>')
    if start == -1 or end == -1:
        return None
    xml = raw[start:end + len(b'</plist>')]
    try:
        return plistlib.loads(xml)
    except Exception:
        return None


MH_PIE = 0x00200000
MH_ALLOW_STACK_EXECUTION = 0x00020000
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_CODE_SIGNATURE = 0x1d
CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0
CSSLOT_ENTITLEMENTS = 5
CS_MAGIC_ENTITLEMENT = 0xfade7171

HARDENED_RUNTIME_OPTOUT_ENTITLEMENTS = [
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
]


def _macho_collect_slices(data: bytes) -> List[Dict[str, Any]]:
    """Walks a (possibly fat/universal) Mach-O binary's load commands.
    Returns one dict per architecture slice with whatever this tool cares
    about: encryption_info, code_signature (dataoff/datasize), mach_header
    flags/PIE bit, and base_off (needed to turn any load-command file offset
    into an absolute offset into `data`, since fat-binary offsets are
    relative to that slice's own start)."""
    results = []

    def parse_thin(macho: bytes, base_off: int):
        magic = struct.unpack_from('<I', macho, base_off)[0]
        if magic in (0xfeedface, 0xcefaedfe):
            is64 = False
        elif magic in (0xfeedfacf, 0xcffaedfe):
            is64 = True
        else:
            return
        little = magic in (0xfeedface, 0xfeedfacf)
        endian = '<' if little else '>'
        _cputype, _cpusubtype, _filetype, ncmds, _sizeofcmds, mh_flags = \
            struct.unpack_from(endian + 'iiIIII', macho, base_off + 4)
        off = base_off + (32 if is64 else 28)
        entry = {"base_off": base_off, "is64": is64, "flags": mh_flags,
                 "pie": bool(mh_flags & MH_PIE),
                 "allow_stack_execution": bool(mh_flags & MH_ALLOW_STACK_EXECUTION),
                 "encryption_info": [], "code_signature": None}
        for _ in range(ncmds):
            if off + 8 > len(macho):
                break
            cmd, cmdsize = struct.unpack_from(endian + 'II', macho, off)
            if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                cryptoff, cryptsize, cryptid = struct.unpack_from(endian + 'III', macho, off + 8)
                entry["encryption_info"].append({"cryptid": cryptid, "cryptoff": cryptoff, "cryptsize": cryptsize})
            elif cmd == LC_CODE_SIGNATURE:
                dataoff, datasize = struct.unpack_from(endian + 'II', macho, off + 8)
                entry["code_signature"] = {"dataoff": dataoff, "datasize": datasize}
            if cmdsize == 0:
                break
            off += cmdsize
        results.append(entry)

    fat_magic = struct.unpack_from('>I', data, 0)[0]
    if fat_magic in (0xcafebabe, 0xcafebabf):
        nfat = struct.unpack_from('>I', data, 4)[0]
        is64_fat = fat_magic == 0xcafebabf
        entry_size = 20 if not is64_fat else 32
        for i in range(nfat):
            entry_off = 8 + i * entry_size
            offset = struct.unpack_from('>I', data, entry_off + 8)[0]
            parse_thin(data, offset)
    else:
        parse_thin(data, 0)
    return results


def _macho_encryption_info(binary_path: str) -> List[Dict[str, int]]:
    data = open(binary_path, 'rb').read()
    out = []
    for s in _macho_collect_slices(data):
        out.extend(s["encryption_info"])
    return out


def extract_entitlements_from_macho(binary_path: str) -> Optional[dict]:
    """Parses entitlements straight out of the Mach-O's embedded code
    signature (LC_CODE_SIGNATURE -> CMS SuperBlob -> CSSLOT_ENTITLEMENTS),
    rather than relying on embedded.mobileprovision (which App Store builds
    typically strip, but the code signature always carries its own copy of
    the entitlements the binary was actually signed with)."""
    data = open(binary_path, 'rb').read()
    for s in _macho_collect_slices(data):
        cs = s.get("code_signature")
        if not cs:
            continue
        base = s["base_off"] + cs["dataoff"]
        try:
            magic, _length, count = struct.unpack_from('>III', data, base)
        except Exception:
            continue
        if magic != CSMAGIC_EMBEDDED_SIGNATURE:
            continue
        for i in range(count):
            idx_off = base + 12 + i * 8
            try:
                blob_type, blob_offset = struct.unpack_from('>II', data, idx_off)
            except Exception:
                continue
            if blob_type != CSSLOT_ENTITLEMENTS:
                continue
            bstart = base + blob_offset
            try:
                bmagic, blen = struct.unpack_from('>II', data, bstart)
            except Exception:
                continue
            if bmagic != CS_MAGIC_ENTITLEMENT:
                continue
            xml_bytes = data[bstart + 8: bstart + blen]
            try:
                return plistlib.loads(xml_bytes)
            except Exception:
                return None
    return None


def analyze_macho_hardening(binary_path: str) -> Dict[str, Any]:
    """PIE bit, FairPlay encryption state, and (via entitlements) Hardened
    Runtime opt-outs -- the Mach-O/iOS analogue of the ELF checks above."""
    data = open(binary_path, 'rb').read()
    slices = _macho_collect_slices(data)
    info = {
        "slices": len(slices),
        "pie": all(s["pie"] for s in slices) if slices else None,
        "allow_stack_execution": any(s["allow_stack_execution"] for s in slices),
        "encryption_info": [c for s in slices for c in s["encryption_info"]],
        "stack_canary_symbol": b'___stack_chk_fail' in data or b'__stack_chk_fail' in data,
        # Swift binaries are built with different stack-protection defaults; the canary-symbol
        # heuristic is unreliable for them, so it is skipped rather than reported.
        "is_swift": b'libswiftCore' in data or b'_swift_retain' in data,
    }
    return info


def macho_encryption_report(binary_path: str) -> List[Dict[str, Any]]:
    """Per-slice FairPlay state, verified against the actual bytes.

    A dump tool can leave cryptid=1 while writing real ciphertext (it failed to
    decrypt), or clear nothing yet write plaintext. So besides the flag this
    measures the Shannon entropy of the encrypted range: ciphertext is ~7.9+
    bits/byte, compiled code is typically 5-6.8.
    verdict: 'decrypted' | 'ciphertext' | 'flag-set-but-readable' | 'unknown'."""
    out = []
    try:
        data = open(binary_path, 'rb').read()
        for sl in _macho_collect_slices(data):
            for enc in sl["encryption_info"]:
                verdict, ent = "decrypted", None
                if enc.get("cryptid"):
                    start = sl["base_off"] + enc["cryptoff"]
                    region = data[start:start + min(enc["cryptsize"], 1 << 20)]
                    if len(region) < 512:
                        verdict = "unknown"
                    else:
                        counts = Counter(region)
                        n = len(region)
                        ent = -sum(c / n * math.log2(c / n) for c in counts.values())
                        verdict = "ciphertext" if ent >= 7.5 else "flag-set-but-readable"
                out.append({"cryptid": enc.get("cryptid"), "cryptsize": enc.get("cryptsize"),
                            "entropy": round(ent, 2) if ent is not None else None, "verdict": verdict})
    except Exception:
        pass
    return out


def _bundle_executable(bundle_dir: str) -> Optional[str]:
    info = _load_plist(os.path.join(bundle_dir, "Info.plist")) or {}
    exe = info.get("CFBundleExecutable")
    if not isinstance(exe, str) or "/" in exe:
        return None
    path = os.path.join(bundle_dir, exe)
    return path if os.path.isfile(path) else None


def check_embedded_encryption(app_dir: str, findings: "FindingsBag", meta: Dict[str, Any]):
    """Frameworks (*.framework) and app extensions (PlugIns/*.appex) are encrypted
    separately from the main binary on App Store builds; check each one."""
    bundles = []
    fw = os.path.join(app_dir, "Frameworks")
    if os.path.isdir(fw):
        bundles += [os.path.join(fw, d) for d in sorted(os.listdir(fw)) if d.endswith(".framework")]
    pl = os.path.join(app_dir, "PlugIns")
    if os.path.isdir(pl):
        bundles += [os.path.join(pl, d) for d in sorted(os.listdir(pl)) if d.endswith(".appex")]
    still_enc, checked = [], 0
    for b in bundles:
        exe = _bundle_executable(b)
        if not exe:
            continue
        checked += 1
        if any(r["verdict"] == "ciphertext" for r in macho_encryption_report(exe)):
            still_enc.append(os.path.basename(b))
    meta["embedded_binaries_checked"] = checked
    meta["embedded_binaries_still_encrypted"] = still_enc
    if still_enc:
        findings.add("INFO", f"{len(still_enc)} of {checked} embedded framework/extension binaries still encrypted",
                      "These binaries contain FairPlay ciphertext, so their code and strings cannot be "
                      "analyzed from this IPA. If you expected a decrypted dump, re-run the dump (e.g. "
                      "with `bagbak -d` for diagnostics) and check that the decryption step completed for "
                      "every binary.",
                      evidence=", ".join(still_enc[:20]), confidence="confirmed")


_WEB_TEXT_EXTS = (".js", ".mjs", ".cjs", ".html", ".htm", ".json", ".xml", ".txt")
_WEB_MAX_FILE = 8 << 20
_WEB_MAX_TOTAL = 80 << 20
_SENSITIVE_KEY = r"[\w.-]*(?:token|jwt|secret|passw(?:or)?d|auth|api[_-]?key|credential)[\w.-]*"
_WEB_STORAGE_RE = re.compile(rb"""(?:localStorage|sessionStorage)\.setItem\(\s*["'](""" + _SENSITIVE_KEY.encode() +
                             rb""")["']""", re.I)
_PREFERENCES_RE = re.compile(rb"""Preferences\.set\(\s*\{\s*key\s*:\s*["'](""" + _SENSITIVE_KEY.encode() +
                             rb""")["']""", re.I)
_URL_HOST_RE = re.compile(rb"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?")


def analyze_hybrid_web(app_dir: str, frameworks: List[str], findings: "FindingsBag", meta: Dict[str, Any],
                       scan_label: str):
    """Capacitor / Cordova apps ship most of their logic as readable web files plus a
    JSON/XML config. A native-binary-only scan misses all of it."""
    cap_cfg = os.path.join(app_dir, "capacitor.config.json")
    cordova_cfg = os.path.join(app_dir, "config.xml")
    is_cap = os.path.isfile(cap_cfg) or any(f.startswith("Capacitor") for f in frameworks)
    is_cordova = os.path.isfile(cordova_cfg) or any(f.startswith("Cordova") for f in frameworks)
    web_root = next((os.path.join(app_dir, d) for d in ("public", "www")
                     if os.path.isdir(os.path.join(app_dir, d))), None)
    if not (is_cap or is_cordova) or not web_root:
        return
    kind = "Capacitor" if is_cap else "Cordova"
    plugins = sorted(f[:-len(".framework")] for f in frameworks
                     if f.endswith(".framework") and f.startswith(("Capacitor", "Cordova")) and
                     f not in ("Capacitor.framework", "Cordova.framework"))
    meta["hybrid"] = {"framework": kind, "web_root": os.path.basename(web_root), "plugins": plugins}

    # ---- config files ----
    if os.path.isfile(cap_cfg):
        try:
            cfg = json.load(open(cap_cfg, encoding="utf-8"))
        except Exception:
            cfg = {}
            findings.add("LOW", "Could not parse capacitor.config.json", "", location="capacitor.config.json")
        server = cfg.get("server") or {}
        ios = cfg.get("ios") or {}
        loc = "capacitor.config.json"
        url = str(server.get("url") or "")
        if url:
            findings.add("HIGH" if url.lower().startswith("http://") else "MEDIUM",
                          "Capacitor loads app content from a remote URL (server.url)",
                          "server.url makes the WebView load its pages from this origin instead of the bundled "
                          "files. It is meant for live-reload during development; left in a release build it "
                          "means the app's code is whatever that server returns" +
                          (", over plaintext HTTP (injectable by a network attacker)." if url.lower().startswith("http://") else "."),
                          evidence=url, location=loc, confidence="confirmed")
        if server.get("cleartext"):
            findings.add("MEDIUM", "Capacitor cleartext traffic enabled (server.cleartext=true)",
                          "Allows the WebView to use plaintext HTTP.", location=loc, confidence="confirmed")
        nav = server.get("allowNavigation") or []
        if isinstance(nav, list) and any(str(n).strip() in ("*", "http://*", "https://*") for n in nav):
            findings.add("MEDIUM", "Capacitor allowNavigation permits any host",
                          "A wildcard allowNavigation lets the app WebView navigate to arbitrary origins, "
                          "which widens what untrusted pages can reach through the Capacitor JS bridge.",
                          evidence=json.dumps(nav)[:200], location=loc, confidence="confirmed")
        if ios.get("webContentsDebuggingEnabled") or cfg.get("webContentsDebuggingEnabled"):
            findings.add("MEDIUM", "WebView debugging enabled in release config",
                          "webContentsDebuggingEnabled=true lets anyone with the device attach Safari's Web "
                          "Inspector to the app's WebView and read/modify its runtime state.",
                          location=loc, confidence="confirmed")
        if str(cfg.get("loggingBehavior", "")).lower() == "debug":
            findings.add("LOW", "Capacitor verbose logging enabled (loggingBehavior=debug)",
                          "Debug logging can leak request data and tokens into device logs.", location=loc,
                          confidence="confirmed")
    if os.path.isfile(cordova_cfg):
        try:
            xml = open(cordova_cfg, "rb").read()
        except OSError:
            xml = b""
        for tag, attr, title in (
                (b"access", b"origin", "Cordova <access origin=\"*\"> allows requests to any host"),
                (b"allow-navigation", b"href", "Cordova <allow-navigation href=\"*\"> allows any navigation"),
                (b"allow-intent", b"href", "Cordova <allow-intent href=\"*\"> allows opening any URL scheme")):
            for m in re.finditer(rb"<" + tag + rb"\b[^>]*\b" + attr + rb"\s*=\s*[\"']\*[\"'][^>]*>", xml):
                meta["hybrid"].setdefault("config_lines", []).append({
                    "file": "config.xml", "line": xml.count(b"\n", 0, m.start()) + 1,
                    "text": m.group(0).decode("utf-8", "replace")})
            if re.search(rb"<" + tag + rb"\b[^>]*\b" + attr + rb"\s*=\s*[\"']\*[\"']", xml):
                findings.add("MEDIUM", title,
                              "Wildcard whitelist entries remove Cordova's origin restrictions, so any loaded "
                              "page can reach native plugins or navigate the WebView anywhere.",
                              location="config.xml", confidence="confirmed")

    # ---- web assets ----
    maps, blobs, total, skipped = [], [], 0, 0
    for root, _dirs, files in os.walk(web_root):
        for fn in sorted(files):
            full = os.path.join(root, fn)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, app_dir).replace(os.sep, "/")
            low = fn.lower()
            if low.endswith(".map"):
                maps.append(rel)
                continue
            if not low.endswith(_WEB_TEXT_EXTS):
                continue
            try:
                size = os.path.getsize(full)
                if size > _WEB_MAX_FILE or total + size > _WEB_MAX_TOTAL:
                    skipped += 1
                    continue
                blobs.append(open(full, "rb").read())
                total += size
            except OSError:
                continue
    meta["hybrid"]["web_files_scanned"] = len(blobs)
    meta["hybrid"]["web_bytes_scanned"] = total
    findings.add("INFO", f"Hybrid {kind} app: web layer scanned ({len(blobs)} files, {total // 1024} KB)",
                  "Most of this app's logic ships as readable JavaScript/HTML under "
                  f"{os.path.basename(web_root)}/, which is not protected by FairPlay. Findings below that "
                  "name 'web assets' come from those files." +
                  (f" {skipped} oversized file(s) were skipped." if skipped else ""),
                  evidence="plugins: " + (", ".join(plugins) or "(none)"), confidence="confirmed")
    if maps:
        findings.add("LOW", f"{len(maps)} JavaScript source map(s) shipped",
                      "Source maps let anyone reconstruct the original, unminified source (comments, "
                      "variable names, internal endpoints). Strip them from release builds.",
                      evidence=", ".join(maps[:8]), confidence="confirmed")
    if not blobs:
        return
    blob = b"\n".join(blobs)
    label = f"{scan_label} web assets ({os.path.basename(web_root)}/)"
    scan_bytes_for_patterns(blob, label, findings, web_layer=True)

    hits = sorted({m.decode(errors="replace") for m in _WEB_STORAGE_RE.findall(blob)})
    if hits:
        findings.add("MEDIUM", "Sensitive-looking values written to web storage",
                      "localStorage/sessionStorage are stored unencrypted in the app container and are "
                      "readable on a jailbroken or backed-up device. Auth tokens and credentials belong in "
                      "the Keychain (e.g. a secure-storage plugin).",
                      evidence=", ".join(hits[:10]), location=label, confidence="heuristic")
    hits = sorted({m.decode(errors="replace") for m in _PREFERENCES_RE.findall(blob)})
    if hits:
        findings.add("MEDIUM", "Sensitive-looking values stored with Capacitor Preferences",
                      "Capacitor's Preferences plugin writes to UserDefaults, which is not encrypted. Use "
                      "Keychain-backed storage for tokens and secrets.",
                      evidence=", ".join(hits[:10]), location=label, confidence="heuristic")

    hosts = Counter(m.decode().lower() for m in _URL_HOST_RE.findall(blob)
                    if not _is_noise_cleartext_url(b"http://" + m))
    if hosts:
        top = [h for h, _ in hosts.most_common(25)]
        meta["hybrid"]["external_hosts"] = [h for h, _ in hosts.most_common(400)]   # full list, for diffing
        findings.add("INFO", f"{len(hosts)} external host(s) referenced by the web layer",
                      "Hosts the JavaScript/HTML refers to. Useful for mapping the backend attack surface; "
                      "review for staging/dev hosts and third-party trackers.",
                      evidence=", ".join(top), location=label, confidence="heuristic")


ATS_INSECURE_KEYS = ["NSAllowsArbitraryLoads", "NSAllowsArbitraryLoadsInWebContent",
                     "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking"]


def analyze_ipa(path: str, workdir: str) -> Tuple[FindingsBag, Dict[str, Any]]:
    findings = FindingsBag()
    meta: Dict[str, Any] = {"file": os.path.basename(path), "type": "IPA"}

    extract_dir = os.path.join(workdir, "ipa_extract")
    os.makedirs(extract_dir, exist_ok=True)
    with open_zip(path) as z:
        _safe_extractall(z, extract_dir)

    payload_dir = os.path.join(extract_dir, "Payload")
    if not os.path.isdir(payload_dir):
        findings.add("HIGH", "No Payload/ directory found", f"{os.path.basename(path)} does not look like a "
                      f"valid IPA (expected a top-level Payload/ folder).")
        return findings, meta

    app_dirs = [os.path.join(payload_dir, d) for d in os.listdir(payload_dir) if d.endswith(".app")]
    if not app_dirs:
        findings.add("HIGH", "No .app bundle found inside Payload/", "")
        return findings, meta
    app_dir = app_dirs[0]

    # ---- Info.plist ----
    info_plist_path = os.path.join(app_dir, "Info.plist")
    info = _load_plist(info_plist_path) or {}
    meta["bundle_id"] = info.get("CFBundleIdentifier")
    meta["name"] = info.get("CFBundleDisplayName") or info.get("CFBundleName")
    meta["version"] = info.get("CFBundleShortVersionString")
    meta["build"] = info.get("CFBundleVersion")
    meta["min_os"] = info.get("MinimumOSVersion")
    executable_name = info.get("CFBundleExecutable")
    meta["executable"] = executable_name

    usage_descriptions = {k: v for k, v in info.items() if k.endswith("UsageDescription")}
    meta["permission_usage_descriptions"] = usage_descriptions
    empty_usage = [k for k, v in usage_descriptions.items() if not v or not str(v).strip()]
    if empty_usage:
        findings.add("LOW", "Empty privacy usage-description string(s)",
                      "iOS requires a human-readable purpose string for each sensitive permission; these are "
                      "present but empty, which Apple's App Review would typically reject, or which leaves "
                      "users with no explanation for why access is requested.",
                      evidence=", ".join(empty_usage), location="Info.plist", confidence="confirmed")

    ats = info.get("NSAppTransportSecurity", {}) or {}
    meta["ats"] = ats
    if ats.get("NSAllowsArbitraryLoads"):
        findings.add("HIGH", "App Transport Security disabled globally (NSAllowsArbitraryLoads=true)",
                      "This disables ATS's baseline TLS requirements (modern TLS version, forward secrecy, "
                      "strong ciphers) for all HTTP(S) connections the app makes, allowing plaintext or "
                      "weakly-secured connections app-wide.",
                      location="Info.plist NSAppTransportSecurity", confidence="confirmed")
    if ats.get("NSAllowsArbitraryLoadsInWebContent"):
        findings.add("MEDIUM", "ATS disabled for web content (NSAllowsArbitraryLoadsInWebContent=true)",
                      "Content loaded in WKWebView/UIWebView is exempt from ATS's TLS requirements.",
                      location="Info.plist NSAppTransportSecurity", confidence="confirmed")
    exception_domains = ats.get("NSExceptionDomains", {}) or {}
    for domain, rules in exception_domains.items():
        if rules.get("NSExceptionAllowsInsecureHTTPLoads") or rules.get("NSIncludesSubdomains") is True and rules.get("NSExceptionAllowsInsecureHTTPLoads"):
            findings.add("MEDIUM", f"Cleartext HTTP allowed for domain: {domain}",
                          f"NSExceptionDomains['{domain}'] sets NSExceptionAllowsInsecureHTTPLoads, permitting "
                          f"plaintext HTTP to this specific domain (and its subdomains if NSIncludesSubdomains "
                          f"is also set).",
                          location="Info.plist NSAppTransportSecurity", confidence="confirmed")

    url_types = info.get("CFBundleURLTypes", []) or []
    schemes = [s for t in url_types for s in t.get("CFBundleURLSchemes", [])]
    meta["custom_url_schemes"] = schemes
    if schemes:
        findings.add("INFO", f"{len(schemes)} custom URL scheme(s) registered",
                      "Custom URL schemes are a common cross-app attack surface (any other app, or a web "
                      "page, can invoke them). Confirm every parameter accepted via these schemes is treated "
                      "as untrusted input, and prefer Universal Links (associated domains) over custom "
                      "schemes for anything security-sensitive, since Universal Links are exclusive to the "
                      "verified owner of the domain.",
                      evidence=", ".join(schemes), location="Info.plist CFBundleURLTypes", confidence="confirmed")

    queries_schemes = info.get("LSApplicationQueriesSchemes", []) or []
    meta["queries_schemes"] = queries_schemes

    if info.get("UIFileSharingEnabled"):
        findings.add("MEDIUM", "iTunes/Finder file sharing enabled (UIFileSharingEnabled=true)",
                      "The app's Documents directory is exposed to the user via Finder/iTunes file sharing. "
                      "Make sure nothing sensitive (tokens, cached documents, databases) is stored there.",
                      location="Info.plist", confidence="confirmed")
    if info.get("LSSupportsOpeningDocumentsInPlace"):
        findings.add("INFO", "Supports opening documents in place",
                      "LSSupportsOpeningDocumentsInPlace is enabled; combined with file sharing this widens "
                      "what's reachable through the Files app.",
                      location="Info.plist")

    its_encryption = info.get("ITSAppUsesNonExemptEncryption")
    if its_encryption is None:
        findings.add("INFO", "ITSAppUsesNonExemptEncryption not declared",
                      "Not a security bug, but this key is normally required for App Store export-compliance "
                      "purposes; its absence just means this build may not be the exact one submitted to "
                      "the Store, or the key is set via App Store Connect metadata instead.",
                      location="Info.plist")

    # ---- Embedded provisioning profile ----
    mp_path = os.path.join(app_dir, "embedded.mobileprovision")
    if os.path.exists(mp_path):
        prof = _extract_mobileprovision_plist(open(mp_path, 'rb').read())
        if prof:
            entitlements = prof.get("Entitlements", {}) or {}
            meta["provisioning"] = {
                "TeamIdentifier": prof.get("TeamIdentifier"),
                "AppIDName": prof.get("AppIDName"),
                "ExpirationDate": str(prof.get("ExpirationDate")),
                "ProvisionsAllDevices": prof.get("ProvisionsAllDevices", False),
                "device_count": len(prof.get("ProvisionedDevices", []) or []),
                "get_task_allow": entitlements.get("get-task-allow"),
                "aps_environment": entitlements.get("aps-environment"),
            }
            if entitlements.get("get-task-allow"):
                findings.add("HIGH", "Provisioning profile allows debugging (get-task-allow=true)",
                              "This build's embedded provisioning profile has get-task-allow set, meaning any "
                              "process is allowed to attach a debugger to the running app -- this is normal "
                              "for a development build but should never be true for something distributed to "
                              "end users (TestFlight/App Store release profiles set this to false).",
                              location="embedded.mobileprovision", confidence="confirmed")
            if prof.get("ProvisionsAllDevices"):
                meta.setdefault("notes", []).append("Enterprise/ProvisionsAllDevices distribution profile.")
        else:
            findings.add("LOW", "Could not parse embedded.mobileprovision",
                          "The file is present but its embedded plist could not be extracted/parsed.")
    else:
        findings.add("INFO", "No embedded.mobileprovision found",
                      "Normal for an App Store-distributed IPA (Apple strips it) or for a re-packaged/decrypted "
                      "dump; just noting it for completeness.")

    # ---- Main executable: encryption + Mach-O hardening + entitlements + string scan ----
    entitlements = None
    if executable_name:
        bin_path = os.path.join(app_dir, executable_name)
        if os.path.exists(bin_path):
            try:
                hardening = analyze_macho_hardening(bin_path)
                meta["macho_hardening"] = hardening
                meta["macho_encryption"] = hardening["encryption_info"]
                enc_report = macho_encryption_report(bin_path)
                meta["macho_encryption_verified"] = enc_report
                if any(r["verdict"] == "ciphertext" for r in enc_report):
                    ents = ", ".join(f"entropy {r['entropy']} bits/byte over {r['cryptsize']} bytes"
                                     for r in enc_report if r["verdict"] == "ciphertext")
                    findings.add("INFO", "Main binary is still FairPlay-encrypted (scan coverage limited)",
                                  "cryptid=1 AND the encrypted range holds ciphertext (" + ents + "), so the "
                                  "real code/strings of this binary are not visible to this tool. If this IPA "
                                  "was meant to be a decrypted dump, the dump did not decrypt it -- re-run it "
                                  "(e.g. `bagbak -d`) rather than trusting the filename.",
                                  location=executable_name, confidence="confirmed")
                elif any(r["verdict"] == "flag-set-but-readable" for r in enc_report):
                    findings.add("INFO", "cryptid=1 set, but the encrypted range is readable",
                                  "The FairPlay flag is still set, but the encrypted range looks like normal "
                                  "code (low entropy), so this is most likely a decrypted dump whose tool did "
                                  "not clear the flag. Scan coverage should be fine; re-signing/installing "
                                  "may require clearing cryptid first.",
                                  location=executable_name, confidence="heuristic")
                if hardening.get("pie") is False:
                    findings.add("MEDIUM", "Main binary not compiled as PIE",
                                  "The MH_PIE flag is not set on this executable. Position-Independent "
                                  "Executables get the full benefit of ASLR; without it, the binary loads at "
                                  "a fixed address, making memory-corruption exploits more reliable to write.",
                                  location=executable_name, confidence="confirmed")
                if hardening.get("allow_stack_execution"):
                    findings.add("HIGH", "Executable stack allowed (MH_ALLOW_STACK_EXECUTION)",
                                  "The binary's mach_header explicitly permits an executable stack, disabling "
                                  "a standard exploit mitigation.",
                                  location=executable_name, confidence="confirmed")
                if not hardening.get("stack_canary_symbol") and not hardening.get("is_swift"):
                    findings.add("LOW", "No stack-canary symbol found in main binary",
                                  "No reference to __stack_chk_fail was found. This is a heuristic (the "
                                  "symbol can be stripped or inlined away) rather than proof stack protection "
                                  "is absent, but it's worth confirming your build settings enable it.",
                                  location=executable_name, confidence="heuristic")
            except Exception:
                pass

            # Entitlements parsed straight from the binary's own code-signature blob.
            # This works even for App Store IPAs where embedded.mobileprovision has
            # been stripped, since the code signature always travels with the binary.
            try:
                entitlements = extract_entitlements_from_macho(bin_path)
            except Exception:
                entitlements = None
            if entitlements:
                meta["entitlements"] = entitlements
                optouts = [e for e in HARDENED_RUNTIME_OPTOUT_ENTITLEMENTS if entitlements.get(e)]
                if optouts:
                    findings.add("MEDIUM", "Hardened Runtime protections disabled via entitlement(s)",
                                  "The binary's code signature grants entitlement(s) that opt out of specific "
                                  "Hardened Runtime protections (JIT/unsigned-executable-memory allowances, "
                                  "disabled library validation, or debugger attachment via get-task-allow). "
                                  "Each of these is sometimes legitimately needed (e.g. a JIT-based scripting "
                                  "engine), but each one also removes a specific exploit-mitigation layer.",
                                  evidence=", ".join(optouts), location=f"{executable_name} (code signature entitlements)",
                                  confidence="confirmed")
                assoc_domains = entitlements.get("com.apple.developer.associated-domains", [])
                meta["associated_domains"] = assoc_domains
                if meta.get("custom_url_schemes") and not assoc_domains:
                    findings.add("INFO", "Custom URL schemes used without Universal Links (associated domains)",
                                  "The app registers custom URL scheme(s) but has no "
                                  "com.apple.developer.associated-domains entitlement. If any of those schemes "
                                  "handle sensitive actions (auth callbacks, deep-linked payments, etc.), "
                                  "migrating to Universal Links would remove the ability for another app to "
                                  "register the same scheme and intercept it.",
                                  location=f"{executable_name} (code signature entitlements)")
            elif not entitlements and os.path.exists(mp_path):
                findings.add("INFO", "Could not extract entitlements from the binary's code signature",
                              "Falling back to embedded.mobileprovision's Entitlements dictionary above, where "
                              "available.")

            blob = open(bin_path, 'rb').read()
            scan_bytes_for_patterns(blob, f"{os.path.basename(path)}:{executable_name}", findings)
            # (Entropy scanning is skipped here: Mach-O strings aren't structured into a
            # single string pool the way DEX is, so a whole-binary entropy scan is far
            # noisier -- it would mostly flag ordinary compiled/linked binary data.)

            weak_symbols = sorted({s for s in [b'CC_DES', b'CC_RC4', b'kCCAlgorithmDES',
                                                b'kCCAlgorithmRC4'] if re.search(rb'\b' + s + rb'\b', blob)})
            if weak_symbols:
                findings.add("LOW", "Weak CommonCrypto symbol references",
                              "Symbol references to legacy CommonCrypto primitives were found linked into the "
                              "binary. As with the general weak-crypto note above, this just means the symbol "
                              "is linked (often via a third-party dependency) -- confirm it isn't used for "
                              "anything security-sensitive.",
                              evidence=", ".join(s.decode() for s in weak_symbols), location=executable_name)

            if b'UIWebView' in blob:
                findings.add("LOW", "Deprecated UIWebView API referenced",
                              "UIWebView is deprecated (iOS 12+) and Apple has rejected new App Store "
                              "submissions using it since ~2020. It lacks WKWebView's process isolation and "
                              "several modern security mitigations. Migrate to WKWebView if this reference is "
                              "still live code (it may also just be a vestigial reference from a bundled "
                              "third-party SDK).",
                              location=executable_name, confidence="heuristic")
        else:
            findings.add("MEDIUM", "Declared executable not found in bundle",
                          f"Info.plist names '{executable_name}' as CFBundleExecutable but it isn't present "
                          f"in the .app bundle.")

    # ---- Frameworks / embedded dylibs inventory ----
    fw_dir = os.path.join(app_dir, "Frameworks")
    frameworks = []
    if os.path.isdir(fw_dir):
        frameworks = sorted(os.listdir(fw_dir))
    meta["embedded_frameworks"] = frameworks
    try:
        check_embedded_encryption(app_dir, findings, meta)
    except Exception:
        pass
    try:
        analyze_hybrid_web(app_dir, frameworks, findings, meta, os.path.basename(path))
    except Exception as e:
        findings.add("LOW", "Hybrid web analysis failed", f"{type(e).__name__}: {e}")

    # ---- Privacy manifests (.xcprivacy) -- app bundle root + each embedded framework ----
    privacy_manifests = {}
    candidates = [("<main app>", os.path.join(app_dir, "PrivacyInfo.xcprivacy"))]
    if os.path.isdir(fw_dir):
        for fw in frameworks:
            candidates.append((fw, os.path.join(fw_dir, fw, "PrivacyInfo.xcprivacy")))
    for owner, ppath in candidates:
        if os.path.exists(ppath):
            pdata = _load_plist(ppath)
            if pdata:
                privacy_manifests[owner] = {
                    "NSPrivacyTracking": pdata.get("NSPrivacyTracking"),
                    "NSPrivacyTrackingDomains": pdata.get("NSPrivacyTrackingDomains", []),
                    "collected_data_types": [d.get("NSPrivacyCollectedDataType")
                                              for d in pdata.get("NSPrivacyCollectedDataTypes", []) or []],
                    "accessed_api_types": [a.get("NSPrivacyAccessedAPIType")
                                           for a in pdata.get("NSPrivacyAccessedAPITypes", []) or []],
                }
    meta["privacy_manifests"] = privacy_manifests
    if privacy_manifests:
        main_pm = privacy_manifests.get("<main app>")
        if main_pm and main_pm.get("NSPrivacyTracking"):
            findings.add("INFO", "App declares tracking in its privacy manifest",
                          f"NSPrivacyTracking=true, with tracking domains: "
                          f"{', '.join(main_pm.get('NSPrivacyTrackingDomains', [])) or '(none listed)'}.",
                          location="PrivacyInfo.xcprivacy")
        findings.add("INFO", f"{len(privacy_manifests)} privacy manifest(s) (.xcprivacy) found",
                      "Apple's privacy-manifest format, declaring tracking status/domains, collected data "
                      "types, and 'required reason' API usage reasons for the app and/or its embedded "
                      "frameworks.",
                      evidence=json.dumps(privacy_manifests)[:1000])
    frameworks_missing_manifest = [fw for fw in frameworks if fw not in privacy_manifests and fw.endswith(".framework")]
    if frameworks_missing_manifest:
        findings.add("INFO", f"{len(frameworks_missing_manifest)} embedded framework(s) without a privacy manifest",
                      "Since 2024, Apple requires privacy manifests for third-party SDKs that use certain "
                      "'required reason' APIs. This tool can't tell whether each framework actually uses one "
                      "of those APIs (that needs binary analysis of the framework itself), so this is a "
                      "prompt to check, not a confirmed compliance gap.",
                      evidence=", ".join(sorted(frameworks_missing_manifest)[:20]))

    # ---- GoogleService-Info.plist (Firebase config) ----
    gsi_path = os.path.join(app_dir, "GoogleService-Info.plist")
    if os.path.exists(gsi_path):
        gsi = _load_plist(gsi_path) or {}
        meta["google_service_info"] = {k: gsi.get(k) for k in
                                        ("API_KEY", "GOOGLE_APP_ID", "PROJECT_ID", "BUNDLE_ID",
                                         "STORAGE_BUCKET", "DATABASE_URL") if k in gsi}
        gsi_bundle_id = gsi.get("BUNDLE_ID")
        if gsi_bundle_id and meta.get("bundle_id") and gsi_bundle_id != meta["bundle_id"]:
            findings.add("LOW", "GoogleService-Info.plist BUNDLE_ID does not match app's CFBundleIdentifier",
                          f"GoogleService-Info.plist declares BUNDLE_ID='{gsi_bundle_id}' but the app's own "
                          f"CFBundleIdentifier is '{meta['bundle_id']}'. This can happen intentionally "
                          f"(shared Firebase project across app variants) but is also a common copy-paste "
                          f"config mistake -- confirm this is the Firebase project you intend this app to use.",
                          location="GoogleService-Info.plist", confidence="confirmed")
        findings.add("INFO", "Firebase config (GoogleService-Info.plist) present",
                      "These values identify the app to its Firebase project; they're meant to ship in the "
                      "client (not secrets in the traditional sense). Confirm Firebase Security Rules / API "
                      "key restrictions are configured server-side, since that's the actual access control.",
                      evidence=json.dumps(meta["google_service_info"]), location="GoogleService-Info.plist")

    return findings, meta


# --------------------------------------------------------------------------
# .aab (Android App Bundle) support
#
# An AAB is a *protobuf*-encoded container (aapt2's Resources.proto schema),
# not the classic binary-XML/arsc format used inside a plain APK -- the
# manifest, resources.pb, etc. all use a completely different wire format.
# Rather than hardcode that schema's specific field numbers (a lot of
# very-easy-to-get-subtly-wrong detail with no sample corpus to validate
# against here), this handler is honestly scoped to what's reliably true
# regardless of the manifest/resource encoding:
#   - Every module's classes*.dex is byte-for-byte the same DEX format as in
#     a plain APK -- fully parsed, same as analyze_apk.
#   - Native libraries are the same ELF format -- fully hardening-checked.
#   - META-INF/*.version and *.properties (relocated under <module>/root/ in
#     an AAB) are plain text -- fully parsed for the SBOM.
#   - The protobuf-encoded manifest is only text-scanned for literal
#     permission-name strings (which appear as plain UTF-8 substrings in the
#     wire format regardless of field numbers) -- NOT structurally parsed, so
#     no exported-component / manifest-flag analysis is possible here. This
#     is stated plainly in the report rather than guessed at.
# --------------------------------------------------------------------------

_COMMON_THIRDPARTY_PACKAGE_PREFIXES = (
    "android.", "androidx.", "com.google.", "com.android.", "kotlin.", "kotlinx.",
    "okhttp3.", "okio.", "retrofit2.", "com.squareup.", "org.json", "org.apache.",
    "com.facebook.", "com.bumptech.", "com.airbnb.", "io.reactivex", "rx.", "j$.",
    "com.razorpay.", "com.loopj.", "cz.msebera.",
)


def _infer_package_from_dex(dexfile: Optional["DexFile"]) -> Optional[str]:
    """Best-effort only: picks the most common non-library 2-segment dotted
    prefix among the app's own class names. This is inferred from code, not
    read from the manifest -- labelled as such wherever it's surfaced."""
    if dexfile is None:
        return None
    counts = Counter()
    for c in dexfile.classes:
        name = c.get("name") or ""
        if not (name.startswith("L") and "/" in name):
            continue
        dotted = name[1:].rstrip(";").replace("/", ".")
        if dotted.startswith(_COMMON_THIRDPARTY_PACKAGE_PREFIXES):
            continue
        parts = dotted.split(".")
        if len(parts) < 2:
            continue
        counts[".".join(parts[:2])] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def collect_aab_sbom(extract_dir: str, names: List[str]) -> List[Dict[str, str]]:
    sbom = []
    for n in names:
        m = re.match(r'^[^/]+/root/META-INF/(.+)\.version$', n)
        if m:
            lib = m.group(1)
            lib_name = lib.replace("_", ":", 1) if "_" in lib else lib
            try:
                version = open(os.path.join(extract_dir, n), encoding="utf-8", errors="replace").read().strip()
            except Exception:
                version = None
            if version and (len(version) > 60 or "property" in version.lower()):
                version = None
            if version:
                sbom.append({"name": lib_name, "version": version, "source": n})
            continue
        m = re.match(r'^[^/]+/root/([^/]+)\.properties$', n)
        if m:
            try:
                text = open(os.path.join(extract_dir, n)).read()
            except Exception:
                continue
            props = {}
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                props[k.strip()] = v.strip()
            version = props.get("version") or props.get("client_version")
            sbom.append({"name": m.group(1), "version": version, "source": n, "raw": props})
    return sbom


def analyze_aab(path: str, workdir: str) -> Tuple[FindingsBag, Dict[str, Any]]:
    findings = FindingsBag()
    meta: Dict[str, Any] = {"file": os.path.basename(path), "type": "AAB"}

    extract_dir = os.path.join(workdir, "aab_extract")
    os.makedirs(extract_dir, exist_ok=True)
    with open_zip(path) as z:
        names = z.namelist()
        _safe_extractall(z, extract_dir)

    modules = sorted({n.split('/', 1)[0] for n in names
                       if '/' in n and n.split('/', 1)[0] not in ('META-INF',)})
    meta["modules"] = modules
    findings.add("INFO", "AAB manifest analyzed via best-effort text scan only",
                  "App Bundles encode AndroidManifest.xml and resources.pb as protobuf, not the classic "
                  "binary-XML/arsc format this tool otherwise structurally parses. Permission strings below "
                  "are found via plain text/substring search (reliable), but exported-component analysis, "
                  "manifest flags (debuggable/allowBackup/cleartextTraffic/etc.), and Network Security Config "
                  "resolution are NOT available for this format. For that level of analysis, generate a "
                  "device-specific .apks with `bundletool build-apks` and scan the result with this tool.",
                  location="(format limitation)")

    # ---- Manifest: permission-string text scan across every module's manifest ----
    all_permissions = set()
    for mod in modules:
        mpath = os.path.join(extract_dir, mod, "manifest", "AndroidManifest.xml")
        if os.path.exists(mpath):
            data = open(mpath, 'rb').read()
            all_permissions.update(m.decode() for m in set(re.findall(rb'android\.permission\.[A-Z][A-Z0-9_]*', data)))
    meta["permissions"] = sorted(all_permissions)
    dangerous_used = sorted(all_permissions & DANGEROUS_PERMISSIONS)
    if dangerous_used:
        findings.add("INFO", "Sensitive/dangerous permissions requested (text-scan match)",
                      "Found via literal string search across the protobuf manifest(s), not a structural "
                      "parse -- cross-check against `bundletool dump manifest` if precision matters.",
                      evidence=", ".join(dangerous_used), confidence="heuristic")

    # ---- DEX (identical format to a plain APK; fully parsed) ----
    dex_rel_paths = sorted(n for n in names if re.match(r'^[^/]+/dex/classes\d*\.dex$', n))
    dexfile = parse_dex_files(extract_dir, dex_rel_paths) if dex_rel_paths else None
    meta["dex_files"] = dex_rel_paths
    if dexfile is not None:
        meta["dex_class_count"] = len(dexfile.classes)
        meta["package_inferred_from_code"] = _infer_package_from_dex(dexfile)
        label = f"{os.path.basename(path)}:dex ({len(dex_rel_paths)} file(s) across {len(modules)} module(s))"
        scan_bytes_for_patterns("\x00".join(s for s in dexfile.strings if s).encode('utf-8', errors='replace'),
                                 label, findings, dexfile=dexfile)
        entropy_scan_strings(dexfile.strings, label, findings, dexfile=dexfile)
    else:
        findings.add("MEDIUM", "No classes.dex found in any module", "")

    # ---- Native libraries across all modules ----
    all_natives = []
    hardening_reports = []
    for mod in modules:
        lib_dir = os.path.join(extract_dir, mod, "lib")
        if not os.path.isdir(lib_dir):
            continue
        mod_natives = []
        for abi in os.listdir(lib_dir):
            abi_dir = os.path.join(lib_dir, abi)
            if not os.path.isdir(abi_dir):
                continue
            for so in os.listdir(abi_dir):
                mod_natives.append(f"{abi}/{so}")
        all_natives.extend(f"{mod}:{n}" for n in mod_natives)
        if mod_natives:
            hardening_reports.extend(native_lib_hardening_findings(lib_dir, mod_natives, findings))
    meta["native_libraries"] = sorted(set(re.sub(r'^[^:]+:[^/]+/', '', n) for n in all_natives))
    meta["native_library_hardening"] = hardening_reports

    # ---- SBOM ----
    sbom = collect_aab_sbom(extract_dir, names)
    meta["sbom"] = sbom
    if sbom:
        findings.add("INFO", f"{len(sbom)} third-party library version marker(s) found (SBOM)",
                      "See the equivalent APK SBOM finding for how to use this list.",
                      evidence="; ".join(f"{e['name']}={e.get('version')}" for e in sbom[:40] if e.get('version')))

    return findings, meta


# --------------------------------------------------------------------------
# Dispatcher
# --------------------------------------------------------------------------

def unrecognised_message(path: str) -> str:
    """Why a file was not recognised, in terms the user can act on."""
    kind = "an APK, APKS/XAPK, AAB or IPA file"
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return f"Could not read '{path}'."
    if head[:2] == b"PK" and not zipfile.is_zipfile(path):
        return (f"'{path}' ({size / 1e6:.1f} MB) is a corrupt or truncated zip archive: the index at the end of "
                f"the file is missing, so the download or copy was probably cut short. Re-download or re-copy it.")
    if head[:2] != b"PK" and path.lower().endswith(".apkm"):
        return (f"'{path}' is an encrypted APKMirror bundle (.apkm), not a zip archive. Install it with the "
                f"APKMirror Installer and pull the APKs (e.g. getapk), or convert it to .apks first.")
    if head[:2] != b"PK":
        return f"'{path}' is not a zip archive, so it is not {kind}."
    return f"Could not recognise '{path}' as {kind}."


def detect_kind(path: str) -> str:
    """Returns 'apk', 'apks', 'aab', 'ipa', or 'unknown'."""
    if not zipfile.is_zipfile(path):
        return "unknown"
    with open_zip(path) as z:
        names = z.namelist()
    if "AndroidManifest.xml" in names and any(n.startswith("classes") and n.endswith(".dex") for n in names):
        return "apk"
    if any(n.startswith("Payload/") for n in names):
        return "ipa"
    if "BundleConfig.pb" in names or any(re.match(r'^[^/]+/manifest/AndroidManifest\.xml$', n) for n in names):
        return "aab"
    if any(n.lower().endswith(".apk") for n in names):
        return "apks"
    # fall back to extension hint
    ext = os.path.splitext(path)[1].lower()
    if ext == ".apk":
        return "apk"
    if ext == ".aab":
        return "aab"
    if ext in (".apks", ".xapk", ".apkm"):
        return "apks"
    if ext in (".ipa", ".tipa"):
        return "ipa"
    return "unknown"


def scan(path: str, outdir: str, save_extracted: bool = True) -> Dict[str, Any]:
    os.makedirs(outdir, exist_ok=True)
    workdir = tempfile.mkdtemp(prefix="appsleuth_")
    try:
        kind = detect_kind(path)
        if kind == "apk":
            findings, meta = analyze_apk(path, workdir)
        elif kind == "apks":
            findings, meta = analyze_apks(path, workdir)
        elif kind == "aab":
            findings, meta = analyze_aab(path, workdir)
        elif kind == "ipa":
            findings, meta = analyze_ipa(path, workdir)
        else:
            raise ValueError(unrecognised_message(path))
        meta["detected_type"] = kind
        if save_extracted:
            shutil.copytree(workdir, os.path.join(outdir, "extracted"), dirs_exist_ok=True)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    result = {
        "input_file": os.path.abspath(path),
        "detected_type": kind,
        "meta": meta,
        "findings": [f.to_dict() for f in findings.sorted()],
        "summary": {
            sev: sum(1 for f in findings.items if f.severity == sev)
            for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
        },
    }

    with open(os.path.join(outdir, "report.json"), "w") as f:
        json.dump(result, f, indent=2, default=str)

    write_markdown_report(result, os.path.join(outdir, "report.md"))
    write_html_report(result, os.path.join(outdir, "report.html"))
    return result


def write_markdown_report(result: Dict[str, Any], path: str):
    meta = result["meta"]
    lines = []
    lines.append(f"# Mobile app static security scan: {os.path.basename(result['input_file'])}")
    lines.append("")
    lines.append(f"- Detected type: **{result['detected_type'].upper()}**")
    for key in ("package", "bundle_id", "versionName", "version", "versionCode", "build",
                "minSdkVersion", "targetSdkVersion", "min_os"):
        if meta.get(key):
            lines.append(f"- {key}: `{meta[key]}`")
    lines.append("")
    s = result["summary"]
    lines.append(f"**Findings:** {s['HIGH']} High, {s['MEDIUM']} Medium, {s['LOW']} Low, {s['INFO']} Info")
    if result.get("suppressed_count"):
        lines.append(f"*({result['suppressed_count']} additional finding(s) suppressed by baseline "
                     f"'{result.get('baseline_file')}' -- see report.json for the full list.)*")
    lines.append("")
    lines.append("> Static analysis only. HIGH/MEDIUM findings are leads for manual review, not confirmed, "
                 "exploitable vulnerabilities -- see each finding's `confidence` field.")
    lines.append("")
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        items = [f for f in result["findings"] if f["severity"] == sev]
        if not items:
            continue
        lines.append(f"## {sev}")
        for f in items:
            lines.append(f"### {f['title']}")
            lines.append(f['detail'])
            if f.get("location"):
                lines.append(f"- Location: `{f['location']}`")
            if f.get("evidence"):
                ev = f['evidence']
                if len(ev) > 500:
                    ev = ev[:500] + " …"
                lines.append(f"- Evidence: `{ev}`")
            lines.append(f"- Confidence: {f.get('confidence', 'heuristic')}")
            lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


_SEVERITY_COLORS = {"HIGH": "#c0392b", "MEDIUM": "#d68910", "LOW": "#2471a3", "INFO": "#5d6d7e"}


def write_html_report(result: Dict[str, Any], path: str):
    """Self-contained (no external assets) HTML report -- same content as
    report.md, laid out for a non-technical stakeholder to skim."""
    meta = result["meta"]
    s = result["summary"]
    esc = html.escape

    meta_rows = "".join(
        f"<tr><th>{esc(k)}</th><td>{esc(str(meta[k]))}</td></tr>"
        for k in ("package", "bundle_id", "versionName", "version", "versionCode", "build",
                  "minSdkVersion", "targetSdkVersion", "min_os")
        if meta.get(k)
    )

    badges = "".join(
        f'<span class="badge" style="background:{_SEVERITY_COLORS[sev]}">{s[sev]} {sev}</span>'
        for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
    )

    sections = []
    for sev in ("HIGH", "MEDIUM", "LOW", "INFO"):
        items = [f for f in result["findings"] if f["severity"] == sev]
        if not items:
            continue
        cards = []
        for f in items:
            loc = f'<div class="loc">Location: <code>{esc(f["location"])}</code></div>' if f.get("location") else ""
            ev = f.get("evidence") or ""
            if len(ev) > 800:
                ev = ev[:800] + " …"
            ev_html = f'<div class="ev"><code>{esc(ev)}</code></div>' if ev else ""
            cards.append(f'''
<div class="card" style="border-left-color:{_SEVERITY_COLORS[sev]}">
  <div class="card-title">{esc(f["title"])}</div>
  <div class="card-body">{esc(f["detail"])}</div>
  {loc}{ev_html}
  <div class="confidence">confidence: {esc(f.get("confidence", "heuristic"))}</div>
</div>''')
        sections.append(f'<h2 style="color:{_SEVERITY_COLORS[sev]}">{sev} ({len(items)})</h2>' + "".join(cards))

    suppressed_note = ""
    if result.get("suppressed_count"):
        suppressed_note = (f'<p class="muted">{result["suppressed_count"]} additional finding(s) suppressed by '
                            f'baseline "{esc(str(result.get("baseline_file")))}".</p>')

    html_doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Scan report: {esc(os.path.basename(result['input_file']))}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 0;
          background: #f7f8fa; color: #1c2530; }}
  .wrap {{ max-width: 900px; margin: 0 auto; padding: 32px 20px 80px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  h2 {{ font-size: 16px; margin-top: 36px; border-bottom: 1px solid #ddd; padding-bottom: 6px; }}
  table {{ border-collapse: collapse; margin: 12px 0 20px; }}
  th, td {{ text-align: left; padding: 3px 12px 3px 0; font-size: 13px; }}
  th {{ color: #667; font-weight: 600; }}
  .badge {{ display: inline-block; color: white; border-radius: 4px; padding: 4px 10px;
             font-size: 12px; font-weight: 600; margin-right: 8px; }}
  .card {{ background: white; border-left: 4px solid #999; border-radius: 4px; padding: 12px 16px;
            margin: 10px 0; box-shadow: 0 1px 2px rgba(0,0,0,0.06); }}
  .card-title {{ font-weight: 600; font-size: 14px; margin-bottom: 6px; }}
  .card-body {{ font-size: 13px; line-height: 1.5; color: #333; }}
  .loc, .ev {{ font-size: 12px; margin-top: 8px; color: #555; word-break: break-all; }}
  .confidence {{ font-size: 11px; color: #888; margin-top: 8px; text-transform: uppercase; letter-spacing: .03em; }}
  code {{ background: #f0f1f3; padding: 1px 4px; border-radius: 3px; }}
  .muted {{ color: #777; font-size: 13px; }}
  .disclaimer {{ font-size: 12px; color: #666; background: #fff8e6; border: 1px solid #f0e0a0;
                  border-radius: 6px; padding: 10px 14px; margin: 16px 0; }}
</style></head>
<body><div class="wrap">
  <h1>Mobile app static security scan</h1>
  <p class="muted">{esc(os.path.basename(result['input_file']))} &mdash; detected as {esc(result['detected_type'].upper())}</p>
  <table>{meta_rows}</table>
  <div>{badges}</div>
  {suppressed_note}
  <div class="disclaimer">Static analysis only. HIGH/MEDIUM findings are leads for manual review, not
  confirmed, exploitable vulnerabilities &mdash; see each finding's confidence field.</div>
  {"".join(sections)}
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)


# --------------------------------------------------------------------------
# Baseline / suppression
# --------------------------------------------------------------------------

def finding_fingerprint(f: Dict[str, Any]) -> str:
    """Stable-ish identity for 'is this essentially the same finding as
    before': title + location, not the full evidence text (which can
    reasonably shift a little between builds -- e.g. a slightly reordered
    evidence list -- without it being a meaningfully different finding)."""
    basis = f"{f.get('title', '')}|{f.get('location', '')}"
    return hashlib.sha256(basis.encode('utf-8', errors='replace')).hexdigest()[:16]


def _app_name(result: Dict[str, Any]) -> str:
    return os.path.basename(str(result.get("input_file") or result.get("meta", {}).get("file") or ""))


def baseline_fingerprint(f: Dict[str, Any], app_name: str) -> str:
    """Like finding_fingerprint, but the scanned file's own name is replaced in the location
    ("MyApp-1.2.apk:dex (classes.dex)" -> "<app>:dex (classes.dex)"), so a baseline keeps
    matching after the app file is renamed or a new build is downloaded under another name."""
    loc = str(f.get("location") or "")
    if app_name:
        loc = re.sub(r"(?<![\w.-])" + re.escape(app_name) + r"(?![\w.-])", "<app>", loc)
    basis = f"{f.get('title', '')}|{loc}"
    return hashlib.sha256(basis.encode('utf-8', errors='replace')).hexdigest()[:16]


def load_baseline(path: str) -> Dict[str, Any]:
    with open(path) as fh:
        data = json.load(fh)
    # Accept either the {fingerprint: {...}} shape written by --write-baseline,
    # or a bare list of fingerprint strings someone hand-authored.
    if isinstance(data, list):
        return {fp: {} for fp in data}
    return data


def apply_baseline(result: Dict[str, Any], baseline: Dict[str, Any], baseline_path: str) -> Dict[str, Any]:
    all_findings = result["findings"]
    new_findings, suppressed = [], []
    name = _app_name(result)
    for f in all_findings:
        fp = baseline_fingerprint(f, name)
        f["fingerprint"] = fp
        if fp in baseline or finding_fingerprint(f) in baseline:     # also match baselines from <= 1.5.2
            suppressed.append(f)
        else:
            new_findings.append(f)
    result["findings"] = new_findings
    result["suppressed_findings"] = suppressed
    result["suppressed_count"] = len(suppressed)
    result["baseline_file"] = baseline_path
    result["summary"] = {sev: sum(1 for f in new_findings if f["severity"] == sev)
                         for sev in ("HIGH", "MEDIUM", "LOW", "INFO")}
    return result


def write_baseline(result: Dict[str, Any], path: str):
    baseline = {}
    name = _app_name(result)
    for f in result["findings"]:
        fp = baseline_fingerprint(f, name)
        baseline[fp] = {"title": f["title"], "location": f.get("location")}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2)


# --------------------------------------------------------------------------
# Diff mode -- compare two scans (old build vs new build) of "the same app"
# --------------------------------------------------------------------------

def _set_diff(old_items, new_items):
    old_set, new_set = set(old_items or []), set(new_items or [])
    return sorted(new_set - old_set), sorted(old_set - new_set)


def diff_scans(old_result: Dict[str, Any], new_result: Dict[str, Any]) -> Dict[str, Any]:
    old_meta, new_meta = old_result.get("meta", {}), new_result.get("meta", {})
    out: Dict[str, Any] = {
        "old_file": old_result.get("input_file"), "new_file": new_result.get("input_file"),
        "old_version": old_meta.get("versionName") or old_meta.get("version"),
        "new_version": new_meta.get("versionName") or new_meta.get("version"),
    }

    added_perms, removed_perms = _set_diff(old_meta.get("permissions"), new_meta.get("permissions"))
    out["permissions"] = {"added": added_perms, "removed": removed_perms}

    def comp_labels(meta):
        return [f"{c['type']}:{c['name']}" for c in meta.get("exported_components", []) or []]
    added_comp, removed_comp = _set_diff(comp_labels(old_meta), comp_labels(new_meta))
    out["exported_components"] = {"added": added_comp, "removed": removed_comp}

    added_schemes, removed_schemes = _set_diff(old_meta.get("custom_url_schemes"), new_meta.get("custom_url_schemes"))
    out["custom_url_schemes"] = {"added": added_schemes, "removed": removed_schemes}

    added_libs, removed_libs = _set_diff(old_meta.get("native_libraries"), new_meta.get("native_libraries"))
    out["native_libraries"] = {"added": added_libs, "removed": removed_libs}

    old_sbom = {e["name"]: e.get("version") for e in old_meta.get("sbom", []) or []}
    new_sbom = {e["name"]: e.get("version") for e in new_meta.get("sbom", []) or []}
    sbom_added = sorted(set(new_sbom) - set(old_sbom))
    sbom_removed = sorted(set(old_sbom) - set(new_sbom))
    sbom_bumped = sorted(f"{k}: {old_sbom[k]} -> {new_sbom[k]}" for k in (set(old_sbom) & set(new_sbom))
                          if old_sbom[k] != new_sbom[k])
    out["sbom"] = {"added": sbom_added, "removed": sbom_removed, "version_changed": sbom_bumped}

    old_fps = {finding_fingerprint(f): f for f in old_result.get("findings", [])}
    new_fps = {finding_fingerprint(f): f for f in new_result.get("findings", [])}
    out["findings"] = {
        "new": [new_fps[k] for k in sorted(set(new_fps) - set(old_fps))],
        "resolved": [old_fps[k] for k in sorted(set(old_fps) - set(new_fps))],
    }
    return out


def write_diff_markdown(diff: Dict[str, Any], path: str):
    lines = [f"# Diff: {os.path.basename(diff['old_file'])} -> {os.path.basename(diff['new_file'])}"]
    if diff.get("old_version") or diff.get("new_version"):
        lines.append(f"\nVersion: `{diff.get('old_version')}` -> `{diff.get('new_version')}`\n")

    def bullet_section(title, added, removed, empty_ok=True):
        if not added and not removed:
            return
        lines.append(f"## {title}")
        for a in added:
            lines.append(f"- + `{a}`")
        for r in removed:
            lines.append(f"- - `{r}`")
        lines.append("")

    bullet_section("Permissions", diff["permissions"]["added"], diff["permissions"]["removed"])
    bullet_section("Exported components", diff["exported_components"]["added"], diff["exported_components"]["removed"])
    bullet_section("Custom URL schemes", diff["custom_url_schemes"]["added"], diff["custom_url_schemes"]["removed"])
    bullet_section("Native libraries", diff["native_libraries"]["added"], diff["native_libraries"]["removed"])
    sbom = diff["sbom"]
    if sbom["added"] or sbom["removed"] or sbom["version_changed"]:
        lines.append("## Third-party libraries (SBOM)")
        for a in sbom["added"]:
            lines.append(f"- + `{a}`")
        for r in sbom["removed"]:
            lines.append(f"- - `{r}`")
        for c in sbom["version_changed"]:
            lines.append(f"- ~ `{c}`")
        lines.append("")

    f_new, f_resolved = diff["findings"]["new"], diff["findings"]["resolved"]
    if f_new:
        lines.append(f"## New findings ({len(f_new)})")
        for f in f_new:
            lines.append(f"- **[{f['severity']}]** {f['title']} (`{f.get('location', '')}`)")
        lines.append("")
    if f_resolved:
        lines.append(f"## Resolved findings ({len(f_resolved)})")
        for f in f_resolved:
            lines.append(f"- **[{f['severity']}]** {f['title']} (`{f.get('location', '')}`)")
        lines.append("")
    if not (f_new or f_resolved):
        lines.append("No finding-level differences.")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# --------------------------------------------------------------------------
# Batch mode
# --------------------------------------------------------------------------

_RECOGNISED_EXTS = (".apk", ".apks", ".xapk", ".apkm", ".aab", ".ipa", ".tipa")


def batch_scan(directory: str, outdir: str, recursive: bool = False, save_extracted: bool = True) -> Dict[str, Any]:
    os.makedirs(outdir, exist_ok=True)
    targets = []
    walker = os.walk(directory) if recursive else [(directory, [], os.listdir(directory))]
    for dirpath, _dirs, files in walker:
        for fn in files:
            if fn.lower().endswith(_RECOGNISED_EXTS):
                targets.append(os.path.join(dirpath, fn))
    targets.sort()

    per_file = []
    for t in targets:
        sub_outdir = os.path.join(outdir, re.sub(r'\W+', '_', os.path.splitext(os.path.basename(t))[0]))
        try:
            result = scan(t, sub_outdir, save_extracted)
            per_file.append({"file": t, "outdir": sub_outdir, "detected_type": result["detected_type"],
                              "summary": result["summary"], "error": None})
        except Exception as e:
            per_file.append({"file": t, "outdir": sub_outdir, "detected_type": None,
                              "summary": None, "error": str(e)})

    per_file.sort(key=lambda r: -(r["summary"]["HIGH"] * 1000 + r["summary"]["MEDIUM"] * 10 + r["summary"]["LOW"])
                  if r["summary"] else 0)
    batch_result = {"directory": os.path.abspath(directory), "count": len(targets), "results": per_file}
    with open(os.path.join(outdir, "batch_summary.json"), "w") as fh:
        json.dump(batch_result, fh, indent=2, default=str)

    lines = [f"# Batch scan: {directory}", "", f"{len(targets)} file(s) scanned.", ""]
    lines.append("| File | Type | High | Medium | Low | Info | Error |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in per_file:
        s = r["summary"] or {}
        lines.append(f"| {os.path.basename(r['file'])} | {r['detected_type'] or '?'} | "
                     f"{s.get('HIGH', '-')} | {s.get('MEDIUM', '-')} | {s.get('LOW', '-')} | {s.get('INFO', '-')} | "
                     f"{r['error'] or ''} |")
    with open(os.path.join(outdir, "batch_summary.md"), "w") as fh:
        fh.write("\n".join(lines))
    return batch_result


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="Path to an .apk, .apks/.xapk, .aab, or .ipa file, OR a directory (batch mode)")
    ap.add_argument("-o", "--outdir", default=None, help="Output directory (default: ./scan_<filename>)")
    ap.add_argument("--no-extract", action="store_true",
                    help="Do not keep the unpacked app contents (by default saved to <outdir>/extracted)")
    ap.add_argument("--recursive", action="store_true",
                     help="Batch mode only: recurse into subdirectories looking for scannable files.")
    ap.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "LOW", "INFO"], default=None,
                     help="Exit with code 3 if any (non-suppressed) finding at or above this severity is "
                          "present. Intended for CI gating. Ignored in batch mode (see per-file exit codes "
                          "in batch_summary.json instead).")
    ap.add_argument("--baseline", default=None,
                     help="Path to a baseline JSON (from --write-baseline) whose findings are suppressed "
                          "from this scan's report and --fail-on check, and reported separately as "
                          "'suppressed'.")
    ap.add_argument("--write-baseline", default=None,
                     help="After scanning, write every current finding's fingerprint to this path as a new "
                          "baseline file (does not itself suppress anything in this run).")
    ap.add_argument("--diff-against", default=None,
                     help="Compare this scan against a previous one: pass either an old .apk/.ipa/etc. file "
                          "(it will be scanned fresh) or a previous scan's report.json. Writes diff.md/diff.json "
                          "into the output directory instead of (in addition to) a normal single-file report.")
    args = ap.parse_args()

    if not os.path.exists(args.file):
        print(f"error: file not found: {args.file}", file=sys.stderr)
        sys.exit(2)

    outdir = args.outdir or f"scan_{os.path.splitext(os.path.basename(args.file.rstrip('/')))[0]}"

    # ---- Batch mode: a directory instead of a single file ----
    if os.path.isdir(args.file):
        batch_result = batch_scan(args.file, outdir, recursive=args.recursive, save_extracted=not args.no_extract)
        print(f"Batch-scanned {batch_result['count']} file(s) under {args.file}")
        print(f"Summary written to: {outdir}/batch_summary.md , {outdir}/batch_summary.json")
        for r in batch_result["results"]:
            if r["error"]:
                print(f"  ! {r['file']}: {r['error']}")
        return

    try:
        result = scan(args.file, outdir, save_extracted=not args.no_extract)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"error: unexpected failure while scanning '{args.file}': {e}", file=sys.stderr)
        sys.exit(1)

    # ---- Baseline suppression ----
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
        except Exception as e:
            print(f"error: could not read baseline file '{args.baseline}': {e}", file=sys.stderr)
            sys.exit(2)
        result = apply_baseline(result, baseline, args.baseline)
        with open(os.path.join(outdir, "report.json"), "w") as f:
            json.dump(result, f, indent=2, default=str)
        write_markdown_report(result, os.path.join(outdir, "report.md"))
        write_html_report(result, os.path.join(outdir, "report.html"))

    if args.write_baseline:
        write_baseline(result, args.write_baseline)
        print(f"Baseline written to: {args.write_baseline}")

    # ---- Diff mode ----
    if args.diff_against:
        if args.diff_against.lower().endswith(".json"):
            with open(args.diff_against) as fh:
                old_result = json.load(fh)
        else:
            old_outdir = os.path.join(outdir, "diff_baseline_scan")
            old_result = scan(args.diff_against, old_outdir, save_extracted=False)
        diff = diff_scans(old_result, result)
        with open(os.path.join(outdir, "diff.json"), "w") as fh:
            json.dump(diff, fh, indent=2, default=str)
        write_diff_markdown(diff, os.path.join(outdir, "diff.md"))
        print(f"Diff written to: {outdir}/diff.json , {outdir}/diff.md "
             f"({len(diff['findings']['new'])} new finding(s), {len(diff['findings']['resolved'])} resolved)")

    s = result["summary"]
    print(f"Scanned {args.file} as {result['detected_type'].upper()}")
    print(f"Findings: {s['HIGH']} High, {s['MEDIUM']} Medium, {s['LOW']} Low, {s['INFO']} Info"
         + (f" ({result['suppressed_count']} suppressed by baseline)" if result.get("suppressed_count") else ""))
    print(f"Reports written to: {outdir}/report.json , {outdir}/report.md , {outdir}/report.html")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        worst = max((SEVERITY_ORDER[f["severity"]] for f in result["findings"]), default=-1)
        if worst >= threshold:
            print(f"--fail-on {args.fail_on}: found a finding at or above this severity.", file=sys.stderr)
            sys.exit(3)


if __name__ == "__main__":
    main()
