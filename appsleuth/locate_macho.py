"""Mach-O (iOS) provider for locate.py: symbols, string / CFString / selector addresses, referencing functions,
Objective-C methods and classes read from the runtime metadata (what objc_msgSend dispatches to), and call sites of
imported functions. Cross-references are implemented for arm64 (the only architecture iOS apps ship)."""
from __future__ import annotations

import bisect
import struct
from array import array
from typing import Any, Dict, List, Optional, Tuple

from . import locate_elf as le

CPU_ARM64 = 0x0100000C
# imported C functions that checks commonly call; reported with every call site
NATIVE_IMPORTS = {
    "_ptrace": ("debugger", "Native import: ptrace (anti-debug)"),
    "_sysctl": ("debugger", "Native import: sysctl (P_TRACED check)"),
    "_task_get_exception_ports": ("debugger", "Native import: task_get_exception_ports"),
    "_isatty": ("debugger", "Native import: isatty"),
    "__dyld_image_count": ("hooking", "Native import: _dyld_image_count (loaded-library scan)"),
    "__dyld_get_image_name": ("hooking", "Native import: _dyld_get_image_name (loaded-library scan)"),
    "_dladdr": ("hooking", "Native import: dladdr (hook detection)"),
    "_fork": ("root", "Native import: fork (sandbox-integrity probe)"),
    "_vfork": ("root", "Native import: vfork (sandbox-integrity probe)"),
    "_posix_spawn": ("root", "Native import: posix_spawn (sandbox-integrity probe)"),
}
# libc / Foundation functions that implement file / process / environment probes (substring match on import names, so
# Swift-mangled stubs such as $sSo..fileExists6atPath are caught too); reported only inside a function that also
# references an indicator string
GENERIC_IMPORTS = ["_access", "_faccessat", "_stat", "_lstat", "_fstatat", "_stat$INODE64", "_lstat$INODE64", "_fopen", "_open", "_openat",
                   "_opendir", "_readdir", "_readlink", "_realpath", "_statfs", "_popen", "_system", "_execve", "_getenv", "_dlopen",
                   "_dlsym", "_syscall", "_fork", "_vfork", "_kill", "_getppid", "_posix_spawn", "_NSClassFromString", "_objc_getClass",
                   "_class_getImageName", "_SecTrustEvaluate", "_SecTrustEvaluateWithError", "_SecCodeCheckValidity",
                   "_SecStaticCodeCheckValidity", "_SecItemCopyMatching", "_connect", "_socket", "_mach_absolute_time", "_clock_gettime",
                   "_gettimeofday", "_mprotect", "_vm_protect"]
SUBSTR_IMPORTS = ["fileExists6atPath", "contentsOfDirectory", "isReadableFile", "canOpenURL", "isDeprecated", "isCaptured"]
# Objective-C selectors that implement probes (found through the selector references the compiler emits)
PROBE_SELECTORS = ["fileExistsAtPath:", "fileExistsAtPath:isDirectory:", "isReadableFileAtPath:", "isWritableFileAtPath:",
                   "contentsOfDirectoryAtPath:error:", "attributesOfItemAtPath:error:", "canOpenURL:", "openURL:", "environment",
                   "isCaptured", "destinationOfSymbolicLinkAtPath:error:", "stringWithContentsOfFile:encoding:error:", "dataWithContentsOfFile:", "bundleIdentifier",
                   "writeToFile:atomically:encoding:error:", "isProtectedDataAvailable", "preferredLanguages"]
PROBE_LABEL = "File / process / environment probe API (in a function that also holds indicators)"
SVC_LABEL = "Inline syscall instruction (svc #0x80) - bypasses libc hooks"
MAX_CLASS_METHODS = 40


class Macho:
    def __init__(self, data: bytes):
        if data[:4] in (b"\xca\xfe\xba\xbe",):
            n = struct.unpack_from(">I", data, 4)[0]
            pick = None
            for i in range(n):
                ct, _cs, off, size, _al = struct.unpack_from(">5I", data, 8 + i * 20)
                if pick is None or ct == CPU_ARM64:
                    pick = (off, size)
            data = data[pick[0]:pick[0] + pick[1]]
        if data[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("not a 64-bit little-endian Mach-O")
        self.d = data
        self.cputype = struct.unpack_from("<I", data, 4)[0]
        ncmds = struct.unpack_from("<I", data, 16)[0]
        self.segs: List[Tuple[str, int, int, int, int]] = []   # name, vmaddr, vmsize, fileoff, filesize
        self.secs: List[Dict[str, Any]] = []
        self.symoff = self.nsyms = self.stroff = self.strsize = 0
        self.indirect_off = self.nindirect = 0
        self.fstarts_off = self.fstarts_size = 0
        self.chained = None
        self.encrypted = False
        self.base = 0
        off = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", data, off)
            if cmd == 0x19:
                nm = data[off + 8:off + 24].split(b"\0")[0].decode()
                va, vs, fo, fs, _mp, _ip, nsects, _fl = struct.unpack_from("<QQQQiiII", data, off + 24)
                self.segs.append((nm, va, vs, fo, fs))
                if nm == "__TEXT":
                    self.base = va
                for k in range(nsects):
                    so = off + 72 + k * 80
                    sn = data[so:so + 16].split(b"\0")[0].decode()
                    sg = data[so + 16:so + 32].split(b"\0")[0].decode()
                    addr, ssz, soff, _al, _ro, _nr, flags, r1, r2, _r3 = struct.unpack_from("<QQIIIIIIII", data, so + 32)
                    self.secs.append({"name": sn, "seg": sg, "addr": addr, "size": ssz, "off": soff,
                                      "type": flags & 0xff, "r1": r1, "r2": r2})
            elif cmd == 2:
                self.symoff, self.nsyms, self.stroff, self.strsize = struct.unpack_from("<IIII", data, off + 8)
            elif cmd == 0xb:
                self.indirect_off, self.nindirect = struct.unpack_from("<II", data, off + 56)
            elif cmd == 0x2c:
                self.encrypted = bool(struct.unpack_from("<I", data, off + 16)[0])
            elif cmd == 0x26:
                self.fstarts_off, self.fstarts_size = struct.unpack_from("<II", data, off + 8)
            elif cmd == 0x80000034:
                self.chained = struct.unpack_from("<II", data, off + 8)
            off += size
        self.fmt = self._chain_format()
        self.syms = self._symbols()
        self._starts: Optional[List[int]] = None
        self._symnames: Optional[Dict[int, str]] = None
        self.objc_imp: Dict[int, str] = {}

    # ---- addressing
    def sec(self, name):
        for s in self.secs:
            if s["name"] == name:
                return s
        return None

    def sec_at(self, va: int) -> Optional[Dict[str, Any]]:
        for s in self.secs:
            if s["addr"] <= va < s["addr"] + s["size"]:
                return s
        return None

    def v2o(self, va: int) -> Optional[int]:
        for nm, sva, vs, fo, fs in self.segs:
            if nm != "__PAGEZERO" and sva <= va < sva + min(vs, fs or vs):
                return fo + va - sva
        return None

    def o2v(self, off: int) -> Optional[int]:
        for nm, sva, _vs, fo, fs in self.segs:
            if nm not in ("__PAGEZERO", "__LINKEDIT") and fo <= off < fo + fs:
                return sva + off - fo
        return None

    def _chain_format(self) -> Optional[int]:
        if not self.chained:
            return None
        try:
            o = self.chained[0]
            starts = o + struct.unpack_from("<I", self.d, o + 4)[0]
            segc = struct.unpack_from("<I", self.d, starts)[0]
            for i in range(segc):
                so = struct.unpack_from("<I", self.d, starts + 4 + i * 4)[0]
                if so:
                    return struct.unpack_from("<H", self.d, starts + so + 6)[0]
        except Exception:
            pass
        return 6

    def decode(self, v: int) -> Optional[int]:
        f = self.fmt
        if v == 0:
            return None
        if f is None:
            return v
        if f in (2, 6):
            if v >> 63:
                return None
            t = v & 0xfffffffff
            return t + (self.base if f == 6 else 0)
        if f in (1, 9, 12):
            if (v >> 62) & 1:
                return None
            if v >> 63:
                return (v & 0xffffffff) + self.base
            t = v & 0x7ffffffffff
            return t + (self.base if f != 1 else 0)
        return None

    def u64(self, va: int) -> Optional[int]:
        o = self.v2o(va)
        return None if o is None or o + 8 > len(self.d) else struct.unpack_from("<Q", self.d, o)[0]

    def ptr(self, va: int) -> Optional[int]:
        v = self.u64(va)
        return None if v is None else self.decode(v)

    def cstr(self, va: Optional[int]) -> Optional[str]:
        if va is None:
            return None
        o = self.v2o(va)
        if o is None:
            return None
        e = self.d.find(b"\0", o, o + 400)
        return self.d[o:e if e != -1 else o + 400].decode("utf-8", "replace")

    # ---- tables
    def _symbols(self):
        out = []   # (name, value, ntype, sect)
        for i in range(self.nsyms):
            strx, ty, sect, _desc, val = struct.unpack_from("<IBBHQ", self.d, self.symoff + i * 16)
            e = self.d.find(b"\0", self.stroff + strx)
            out.append((self.d[self.stroff + strx:e].decode("latin-1"), val, ty, sect))
        return out

    def func_starts(self) -> List[int]:
        if self._starts is not None:
            return self._starts
        st: List[int] = []
        if self.fstarts_off:
            pos, end, cur = self.fstarts_off, self.fstarts_off + self.fstarts_size, self.base
            while pos < end:
                v, shift = 0, 0
                while True:
                    b = self.d[pos]
                    pos += 1
                    v |= (b & 0x7f) << shift
                    shift += 7
                    if not b & 0x80:
                        break
                if v == 0:
                    break
                cur += v
                st.append(cur)
        txt = self.sec("__text")
        lo, hi = (txt["addr"], txt["addr"] + txt["size"]) if txt else (0, 0)
        self._starts = sorted(set(st) | {v for n, v, t, s in self.syms if (t & 0xe) == 0xe and s and lo <= v < hi})
        return self._starts

    def func_at(self, addr: int) -> Tuple[int, str]:
        st = self.func_starts()
        i = bisect.bisect_right(st, addr) - 1
        start = st[i] if i >= 0 else addr
        nm = self.objc_imp.get(start)
        if nm is None:
            if self._symnames is None:
                self._symnames = {}
                for n, v, t, s in self.syms:
                    if (t & 0xe) == 0xe and s:
                        self._symnames.setdefault(v, n)
            nm = self._symnames.get(start)
        return start, nm or "sub_%x" % start

    def indirect_symbol(self, idx: int) -> Optional[str]:
        if idx >= self.nindirect:
            return None
        si = struct.unpack_from("<I", self.d, self.indirect_off + idx * 4)[0]
        if si & 0xC0000000 or si >= self.nsyms:
            return None
        return self.syms[si][0]

    def import_addrs(self) -> Dict[str, Dict[str, List[int]]]:
        """name -> {"stubs": [addr], "slots": [addr]}"""
        out: Dict[str, Dict[str, List[int]]] = {}
        for s in self.secs:
            if s["type"] == 8:
                stride = s["r2"] or 12
                for i in range(s["size"] // stride):
                    nm = self.indirect_symbol(s["r1"] + i)
                    if nm:
                        out.setdefault(nm, {"stubs": [], "slots": []})["stubs"].append(s["addr"] + i * stride)
            elif s["type"] in (6, 7):
                for i in range(s["size"] // 8):
                    nm = self.indirect_symbol(s["r1"] + i)
                    if nm:
                        out.setdefault(nm, {"stubs": [], "slots": []})["slots"].append(s["addr"] + i * 8)
        return out

    def code_words(self):
        out = []
        for s in self.secs:
            if s["name"] == "__text" and s["seg"] == "__TEXT":
                raw = self.d[s["off"]:s["off"] + s["size"]]
                a = array("I")
                a.frombytes(raw[: len(raw) // 4 * 4])
                out.append((s["addr"], a))
        return out

    def ptr_section(self, name: str) -> List[Tuple[int, Optional[int]]]:
        s = self.sec(name)
        if not s:
            return []
        return [(s["addr"] + i * 8, self.ptr(s["addr"] + i * 8)) for i in range(s["size"] // 8)]

    # ---- Objective-C metadata
    def method_list(self, ml: Optional[int]) -> List[Tuple[str, int]]:
        if not ml:
            return []
        o = self.v2o(ml)
        if o is None:
            return []
        flags, count = struct.unpack_from("<II", self.d, o)
        small = bool(flags & 0x80000000)
        ent = 12 if small else (flags & 0xfffc) or 24
        out = []
        for i in range(min(count, 20000)):
            ea = ml + 8 + i * ent
            eo = self.v2o(ea)
            if eo is None or eo + 24 > len(self.d):
                break
            if small:
                noff, _toff, ioff = struct.unpack_from("<iii", self.d, eo)
                nameaddr = ea + noff
                sec = self.sec_at(nameaddr)
                sel = self.cstr(self.ptr(nameaddr)) if sec and sec["name"] == "__objc_selrefs" else self.cstr(nameaddr)
                imp = ea + 8 + ioff
            else:
                sel = self.cstr(self.ptr(ea))
                imp = self.ptr(ea + 16)
            if sel and imp:
                out.append((sel, imp))
        return out

    def objc_classes(self) -> List[Dict[str, Any]]:
        res = []
        for sname in ("__objc_classlist", "__objc_nlclslist"):
            for _slot, cls in self.ptr_section(sname):
                if not cls:
                    continue
                try:
                    ro = self._ro(cls)
                    if not ro:
                        continue
                    name = self.cstr(self.ptr(ro + 24))
                    meta = self.ptr(cls)
                    mro = self._ro(meta) if meta else None
                    res.append({"addr": cls, "name": name or "?",
                                "inst": self.method_list(self.ptr(ro + 32)),
                                "cls": self.method_list(self.ptr(mro + 32)) if mro else []})
                except (struct.error, TypeError):
                    continue
        for _slot, cat in self.ptr_section("__objc_catlist"):
            if not cat:
                continue
            try:
                cname = self.cstr(self.ptr(cat)) or "?"
                cls = self.ptr(cat + 8)
                base = "?"
                if cls:
                    ro = self._ro(cls)
                    base = (self.cstr(self.ptr(ro + 24)) if ro else None) or "?"
                res.append({"addr": cat, "name": "%s(%s)" % (base, cname), "category": True,
                            "inst": self.method_list(self.ptr(cat + 16)), "cls": self.method_list(self.ptr(cat + 24))})
            except (struct.error, TypeError):
                continue
        for c in res:
            for sel, imp in c["inst"]:
                self.objc_imp[imp] = "-[%s %s]" % (c["name"], sel)
            for sel, imp in c["cls"]:
                self.objc_imp[imp] = "+[%s %s]" % (c["name"], sel)
        return res

    def _ro(self, cls: int) -> Optional[int]:
        bits = self.u64(cls + 32)
        if bits is None:
            return None
        v = self.decode(bits)
        if v is None:
            return None
        return v & 0x7ffffffffff8


def locate(path: str, rel: str, sigs, sdk: bool) -> List[Dict[str, Any]]:
    from .locate import rec
    with open(path, "rb") as fh:
        data = fh.read()
    m = Macho(data)
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(r):
        k = (r["indicator"], r["kind"], r["where"], r["address"])
        if k not in seen:
            seen.add(k)
            out.append(r)

    arm64 = m.cputype == CPU_ARM64 and not m.encrypted
    if m.encrypted:
        out.append(rec("", "", "note", rel, "FairPlay-encrypted binary: code cross-references (functions using each "
                       "string / import) are not available; scan a decrypted dump for them"))
    classes = m.objc_classes()                # also fills m.objc_imp (used to name functions)
    d = m.d
    linkedit = [(fo, fo + fs) for nm, _va, _vs, fo, fs in m.segs if nm == "__LINKEDIT"]

    # symbols
    for cat, label, needles in sigs:
        for nm, val, ty, sect in m.syms:
            if (ty & 0xe) == 0xe and sect and any(n in nm for n in needles):
                add(rec(cat, label, "native-symbol", rel, nm, val, "symbol table (defined)", sdk))
    # Objective-C classes / methods
    for cat, label, needles in sigs:
        for c in classes:
            cname_hit = any(n in c["name"] for n in needles)
            shown = 0
            for kind_ch, lst in (("-", c["inst"]), ("+", c["cls"])):
                for sel, imp in lst:
                    if any(n in sel for n in needles):
                        add(rec(cat, label, "objc-method", rel, "%s[%s %s]" % (kind_ch, c["name"], sel), imp,
                                "Objective-C method (selector matches)", sdk))
                    elif cname_hit and shown < MAX_CLASS_METHODS:
                        shown += 1
                        add(rec(cat, label, "objc-method", rel, "%s[%s %s]" % (kind_ch, c["name"], sel), imp,
                                "method of matching Objective-C class", sdk))
            if cname_hit:
                add(rec(cat, label, "objc-class", rel, c["name"], c["addr"],
                        "class metadata" + (" (category)" if c.get("category") else ""), sdk))

    # string occurrences -> addresses -> referencing functions
    occ = []
    for cat, label, needles in sigs:
        for n in needles:
            nb = n.encode()
            pos, cnt = d.find(nb), 0
            while pos != -1 and cnt < 20:
                va = m.o2v(pos)
                if va is not None and not any(a <= pos < b for a, b in linkedit):
                    st = pos
                    while st > 0 and pos - st < 512 and d[st - 1] != 0 and 32 <= d[st - 1] < 127:
                        st -= 1
                    occ.append((cat, label, n, va, m.o2v(st) or va))
                    cnt += 1
                pos = d.find(nb, pos + len(nb))
    targets_by_occ: Dict[int, List[Tuple[int, str]]] = {}    # target address -> [(occ index, what)]
    if occ:
        starts = {}
        for i, (_c, _l, _n, va, st) in enumerate(occ):
            starts.setdefault(st, []).append(i)
            starts.setdefault(va, []).append(i)
        for i, (_c, _l, _n, va, st) in enumerate(occ):
            targets_by_occ.setdefault(st, []).append((i, "string"))
            targets_by_occ.setdefault(va, []).append((i, "string"))
            # Swift string literals are materialised as (address + 0x20) and then adjusted by `sub x, x, #0x20`
            targets_by_occ.setdefault(st + 0x20, []).append((i, "Swift string literal"))
        cf = m.sec("__cfstring")
        if cf:
            for k in range(cf["size"] // 32):
                a = cf["addr"] + k * 32
                sp = m.ptr(a + 16)
                for i in starts.get(sp, []):
                    targets_by_occ.setdefault(a, []).append((i, "CFString"))
        for slot, sp in m.ptr_section("__objc_selrefs"):
            for i in starts.get(sp, []):
                targets_by_occ.setdefault(slot, []).append((i, "selector"))
    # classes matching by name: classrefs
    cls_by_addr = {}
    for cat, label, needles in sigs:
        for c in classes:
            if any(n in c["name"] for n in needles):
                cls_by_addr.setdefault(c["addr"], []).append((cat, label, c["name"]))
    cls_targets: Dict[int, List[Tuple[str, str, str]]] = {}
    if cls_by_addr:
        for slot, cp in m.ptr_section("__objc_classrefs") + m.ptr_section("__objc_superrefs"):
            if cp in cls_by_addr:
                cls_targets.setdefault(slot, []).extend(cls_by_addr[cp])

    # strings that live in data tables (Swift arrays of literals, inline small strings): find the table slot, then the
    # code that references the table (heuristic: nearest referenced address at or before the slot)
    data_hits: List[Tuple[int, int, str]] = []          # (address in data, occ index, how)
    if arm64 and occ:
        dranges = [(x["addr"], x["addr"] + x["size"]) for x in m.secs
                   if x["seg"] in ("__DATA", "__DATA_CONST") and not x["name"].startswith("__objc_")
                   and x["name"] not in ("__cfstring", "__got", "__auth_got", "__la_symbol_ptr")]
        want: Dict[int, int] = {}
        for i, (_c, _l, _n, va, st) in enumerate(occ):
            want.setdefault(st, i)
            want.setdefault(va, i)
            if any(lo <= va < hi for lo, hi in dranges):
                data_hits.append((va, i, "inline in data"))
        for x in m.secs:
            if not any(x["addr"] == lo for lo, _h in dranges):
                continue
            o = x["off"]
            for k in range(0, x["size"] - 7, 8):
                v = struct.unpack_from("<Q", d, o + k)[0]
                if v and ((v & 0xfffffffff) + m.base in want or (v & 0xfffffffff) in want or v in want):
                    t = m.decode(v) if m.fmt else v
                    for cand in (t, (v & 0xfffffffff) + m.base):
                        if cand in want:
                            data_hits.append((x["addr"] + k, want[cand], "pointer in data table"))
                            break
    sel_slots: Dict[int, str] = {}
    if arm64:
        for slot, sp in m.ptr_section("__objc_selrefs"):
            nm = m.cstr(sp)
            if nm in PROBE_SELECTORS:
                sel_slots[slot] = nm
    ctx: Dict[str, Dict[int, Tuple[str, set]]] = {}     # category -> function start -> (name, indicator labels)
    if arm64:
        words = m.code_words()
        all_t = set(targets_by_occ) | set(cls_targets) | set(sel_slots)
        refs = le.refs_arm64(None, all_t, words) if all_t else {}
        # Objective-C selector stubs (objc_msgSend$sel): a `bl` to the stub is a message send of that selector
        stub_slot: Dict[int, int] = {}
        for x in m.secs:
            if x["name"] == "__objc_stubs":
                for k in range(0, x["size"] - 31, 32):
                    w0, w1 = struct.unpack_from("<II", d, x["off"] + k)
                    if (w0 & 0x9f000000) == 0x90000000 and (w1 & 0xffc00000) == 0xf9400000:
                        pc0 = x["addr"] + k
                        page = (pc0 & ~0xfff) + (le._sx((((w0 >> 5) & 0x7ffff) << 2) | ((w0 >> 29) & 3), 21) << 12)
                        slot = page + (((w1 >> 10) & 0xfff) << 3)
                        if slot in all_t:
                            stub_slot[pc0] = slot
        if stub_slot:
            for stub, pcs in le.calls_arm64(None, set(stub_slot), words).items():
                refs.setdefault(stub_slot[stub], []).extend(pcs)
        for t, pcs in refs.items():
            for pc in pcs:
                fstart, fname = m.func_at(pc)
                for i, what in targets_by_occ.get(t, []):
                    cat, label, n = occ[i][0], occ[i][1], occ[i][2]
                    ctx.setdefault(cat, {}).setdefault(fstart, (fname, set()))[1].add(label)
                    add(rec(cat, label, "native-function", rel, fname, fstart,
                            'uses %s "%s" (reference at 0x%x)' % (what, n, pc), sdk))
                for cat, label, cname in cls_targets.get(t, []):
                    ctx.setdefault(cat, {}).setdefault(fstart, (fname, set()))[1].add(label)
                    add(rec(cat, label, "native-function", rel, fname, fstart,
                            "uses class %s (reference at 0x%x)" % (cname, pc), sdk))
    if arm64 and data_hits:
        import bisect
        table = le.data_refs_arm64(words, dranges)
        keys = [t for t, _pc in table]
        for addr, i, how in data_hits:
            j = bisect.bisect_right(keys, addr) - 1
            if j < 0 or addr - keys[j] > 0x600:
                continue
            tgt = keys[j]
            cat, label, n = occ[i][0], occ[i][1], occ[i][2]
            seen_f = set()
            while j >= 0 and keys[j] == tgt and len(seen_f) < 6:
                fstart, fname = m.func_at(table[j][1])
                if fstart not in seen_f:
                    seen_f.add(fstart)
                    ctx.setdefault(cat, {}).setdefault(fstart, (fname, set()))[1].add(label)
                    add(rec(cat, label, "native-function", rel, fname, fstart,
                            'table at 0x%x holds "%s" (%s, slot 0x%x; heuristic)' % (tgt, n, how, addr), sdk))
                j -= 1
    for i, (cat, label, n, va, st) in enumerate(occ):
        sec = m.sec_at(va)
        add(rec(cat, label, "native-string", rel, '"%s"' % n, va,
                "in %s" % (sec["name"] if sec else "data"), sdk))

    # probe APIs inside functions that also hold indicators
    def probe(fstart, fname, what):
        for cat, funcs in ctx.items():
            if fstart in funcs:
                add(rec(cat, PROBE_LABEL, "native-function", rel, fname, fstart,
                        "%s; function also references: %s" % (what, ", ".join(sorted(funcs[fstart][1])[:3])), sdk))

    if arm64:
        for t, pcs in refs.items():
            if t in sel_slots:
                for pc in pcs:
                    fstart, fname = m.func_at(pc)
                    probe(fstart, fname, "sends -%s at 0x%x" % (sel_slots[t], pc))
        imps = m.import_addrs()
        for nm, addrs in imps.items():
            specific = NATIVE_IMPORTS.get(nm)
            is_generic = nm in GENERIC_IMPORTS or any(p in nm for p in SUBSTR_IMPORTS)
            if not specific and not is_generic:
                continue
            st_set, slot_set = set(addrs["stubs"]), set(addrs["slots"])
            calls = le.calls_arm64(None, st_set, words) if st_set else {}
            irefs = le.refs_arm64(None, slot_set, words) if slot_set else {}
            fns = {}
            for pcs in list(calls.values()) + list(irefs.values()):
                for pc in pcs:
                    fstart, fname = m.func_at(pc)
                    fns.setdefault(fstart, (fname, pc))
            shown = nm[1:] if nm.startswith("_") else nm
            if specific:
                cat, label = specific
                add(rec(cat, label, "native-import", rel, shown, None, "imported symbol", sdk))
                for fstart, (fname, pc) in sorted(fns.items()):
                    add(rec(cat, label, "native-function", rel, fname, fstart, "calls %s at 0x%x" % (shown, pc), sdk))
            else:
                for fstart, (fname, pc) in sorted(fns.items()):
                    probe(fstart, fname, "calls %s() at 0x%x" % (shown if len(shown) < 60 else shown[:57] + "...", pc))
        fs = {}
        for pc in le.svc_sites(words, 0xD4001001):
            fstart, fname = m.func_at(pc)
            fs.setdefault(fstart, (fname, pc))
        for fstart, (fname, pc) in sorted(fs.items()):
            add(rec("hooking", SVC_LABEL, "native-function", rel, fname, fstart, "svc #0x80 at 0x%x" % pc, sdk))
    return out
