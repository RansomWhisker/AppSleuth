"""ELF (Android .so) provider for locate.py: symbols, string addresses, referencing functions, import call sites.
Full cross-reference support for 64-bit ARM (adrp+add/ldr, bl) and x86-64 (rip-relative lea, call); other machines
get symbols and string offsets only."""
from __future__ import annotations

import struct
from array import array
from typing import Any, Dict, List, Optional, Tuple

EM_X86_64, EM_AARCH64 = 62, 183
# imported functions that checks commonly call; reported with every call site
# occurrences of one needle followed per binary (references); only the first MAX_STR_SHOWN are listed as strings
MAX_OCC = 400
MAX_STR_SHOWN = 20

NATIVE_IMPORTS = {
    "ptrace": ("debugger", "Native import: ptrace (anti-debug)"),
}
# libc functions that implement file / process / environment probes; reported only for a function that also
# references an indicator string of some category (e.g. access() next to "/system/xbin/su")
GENERIC_IMPORTS = ["access", "faccessat", "stat", "lstat", "fstatat", "__xstat", "stat64", "fopen", "open", "openat", "opendir",
                   "readdir", "readlink", "realpath", "statfs", "popen", "system", "execve", "execl", "execv", "execvp",
                   "getenv", "dlopen", "dlsym", "syscall", "inotify_add_watch", "fork", "kill", "getppid", "__system_property_get",
                   "clock_gettime", "mprotect", "connect", "socket", "memcmp"]
PROBE_LABEL = "File / process / environment probe API (in a function that also holds indicators)"
SVC_LABEL = "Inline syscall instruction (svc) - bypasses libc hooks"


def svc_sites(words, imm_word: int) -> List[int]:
    out = []
    for base, a in words:
        for i in range(len(a)):
            if a[i] == imm_word:
                out.append(base + i * 4)
    return out


class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a little-endian ELF64")
        self.d = data
        (_t, self.machine, _v, self.entry, phoff, shoff, _fl, _eh, phentsize, phnum,
         shentsize, shnum, shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        self.segs = []   # (vaddr, off, filesz, flags)
        for i in range(phnum):
            pt, fl, off, va, _pa, fsz, _ms, _al = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
            if pt == 1:
                self.segs.append((va, off, fsz, fl))
        self.secs = []   # dict per section
        for i in range(shnum):
            n, ty, fl, addr, off, size, link, info, _al, ent = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
            fsize = 0 if ty == 8 else max(0, min(size, len(data) - off))     # NOBITS (.bss) has no file bytes
            self.secs.append({"name_off": n, "type": ty, "flags": fl, "addr": addr, "off": off, "size": size,
                              "fsize": fsize, "link": link, "info": info, "ent": ent})
        if shnum and shstrndx < shnum:
            so = self.secs[shstrndx]["off"]
            for s in self.secs:
                e = data.find(b"\0", so + s["name_off"])
                s["name"] = data[so + s["name_off"]:e].decode("latin-1")
        for s in self.secs:
            s.setdefault("name", "")
        self.syms = self._symbols()
        self._starts = None

    def sec(self, name):
        for s in self.secs:
            if s["name"] == name:
                return s
        return None

    def v2o(self, va: int) -> Optional[int]:
        for sva, off, fsz, _f in self.segs:
            if sva <= va < sva + fsz:
                return off + va - sva
        return None

    def o2v(self, off: int) -> Optional[int]:
        for sva, soff, fsz, _f in self.segs:
            if soff <= off < soff + fsz:
                return sva + off - soff
        return None

    def _symbols(self):
        out = []   # (name, value, size, type, shndx, bind, dynamic)
        for s in self.secs:
            if s["type"] not in (2, 11):      # SYMTAB, DYNSYM
                continue
            strs = self.secs[s["link"]]
            for i in range(s["fsize"] // 24):
                no, info, _o, shndx, val, size = struct.unpack_from("<IBBHQQ", self.d, s["off"] + i * 24)
                e = self.d.find(b"\0", strs["off"] + no)
                nm = self.d[strs["off"] + no:e].decode("latin-1")
                if nm:
                    out.append((nm, val, size, info & 15, shndx, info >> 4, s["type"] == 11))
        return out

    def func_starts(self) -> List[int]:
        if self._starts is not None:
            return self._starts
        starts = set()
        h = self.sec(".eh_frame_hdr")
        if h and h["size"] > 12:
            o = h["off"]
            ver, _ep, fcp, tbl = struct.unpack_from("<BBBB", self.d, o)
            if ver == 1 and tbl == 0x3b:
                pos = o + 4 + 4                              # skip eh_frame_ptr (sdata4)
                if fcp == 0x03:
                    cnt = struct.unpack_from("<I", self.d, pos)[0]
                    pos += 4
                elif fcp == 0x1b:
                    pos += 4
                    cnt = struct.unpack_from("<I", self.d, o + 8)[0]
                else:
                    cnt = 0
                for i in range(min(cnt, 2_000_000, max(0, (len(self.d) - pos) // 8))):
                    loc = struct.unpack_from("<i", self.d, pos + i * 8)[0]
                    starts.add(h["addr"] + loc)
        for nm, val, _sz, ty, shndx, _b, _dyn in self.syms:
            if ty == 2 and shndx:
                starts.add(val & ~1)
        self._starts = sorted(starts)
        return self._starts

    def func_at(self, addr: int) -> Tuple[int, str]:
        import bisect
        st = self.func_starts()
        i = bisect.bisect_right(st, addr) - 1
        start = st[i] if i >= 0 else addr
        names = getattr(self, "_names", None)
        if names is None:
            names = self._names = {}
            for nm, val, _s, ty, shndx, _b, _d in self.syms:
                if ty == 2 and shndx:
                    names.setdefault(val & ~1, nm)
        return start, names.get(start, "sub_%x" % start)


def _exec_sections(e: Elf):
    return [s for s in e.secs if s["flags"] & 4 and s["type"] == 1 and s["addr"]]


def _code_words(e: Elf):
    """-> list of (addr, array('I')) for executable sections (arm64)."""
    out = []
    for s in _exec_sections(e):
        raw = e.d[s["off"]:s["off"] + s["size"]]
        raw = raw[: len(raw) // 4 * 4]
        a = array("I")
        a.frombytes(raw)
        out.append((s["addr"], a))
    return out


def _sx(v: int, bits: int) -> int:
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def _lo12(w2: int, rd: int) -> Optional[int]:
    """Low part of an adrp pair: add-immediate, or any load (GPR or SIMD b/h/s/d/q, ldr or ldp) based on rd.
    SIMD loads of string bytes (ldr q0, [x8, #lo]) are how compilers inline short string compares."""
    if ((w2 >> 5) & 31) != rd:
        return None
    if (w2 & 0xff800000) == 0x91000000:                                   # add xd, xn, #imm{, lsl 12}
        return ((w2 >> 10) & 0xfff) << (12 if (w2 >> 22) & 1 else 0)
    if (w2 & 0x3b000000) == 0x39000000 and (w2 >> 22) & 1:               # ldr* [xn, #imm12] (unsigned offset)
        size, v, opc = w2 >> 30, (w2 >> 26) & 1, (w2 >> 22) & 3
        scale = (((opc >> 1) << 2) | size) if v else size
        return ((w2 >> 10) & 0xfff) << scale
    if (w2 & 0x3bc00000) == 0x29400000:                                   # ldp [xn, #imm7] (signed offset)
        opc, v = w2 >> 30, (w2 >> 26) & 1
        scale = (2 + opc) if v else (2 + (opc >> 1))
        lo = _sx((w2 >> 15) & 0x7f, 7) << scale
        return lo if lo >= 0 else None
    return None


def refs_arm64(e, targets: set, words=None) -> Dict[int, List[int]]:
    """target address -> [instruction addresses] using adrp+add / adrp+ldr pairs."""
    pages = {t & ~0xfff for t in targets}
    hits: Dict[int, List[int]] = {}
    for base, a in (words if words is not None else _code_words(e)):
        n = len(a)
        for i in range(n):
            w = a[i]
            if (w & 0x9f000000) != 0x90000000:
                continue
            pc = base + i * 4
            imm = _sx((((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3), 21) << 12
            page = (pc & ~0xfff) + imm
            if page not in pages:
                continue
            rd = w & 31
            for j in range(i + 1, min(i + 13, n)):
                lo = _lo12(a[j], rd)
                if lo is None:
                    continue
                t = page + lo
                if t in targets:
                    hits.setdefault(t, []).append(pc)
                break
    return hits


def data_refs_arm64(words, ranges) -> List[Tuple[int, int]]:
    """Every adrp+add / adrp+ldr whose target lies inside one of the (lo, hi) ranges -> sorted [(target, pc)]."""
    pages = set()
    for lo, hi in ranges:
        pages.update(range(lo & ~0xfff, hi, 0x1000))
    out: List[Tuple[int, int]] = []
    for base, a in words:
        n = len(a)
        for i in range(n):
            w = a[i]
            if (w & 0x9f000000) != 0x90000000:
                continue
            pc = base + i * 4
            page = (pc & ~0xfff) + (_sx((((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3), 21) << 12)
            if page not in pages:
                continue
            rd = w & 31
            for j in range(i + 1, min(i + 13, n)):
                lo = _lo12(a[j], rd)
                if lo is not None:
                    out.append((page + lo, pc))
                    break
    out.sort()
    return out


def calls_arm64(e, targets: set, words=None) -> Dict[int, List[int]]:
    hits: Dict[int, List[int]] = {}
    for base, a in (words if words is not None else _code_words(e)):
        for i in range(len(a)):
            w = a[i]
            if (w & 0x7c000000) == 0x14000000:           # b / bl
                t = base + i * 4 + (_sx(w & 0x3ffffff, 26) << 2)
                if t in targets:
                    hits.setdefault(t, []).append(base + i * 4)
    return hits


def refs_x86(e: Elf, targets: set) -> Dict[int, List[int]]:
    import re
    rip = rb"[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]"          # ModRM mod=00 rm=101: [rip + disp32]
    pats = [
        re.compile(rb"[\x40-\x4f]?\x8d" + rip, re.S),                       # lea
        re.compile(rb"[\x40-\x4f]?\x8b" + rip, re.S),                       # mov r, [rip+x]
        # two-byte opcodes without an immediate: movaps / movups / movdqa / movdqu / movzx / pcmpeqb / ptest ...
        # (vector loads of string bytes are how compilers inline short string compares)
        re.compile(rb"[\x66\xf2\xf3]?[\x40-\x4f]?\x0f[\x10\x11\x12\x16\x28\x29\x2e\x2f\x6f\x7e\x7f\xb6\xb7\xbe\xbf"
                   rb"\x74\x75\x76\xd6\xdb\xeb\xef\xfc-\xfe\xd4\xf8-\xfb]" + rip, re.S),
    ]
    hits: Dict[int, List[int]] = {}
    for s in _exec_sections(e):
        raw = e.d[s["off"]:s["off"] + s["size"]]
        for pat in pats:
            for m in pat.finditer(raw):
                p = m.end()
                if p + 4 > len(raw):
                    continue
                disp = struct.unpack_from("<i", raw, p)[0]
                t = s["addr"] + p + 4 + disp
                if t in targets:
                    hits.setdefault(t, []).append(s["addr"] + m.start())
    for t in hits:
        hits[t] = sorted(set(hits[t]))
    return hits


def calls_x86(e: Elf, targets: set) -> Dict[int, List[int]]:
    import re
    hits: Dict[int, List[int]] = {}
    for s in _exec_sections(e):
        raw = e.d[s["off"]:s["off"] + s["size"]]
        for m in re.finditer(rb"[\xe8\xe9]", raw):
            p = m.end()
            if p + 4 > len(raw):
                continue
            t = s["addr"] + p + 4 + struct.unpack_from("<i", raw, p)[0]
            if t in targets:
                hits.setdefault(t, []).append(s["addr"] + m.start())
    return hits


def got_slots(e: Elf) -> Dict[str, List[int]]:
    """imported symbol name -> GOT slot addresses (from .rela.plt and .rela.dyn)."""
    dyn = [s for s in e.secs if s["type"] == 11]
    if not dyn:
        return {}
    ds = dyn[0]
    strs = e.secs[ds["link"]]
    out: Dict[str, List[int]] = {}
    for s in e.secs:
        if s["type"] != 4:
            continue
        for i in range(s["fsize"] // 24):
            off, info, _ad = struct.unpack_from("<QQq", e.d, s["off"] + i * 24)
            sym, ty = info >> 32, info & 0xffffffff
            if not sym or ty not in (1025, 1026, 6, 7, 257):   # JUMP_SLOT/GLOB_DAT (aarch64 / x86-64)
                continue
            no = struct.unpack_from("<I", e.d, ds["off"] + sym * 24)[0]
            nm = e.d[strs["off"] + no:e.d.find(b"\0", strs["off"] + no)].decode("latin-1")
            out.setdefault(nm, []).append(off)
    return out


def plt_stubs(e: Elf) -> Dict[int, int]:
    """plt stub address -> GOT slot address."""
    out: Dict[int, int] = {}
    for s in e.secs:
        if not s["name"].startswith(".plt"):
            continue
        raw = e.d[s["off"]:s["off"] + s["size"]]
        if e.machine == EM_AARCH64:
            for k in range(0, len(raw) - 7, 4):
                w, w2 = struct.unpack_from("<II", raw, k)
                if (w & 0x9f000000) == 0x90000000 and (w2 & 0xffc00000) == 0xf9400000:
                    pc = s["addr"] + k
                    imm = _sx((((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3), 21) << 12
                    out[pc] = ((pc & ~0xfff) + imm) + (((w2 >> 10) & 0xfff) << 3)
        elif e.machine == EM_X86_64:
            for k in range(0, len(raw) - 5, 1):
                if raw[k] == 0xff and raw[k + 1] == 0x25:
                    slot = s["addr"] + k + 6 + struct.unpack_from("<i", raw, k + 2)[0]
                    out[s["addr"] + (k // 16) * 16] = slot
    return out


def locate(path: str, rel: str, sigs, sdk: bool) -> List[Dict[str, Any]]:
    from .locate import rec
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        e = Elf(data)
    except Exception:
        return _strings_only(data, rel, sigs, sdk)
    out: List[Dict[str, Any]] = []
    seen: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    ctx: Dict[str, Dict[int, Tuple[str, set]]] = {}      # category -> function start -> (name, indicator labels)

    def add(r):
        k = (r["indicator"], r["kind"], r["where"], r["address"])
        old = seen.get(k)
        if old is None:
            seen[k] = r
            out.append(r)
        elif r["kind"] == "native-function" and r["via"] not in old["via"] and len(old["via"]) < 400:
            old["via"] += "; " + r["via"]          # same function, another reason (e.g. a second needle)

    jni = lambda n: n.replace("/", "_").replace(".", "_")
    # symbols (exported = in .dynsym and defined; internal = only in .symtab)
    for cat, label, needles in sigs:
        variants = needles + [jni(n) for n in needles if "/" in n or "." in n]
        for nm, val, size, ty, shndx, bind, dynamic in e.syms:
            if not shndx or ty not in (1, 2):
                continue
            if any(v in nm for v in variants):
                add(rec(cat, label, "native-symbol", rel, nm, val,
                        "%s %s (%d bytes)" % ("exported" if dynamic else "internal",
                                              "function" if ty == 2 else "data", size), sdk))
    # strings: address + referencing functions
    strtab_ranges = [(s["off"], s["off"] + s["size"]) for s in e.secs if s["type"] == 3]
    occ: List[Tuple[str, str, str, int, int]] = []      # cat, label, needle, file offset, vaddr of string start
    for cat, label, needles in sigs:
        for n in needles:
            nb = n.encode()
            pos, cnt = data.find(nb), 0
            while pos != -1 and cnt < MAX_OCC:
                if not any(a <= pos < b for a, b in strtab_ranges):
                    va = e.o2v(pos)
                    if va is not None:
                        st = pos
                        while st > 0 and pos - st < 512 and data[st - 1] != 0 and (32 <= data[st - 1] < 127 or data[st - 1] in (9, 10, 13)):
                            st -= 1
                        en, odd = pos + len(nb), 0          # C string: NUL within 256 bytes, at most 4 non-text bytes
                        while en < len(data) and en - pos < 256 and data[en] != 0:
                            odd += not (32 <= data[en] < 127 or data[en] in (9, 10, 13))
                            en += 1
                        if odd > 4:
                            en = len(data)
                        if en >= len(data) or data[en] != 0:     # packed / unterminated blob: only the exact address
                            st = pos
                        occ.append((cat, label, n, pos, e.o2v(st) or va))
                        cnt += 1
                pos = data.find(nb, pos + len(nb))
    if occ:
        def span(o):
            va = e.o2v(o[3])
            # packed strings (Rust, obfuscators): code may point anywhere between the run's start and the needle
            return set(range(o[4], va + 1)) if va is not None and 0 <= va - o[4] <= 256 else {o[4], va}
        targets = set().union(*(span(o) for o in occ)) - {None}
        if e.machine == EM_AARCH64:
            refs = refs_arm64(e, targets)
        elif e.machine == EM_X86_64:
            refs = refs_x86(e, targets)
        else:
            refs = {}
        shown_n: Dict[Tuple[str, str], int] = {}
        for cat, label, n, pos, st in occ:
            va = e.o2v(pos)
            shown_n[(label, n)] = shown_n.get((label, n), 0) + 1
            if shown_n[(label, n)] <= MAX_STR_SHOWN:
                add(rec(cat, label, "native-string", rel, '"%s"' % n, va, "in read-only data", sdk))
            fns: Dict[int, Tuple[str, int]] = {}
            for t in sorted(span((cat, label, n, pos, st)) - {None}):
                for pc in refs.get(t, []):
                    fstart, fname = e.func_at(pc)
                    fns.setdefault(fstart, (fname, pc))
            for fstart, (fname, pc) in sorted(fns.items()):
                ctx.setdefault(cat, {}).setdefault(fstart, (fname, set()))[1].add(label)
                add(rec(cat, label, "native-function", rel, fname, fstart,
                        'references "%s" at 0x%x' % (n, pc), sdk))
    # imported functions that implement checks, with call sites
    if e.machine in (EM_AARCH64, EM_X86_64):
        slots = got_slots(e)
        generic = [n for n in GENERIC_IMPORTS if n in slots]
        # imported functions whose name is itself an indicator
        needle_imps: Dict[str, List[Tuple[str, str]]] = {}
        for cat, label, needles in sigs:
            for nm in slots:
                if any(n in nm for n in needles):
                    needle_imps.setdefault(nm, []).append((cat, label))
        wanted = list(dict.fromkeys([n for n in NATIVE_IMPORTS if n in slots] + generic + list(needle_imps)))
        if wanted:
            stubs = plt_stubs(e)
            plt = [(x["addr"], x["addr"] + x["size"]) for x in e.secs if x["name"].startswith(".plt")]
            for nm in wanted:
                slot_set = set(slots[nm])
                stub_set = {s2 for s2, g in stubs.items() if g in slot_set}
                call = (calls_arm64 if e.machine == EM_AARCH64 else calls_x86)(e, stub_set) if stub_set else {}
                ref = (refs_arm64 if e.machine == EM_AARCH64 else refs_x86)(e, slot_set)
                fns = {}
                for pcs in list(call.values()) + list(ref.values()):
                    for pc in pcs:
                        if any(a <= pc < b for a, b in plt):
                            continue          # the PLT stub itself, not a caller
                        fstart, fname = e.func_at(pc)
                        fns.setdefault(fstart, (fname, pc))
                pairs = ([NATIVE_IMPORTS[nm]] if nm in NATIVE_IMPORTS else []) + needle_imps.get(nm, [])
                for cat, label in pairs:
                    add(rec(cat, label, "native-import", rel, nm, None, "imported symbol", sdk))
                    for fstart, (fname, pc) in sorted(fns.items()):
                        add(rec(cat, label, "native-function", rel, fname, fstart, "calls %s at 0x%x" % (nm, pc), sdk))
                if nm in generic and nm not in NATIVE_IMPORTS:
                    for cat, funcs in ctx.items():
                        for fstart, (fname, pc) in sorted(fns.items()):
                            if fstart in funcs:
                                add(rec(cat, PROBE_LABEL, "native-function", rel, fname, fstart,
                                        "calls %s() at 0x%x; function also references: %s" %
                                        (nm, pc, ", ".join(sorted(funcs[fstart][1])[:3])), sdk))
        if e.machine == EM_X86_64:
            seen_f = {}
            for sec in _exec_sections(e):
                raw = e.d[sec["off"]:sec["off"] + sec["size"]]
                p0 = raw.find(b"\x0f\x05")
                while p0 != -1:
                    fstart, fname = e.func_at(sec["addr"] + p0)
                    seen_f.setdefault(fstart, (fname, sec["addr"] + p0))
                    p0 = raw.find(b"\x0f\x05", p0 + 2)
            for fstart, (fname, pc) in sorted(seen_f.items()):
                add(rec("hooking", SVC_LABEL, "native-function", rel, fname, fstart, "syscall at 0x%x (byte-pattern match)" % pc, sdk))
        if e.machine == EM_AARCH64:
            seen_f = {}
            for pc in svc_sites(_code_words(e), 0xD4000001):
                fstart, fname = e.func_at(pc)
                seen_f.setdefault(fstart, (fname, pc))
            for fstart, (fname, pc) in sorted(seen_f.items()):
                add(rec("hooking", SVC_LABEL, "native-function", rel, fname, fstart, "svc #0 at 0x%x" % pc, sdk))
    return out


def _strings_only(data: bytes, rel: str, sigs, sdk: bool) -> List[Dict[str, Any]]:
    from .locate import rec
    out = []
    for cat, label, needles in sigs:
        for n in needles:
            pos = data.find(n.encode())
            if pos != -1:
                out.append(rec(cat, label, "native-string", rel, '"%s"' % n, None,
                               "file offset 0x%x (32-bit / unsupported ELF: no cross-references)" % pos, sdk))
    return out
