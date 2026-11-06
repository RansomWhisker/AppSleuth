import struct
import types
import unittest

from appsleuth import locate_macho, protections


def _thin_macho_with_codesig(blob: bytes) -> bytes:
    hdr = struct.pack("<IiiIIIII", 0xfeedfacf, 0x0100000C, 0, 6, 1, 16, 0, 0)
    sig_off = 32 + 16
    lc = struct.pack("<IIII", 0x1d, 16, sig_off, len(blob))
    return hdr + lc + blob


class CodeSignature(unittest.TestCase):
    def test_entitlements_in_code_signature_are_not_scanned(self):
        data = _thin_macho_with_codesig(b"<key>get-task-allow</key>")
        self.assertIn(b"get-task-allow", data)
        self.assertNotIn(b"get-task-allow", protections._strip_codesig(data))

    def test_non_macho_untouched(self):
        self.assertEqual(protections._strip_codesig(b"x" * 64), b"x" * 64)


class BenignDexNames(unittest.TestCase):
    def test_audio_flag_secure_is_not_screen_protection(self):
        self.assertTrue(protections._benign(b"FLAG_SECURE", "classes.dex", b"\x00\x0bFLAG_SECURE\x00\x10FLAG_SHOW"))
        self.assertFalse(protections._benign(b"FLAG_SECURE", "classes.dex", b"\x24USE_WINDOW_FLAG_SECURE_IN_ACTIVITIES\x00"))
        self.assertFalse(protections._benign(b"FLAG_SECURE", "index.android.bundle", b"AudioAttributesCompat"))

    def test_dbus_needle_no_longer_matches_bare_nul_auth(self):
        sig = next(s for s in protections.SIGS if s[1] == "D-Bus handshake probe (AUTH)")
        self.assertNotIn("\x00AUTH", sig[4])


class ExportTrie(unittest.TestCase):
    def test_exports_trie_symbols(self):
        root = bytes([0x00, 0x01]) + b"_foo\0" + bytes([8])
        child = bytes([0x02, 0x00, 0x10, 0x00])
        trie = root + child
        fake = types.SimpleNamespace(exports=(4, len(trie)), d=b"\0" * 4 + trie, base=0x100000000)
        self.assertEqual(locate_macho.Macho._export_trie(fake), [("_foo", 0x100000010)])


class Arm64LowParts(unittest.TestCase):
    def test_simd_and_byte_loads_complete_an_adrp_pair(self):
        from appsleuth.locate_elf import _lo12
        self.assertEqual(_lo12(0x3dc1a100, 8), 0x680)     # ldr q0, [x8, #0x680]
        self.assertEqual(_lo12(0xfd473500, 8), 0xe68)     # ldr d0, [x8, #0xe68]
        self.assertEqual(_lo12(0x39401500, 8), 5)         # ldrb w0, [x8, #5]
        self.assertEqual(_lo12(0x9110e100, 8), 0x438)     # add x0, x8, #0x438
        self.assertIsNone(_lo12(0x9110e100, 9))           # different base register


class X86VectorLoads(unittest.TestCase):
    def test_movaps_rip_relative_is_a_reference(self):
        from appsleuth import locate_elf
        code = b"\x90" * 4 + b"\x0f\x28\x05" + struct.pack("<i", 0x100 - (0x1000 + 4 + 7))
        fake = types.SimpleNamespace(d=code)
        orig = locate_elf._exec_sections
        locate_elf._exec_sections = lambda e: [{"off": 0, "size": len(code), "addr": 0x1000}]
        try:
            self.assertEqual(locate_elf.refs_x86(fake, {0x100}), {0x100: [0x1004]})
        finally:
            locate_elf._exec_sections = orig


class ZeroFillSections(unittest.TestCase):
    def test_bss_has_no_file_bytes(self):
        # header + LC_SEGMENT_64 __DATA with one __bss (S_ZEROFILL) section whose size runs past the file end
        sect = b"__bss".ljust(16, b"\0") + b"__DATA".ljust(16, b"\0") + struct.pack("<QQIIIIIIII", 0x4000, 0x10000, 0, 0, 0, 0, 0x1, 0, 0, 0)
        seg = struct.pack("<II", 0x19, 72 + 80) + b"__DATA".ljust(16, b"\0") + struct.pack("<QQQQiiII", 0x4000, 0x10000, 0, 0, 3, 3, 1, 0)
        hdr = struct.pack("<IiiIIIII", 0xfeedfacf, 0x0100000C, 0, 6, 1, len(seg + sect), 0, 0)
        m = locate_macho.Macho(hdr + seg + sect)
        self.assertEqual(m.sec("__bss")["fsize"], 0)
