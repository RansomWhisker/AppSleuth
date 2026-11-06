import unittest
from array import array

from appsleuth import info, locate, locate_elf, locate_macho


class NativeXrefs(unittest.TestCase):
    def test_arm64_adrp_add_reference(self):
        words = [(0x1000, array("I", [0xB0000000, 0x91004000]))]    # adrp x0,+0x1000 ; add x0,x0,#0x10
        self.assertEqual(locate_elf.refs_arm64(None, {0x2010}, words), {0x2010: [0x1000]})
        self.assertEqual(locate_elf.refs_arm64(None, {0x2020}, words), {})

    def test_arm64_bl_call_site(self):
        words = [(0x2000, array("I", [0x94000400]))]               # bl +0x1000
        self.assertEqual(locate_elf.calls_arm64(None, {0x3000}, words), {0x3000: [0x2000]})

    def test_macho_pointer_decoding(self):
        m = locate_macho.Macho.__new__(locate_macho.Macho)
        m.fmt, m.base = 6, 0x100000000
        self.assertIsNone(m.decode(0))                             # null stays null
        self.assertEqual(m.decode(0x1234), 0x100001234)            # rebase = offset + image base
        self.assertIsNone(m.decode(1 << 63))                       # bind
        m.fmt = None
        self.assertEqual(m.decode(0x100001234), 0x100001234)


class ProbeCoverage(unittest.TestCase):
    def test_signatures_cover_dopamine_frida_magisk_paths(self):
        ios = {n for _c, _l, ns in locate.sigs_for("ios") for n in ns}
        android = {n for _c, _l, ns in locate.sigs_for("android") for n in ns}
        self.assertTrue({"Dopamine", "/var/jb/", "palera1n", "/Applications/Cydia.app", "/usr/sbin/frida-server"} <= ios)
        self.assertTrue({"/data/adb/magisk", "/sbin/.magisk", "KernelSU", "/data/local/tmp/frida-server"} <= android)

    def test_data_table_refs(self):
        words = [(0x1000, array("I", [0xB0000000, 0x91004000]))]    # adrp x0,+0x1000 ; add x0,x0,#0x10 -> 0x2010
        self.assertEqual(locate_elf.data_refs_arm64(words, [(0x2000, 0x3000)]), [(0x2010, 0x1000)])
        self.assertEqual(locate_elf.data_refs_arm64(words, [(0x5000, 0x6000)]), [])

    def test_java_probe_table_is_well_formed(self):
        for cat, label, kind, sigs in locate.JAVA_PROBES:
            self.assertIn(kind, ("m", "f"))
            for sg in sigs:
                self.assertRegex(sg, r"^L[\w/$]+;->[\w<>]+$")


class Records(unittest.TestCase):
    def test_text_hit_has_line_and_offset(self):
        sigs = [("root", "su binary probes", ["/system/xbin/su"])]
        r = locate.locate_text("x.js", "www/app.js", sigs, b"a\nb\nvar p='/system/xbin/su';")
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["kind"], "file-string")
        self.assertIn("line 3", r[0]["where"])
        self.assertEqual(r[0]["file"], "www/app.js")

    def test_signatures_include_dotted_class_form(self):
        ns = [n for c, l, ns in locate.sigs_for("android") if l == "RootBeer library" for n in ns]
        self.assertIn("com/scottyab/rootbeer", ns)
        self.assertIn("com.scottyab.rootbeer", ns)

    def test_render_groups_by_category_and_caps(self):
        recs = [locate.rec("root", "RootBeer library", "java-method", "classes.dex", "Lcom/x/A;->m%d()" % i,
                           None, "uses string \"x\"") for i in range(info.LOC_LIMIT + 5)]
        recs.append(locate.rec("root", "RootBeer library", "native-function", "lib/a.so", "sub_10", 0x10, "calls ptrace"))
        recs.append(locate.rec("", "", "note", "App", "encrypted"))
        text = "\n".join(info.location_lines(recs, "android"))
        self.assertIn("Root detection", text)
        self.assertIn("and 6 more", text)            # 31 records -> 30 shown
        self.assertIn("encrypted", text)


if __name__ == "__main__":
    unittest.main()
