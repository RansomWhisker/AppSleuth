import os
import plistlib
import tempfile
import unittest
import zipfile

from appsleuth import diff as D


def mk_ipa(path, *, version, perms=(), schemes=(), min_os="15.0", files=None):
    info = {"CFBundleIdentifier": "com.t.app", "CFBundleExecutable": "App", "CFBundleShortVersionString": version,
            "CFBundleVersion": version, "MinimumOSVersion": min_os}
    for p in perms:
        info[p] = "why"
    if schemes:
        info["CFBundleURLTypes"] = [{"CFBundleURLSchemes": list(schemes)}]
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/App.app/Info.plist", plistlib.dumps(info))
        z.writestr("Payload/App.app/App", b"\xcf\xfa\xed\xfe" + b"\0" * 64)
        for n, data in (files or {}).items():
            z.writestr("Payload/App.app/" + n, data)


class ArtifactDiff(unittest.TestCase):
    def test_categories_and_rename_proof(self):
        d = tempfile.mkdtemp()
        a, b = os.path.join(d, "a.ipa"), os.path.join(d, "b.ipa")
        mk_ipa(a, version="1", files={"public/app.js": b"1", "Frameworks/X.framework/X": b"x"})
        mk_ipa(b, version="2", files={"public/app.js": b"22", "public/new.js": b"n"})
        r = D.artifact_diff(a, b, "ipa")
        self.assertEqual(r["added"], ["public/new.js"])
        self.assertEqual(r["removed"], ["Frameworks/X.framework/X"])
        self.assertIn("public/app.js", r["modified"])
        self.assertIn("web layer", r["by_category"])


class Regressions(unittest.TestCase):
    base = {"platform": "ios", "id": "x", "flags": {}, "signer": {"team_id": "AAA"}, "min_os": "15.0"}

    def run_reg(self, old, new):
        o, n = dict(self.base, **old), dict(self.base, **new)
        p = D.posture_diff(o, n)
        return D.regressions(o, n, p, {"new": [], "resolved": [], "severity_changed": []})

    def test_signer_and_flags(self):
        regs = self.run_reg({}, {"signer": {"team_id": "BBB"}, "flags": {"ats_disabled": True}})
        self.assertEqual({r["severity"] for r in regs}, {"HIGH"})
        self.assertEqual(len(regs), 2)

    def test_min_os_float_versions(self):
        regs = self.run_reg({"min_os": "15.6"}, {"min_os": "14.0"})
        self.assertIn("Minimum OS lowered: 15.6 -> 14.0", regs[0]["text"])

    def test_improvement_is_not_regression(self):
        self.assertEqual(self.run_reg({"flags": {"ats_disabled": True}}, {"flags": {}}), [])

    def test_fingerprint_ignores_filename_and_counts(self):
        a = {"title": "44 high-entropy string(s)", "location": "old-1.0.apk:dex (classes.dex) [Lx;->y]"}
        b = {"title": "47 high-entropy string(s)", "location": "new-2.0.apk:dex (classes.dex) [Lz;->w]"}
        self.assertEqual(D._fp(a), D._fp(b))


if __name__ == "__main__":
    unittest.main()
