"""End-to-end smoke tests on tiny synthetic apps (catches OS-specific path bugs in CI)."""
import contextlib
import io
import json
import os
import tempfile
import unittest

from appsleuth import cli
from tests.test_diff import mk_ipa


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cli.main(list(argv))
        except SystemExit as e:
            code = e.code or 0
    return code, out.getvalue(), err.getvalue()


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.a = os.path.join(self.d, "a.ipa")
        self.b = os.path.join(self.d, "b.ipa")
        mk_ipa(self.a, version="1", files={"public/app.js": b"var x=1;"})
        mk_ipa(self.b, version="2", perms=["NSCameraUsageDescription"], schemes=["myapp"],
               files={"public/app.js": b"var x=2;"})

    def test_scan_writes_reports(self):
        out = os.path.join(self.d, "r")
        code, text, _ = run("scan", self.a, "-o", out)
        self.assertEqual(code, 0, text)
        with open(os.path.join(out, "report.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["meta"]["bundle_id"], "com.t.app")
        for f in ("report.md", "report.html"):
            self.assertTrue(os.path.getsize(os.path.join(out, f)) > 0)

    def test_info(self):
        code, text, _ = run("info", self.b)
        self.assertEqual(code, 0)
        self.assertIn("com.t.app", text)

    def test_diff(self):
        code, text, _ = run("diff", self.a, self.b, "-o", os.path.join(self.d, "dd"))
        self.assertEqual(code, 0, text)
        self.assertIn("1 → 2", text)


if __name__ == "__main__":
    unittest.main()
