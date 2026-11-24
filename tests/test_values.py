import contextlib
import io
import os
import tempfile
import unittest

from appsleuth import cli, dataaudit

PREFS = ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>"
         "<string name=\"user_password\">hunter2</string><string name=\"theme\">dark</string>"
         "<string name=\"api_base\">https://api.example.com/v1</string></map>")


def audit(reveal=True):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "shared_prefs"))
    with open(os.path.join(d, "shared_prefs", "auth.xml"), "w") as fh:
        fh.write(PREFS)
    return d, dataaudit.audit_dir(d, "android", reveal=reveal)


class StoredValues(unittest.TestCase):
    def test_important_values_shown_others_hidden_until_all(self):
        _, res = audit()
        text = "\n".join(dataaudit.value_lines(res["meta"]))
        self.assertIn("user_password = hunter2", text)
        self.assertIn("api_base = https://api.example.com/v1", text)
        self.assertNotIn("theme", text)
        self.assertIn("theme = dark", "\n".join(dataaudit.value_lines(res["meta"], everything=True)))

    def test_redact(self):
        _, res = audit(reveal=False)
        self.assertNotIn("hunter2", "\n".join(dataaudit.value_lines(res["meta"], everything=True)))

    def test_cli_prints_values_by_default(self):
        d, _ = audit()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["--no-banner", "data", "--audit-dir", d, "--platform", "android"])
        self.assertIn("hunter2", out.getvalue())
        self.assertIn("Stored values", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["--no-banner", "data", "--audit-dir", d, "--platform", "android", "--redact"])
        self.assertNotIn("hunter2", out.getvalue())


if __name__ == "__main__":
    unittest.main()
