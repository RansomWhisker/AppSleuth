import os
import plistlib
import tempfile
import unittest
import zipfile

from appsleuth import cli, shell


def completer(target=None):
    st = {"target": target}
    return shell.Completer(cli.build_parser(), st), st


class Completion(unittest.TestCase):
    def test_commands_flags_and_choices(self):
        c, _ = completer()
        self.assertIn("runtime ", c._candidates("", "ru"))
        self.assertIn("files ", c._candidates("", "fi"))
        self.assertIn("--dump-crypto ", c._candidates("runtime --android ", "--du"))
        self.assertIn("HIGH ", c._candidates("scan app.ipa --fail-on ", "H"))
        self.assertIn("--search ", c._candidates("files ", "--se"))

    def test_package_entries_complete_for_files(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "t.ipa")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("Payload/T.app/Info.plist", plistlib.dumps({"a": 1}))
            z.writestr("Payload/T.app/GoogleService-Info.plist", plistlib.dumps({"a": 1}))
        c, _ = completer(p)
        got = c._candidates("files ", "Goo")
        self.assertIn("GoogleService-Info.plist ", got)
        self.assertTrue(any(x.startswith("Payload/T.app/Info.plist") for x in c._candidates("files ", "Payload/T.app/I")))

    def test_app_files_complete_for_scan(self):
        d = tempfile.mkdtemp()
        open(os.path.join(d, "x.apk"), "w").close()
        open(os.path.join(d, "notes.txt"), "w").close()
        c, _ = completer()
        got = c._candidates("scan ", os.path.join(d, ""))
        self.assertTrue(any(g.endswith("x.apk") for g in got))
        self.assertFalse(any(g.endswith("notes.txt") for g in got))

    def test_expand_inserts_target(self):
        st = {"target": "/x/app.ipa"}
        self.assertEqual(shell.expand(["info"], st), ["info", "/x/app.ipa"])
        self.assertEqual(shell.expand(["files", "Info.plist"], st), ["files", "/x/app.ipa", "Info.plist"])
        self.assertEqual(shell.expand(["scan", "other.apk"], st), ["scan", "other.apk"])
        self.assertEqual(shell.expand(["info"], {"target": None}), ["info"])

    def test_completion_script(self):
        text = shell.completion_script("bash", cli.build_parser())
        self.assertIn("complete -o filenames -F _appsleuth appsleuth", text)
        self.assertIn("--dump-crypto", text)
        self.assertTrue(shell.completion_script("zsh", cli.build_parser()).startswith("autoload"))


if __name__ == "__main__":
    unittest.main()
