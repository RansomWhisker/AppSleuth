import contextlib
import io
import os
import plistlib
import tempfile
import unittest
import zipfile

from appsleuth import appfiles, cli, files
from tests.test_cordova_android import axml, make_apk


def make_ipa():
    p = os.path.join(tempfile.mkdtemp(), "t.ipa")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("Payload/T.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.t.app"}, fmt=plistlib.FMT_BINARY))
        z.writestr("Payload/T.app/GoogleService-Info.plist", plistlib.dumps({"API_KEY": "AIzaFAKE"}))
        z.writestr("Payload/T.app/capacitor.config.json", '{"appId":"com.t.app"}')
        z.writestr("Payload/T.app/Frameworks/X.framework/Info.plist", plistlib.dumps({"fw": 1}))
        z.writestr("Payload/T.app/blob.bin", bytes(range(256)))
    return p


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cli.main(["--no-banner", "files", *argv, "--no-prompt"])
        except SystemExit as e:
            code = e.code or 0
    return out.getvalue(), err.getvalue(), code


class FilesCommand(unittest.TestCase):
    def test_lists_important_files_only_by_default(self):
        out, _, _ = run(make_ipa())
        self.assertIn("GoogleService-Info.plist", out)
        self.assertIn("capacitor.config.json", out)
        self.assertNotIn("blob.bin", out)
        self.assertNotIn("Frameworks", out)

    def test_all_lists_everything(self):
        out, _, _ = run(make_ipa(), "--all")
        self.assertIn("blob.bin", out)
        self.assertIn("Frameworks/X.framework/Info.plist", out)

    def test_binary_plist_is_decoded_and_prefers_app_plist(self):
        out, err, _ = run(make_ipa(), "Info.plist")
        self.assertIn("<key>CFBundleIdentifier</key>", out)
        self.assertNotIn("<key>fw</key>", out)

    def test_open_by_number_and_json_pretty(self):
        ipa = make_ipa()
        out, _, _ = run(ipa, "3")
        self.assertIn('"appId": "com.t.app"', out)

    def test_open_non_listed_file_by_name_gives_hex(self):
        out, _, _ = run(make_ipa(), "blob.bin")
        self.assertIn("00 01 02 03", out)

    def test_unknown_file_fails(self):
        _, err, code = run(make_ipa(), "nope.txt")
        self.assertEqual(code, 1)
        self.assertIn("no file matches", err)

    def test_save(self):
        d = tempfile.mkdtemp()
        run(make_ipa(), "--save", d)
        self.assertTrue(os.path.isfile(os.path.join(d, "Payload", "T.app", "GoogleService-Info.plist")))

    def test_android_compiled_xml_decoded(self):
        apk = make_apk([("widget", {"id": "x"}, 1)], extra={"google-services.json": '{"project_info":{}}'})
        out, _, _ = run(apk, "AndroidManifest.xml")
        self.assertIn('<manifest package="com.x.c"/>', out)
        out, _, _ = run(apk)
        self.assertIn("google-services.json", out)
        out, _, _ = run(apk, "config.xml")
        self.assertIn('<widget id="x"/>', out)

    def test_mobileprovision_signature_stripped(self):
        p = os.path.join(tempfile.mkdtemp(), "t.ipa")
        pl = plistlib.dumps({"Name": "dev profile"})
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("Payload/T.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "a"}))
            z.writestr("Payload/T.app/embedded.mobileprovision", b"\x30\x82junk" + pl + b"\x00sig")
        out, _, _ = run(p, "embedded.mobileprovision")
        self.assertIn("dev profile", out)

    def test_search_text_plist_binary_and_utf16(self):
        p = os.path.join(tempfile.mkdtemp(), "t.ipa")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("Payload/T.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.t.app", "K": "SecretValue"}, fmt=plistlib.FMT_BINARY))
            z.writestr("Payload/T.app/T", b"\x00\x01api_key=hunter2\x00\x02" + "wide-hunter2".encode("utf-16-le"))
            z.writestr("Payload/T.app/pic.png", b"\x00hunter2")
        out, err, code = run(p, "--search", "secretvalue")
        self.assertIn("Info.plist:", out)
        self.assertIn("SecretValue", out)
        out, err, code = run(p, "-s", "hunter2")
        self.assertEqual(out.count("T.app/T:"), 2)       # ASCII and UTF-16 hits
        self.assertNotIn("pic.png", out)                 # media skipped
        out, _, code = run(p, "-s", "secretvalue", "--case")
        self.assertEqual(code, 1)
        out, _, code = run(p, "-s", r"api_key=\w+", "--regex")
        self.assertIn("api_key=hunter2", out)
        out, _, _ = run(p, "-s", "hunter2", "Info.plist")  # restricted to named file
        self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
