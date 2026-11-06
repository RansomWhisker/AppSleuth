import os
import tempfile
import unittest

from appsleuth import appfiles, info, techstack


def _app(platform, files, plist=None):
    d = tempfile.mkdtemp()
    for rel, data in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
    a = appfiles.App("x", "ipa" if platform == "ios" else "apk", d)
    a.roots = [d]
    a.main_root = d
    a.info_plist = plist or {}
    return a


class TechStack(unittest.TestCase):
    def test_xcode_version(self):
        self.assertEqual(techstack._xcode("1540"), "15.4")
        self.assertEqual(techstack._xcode("1501"), "15.0.1")

    def test_android_flutter_and_abis(self):
        a = _app("android", {"lib/arm64-v8a/libflutter.so": b"Flutter/3.19.0", "lib/arm64-v8a/libapp.so": b"3.3.0 (stable)",
                             "lib/x86_64/libflutter.so": b"x", "assets/flutter_assets/AssetManifest.json": b"{}"})
        r = techstack.detect(a)
        names = {i["name"]: i for i in r["items"]}
        self.assertEqual(r["primary"], "Flutter")
        self.assertEqual(names["Flutter"]["version"], "3.19.0")
        self.assertEqual(names["Dart"]["version"], "3.3.0")
        self.assertEqual(r["toolchain"]["abis"], ["arm64-v8a", "x86_64"])

    def test_capacitor_hides_cordova_compat_layer(self):
        a = _app("android", {"assets/capacitor.config.json": b"{}", "assets/www/cordova_plugins.js": b""})
        names = [i["name"] for i in techstack.detect(a)["items"]]
        self.assertIn("Capacitor", names)
        self.assertNotIn("Cordova", names)

    def test_ios_toolchain_from_info_plist(self):
        a = _app("ios", {"Frameworks/Alamofire.framework/Alamofire": b"x", "Frameworks/libswiftCore.dylib": b"x"},
                 {"DTXcode": "1540", "DTSDKName": "iphoneos17.5", "CFBundleExecutable": "App"})
        r = techstack.detect(a)
        names = [i["name"] for i in r["items"]]
        self.assertIn("Alamofire", names)
        self.assertIn("Swift", names)
        self.assertEqual(r["toolchain"]["xcode"], "15.4")

    def test_render_lists_primary_and_evidence_only_in_full(self):
        ts = {"primary": "Flutter", "items": [{"category": "Framework", "name": "Flutter", "version": "3.19.0", "evidence": ["libflutter.so"]}],
              "toolchain": {"abis": ["arm64-v8a"]}}
        short = "\n".join(info.techstack_lines(ts, "android"))
        full = "\n".join(info.techstack_lines(ts, "android", full=True))
        self.assertIn("Flutter 3.19.0", short)
        self.assertNotIn("libflutter.so", short)
        self.assertIn("libflutter.so", full)


if __name__ == "__main__":
    unittest.main()
