import tempfile
import unittest

from appsleuth import engine
from tests.test_cordova_android import make_apk

KEY = "AI" + "zaSyD4kQ9xV2mN7pL1rT8wZ3bC6hJ0eF5gYaM"


class Locator(unittest.TestCase):
    def test_file_and_line(self):
        a, b = b"one\ntwo\n", b"x\ny\nvar k='SECRET';\n"
        blob = b"\n".join([a, b])
        loc = engine.file_line_locator(["www/a.js", "www/b.js"], [a, b])
        self.assertEqual(loc(blob, blob.index(b"two")), "www/a.js:2")
        self.assertEqual(loc(blob, blob.index(b"SECRET")), "www/b.js:3")

    def test_column_only_for_long_lines(self):
        a = b"a" * 400 + b"KEY" + b"b" * 10
        loc = engine.file_line_locator(["www/min.js"], [a])
        self.assertEqual(loc(a, 400), "www/min.js:1:401")

    def test_offset_locator(self):
        self.assertEqual(engine.offset_locator("App")(b"", 255), "App @0xff")


class ApkWebSecrets(unittest.TestCase):
    def test_secret_has_exact_file_and_line(self):
        apk = make_apk([("widget", {"id": "x"}, 2)], {
            "assets/www/js/other.js": "// nothing\n",
            "assets/www/js/app.js": "var a = 1;\nvar b = 2;\nvar g='" + KEY + "';\n"})
        fb, _ = engine.analyze_apk(apk, tempfile.mkdtemp())
        hit = [x for x in fb.secrets if x["type"] == "Google API Key"]
        self.assertEqual([x["location"] for x in hit], ["assets/www/js/app.js:3"])
        f = [f for f in fb.items if f.title.startswith("Client-side identifier: Google API key")]
        self.assertEqual(f[0].location, "assets/www/js/app.js:3")


if __name__ == "__main__":
    unittest.main()
