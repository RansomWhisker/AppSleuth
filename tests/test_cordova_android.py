import os
import struct
import tempfile
import unittest
import zipfile

from appsleuth import engine, info


def axml(elements):
    """Encode [(tag, {attr: str}, line)] as flat binary XML (string-pool + start/end elements)."""
    pool = []

    def sid(x):
        if x not in pool:
            pool.append(x)
        return pool.index(x)

    body = b""
    for tag, attrs, line in elements:
        t = sid(tag)
        a = b"".join(struct.pack("<iiiHBBI", -1, sid(k), sid(v), 8, 0, 3, sid(v)) for k, v in attrs.items())
        body += struct.pack("<HHIIi", 0x0102, 16, 36 + len(a), line, -1) + struct.pack("<ii", -1, t)
        body += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0) + a
        body += struct.pack("<HHIIi", 0x0103, 16, 24, line, -1) + struct.pack("<ii", -1, t)
    enc = [struct.pack("<H", len(x)) + x.encode("utf-16-le") + b"\0\0" for x in pool]
    offs, o = [], 0
    for e in enc:
        offs.append(o)
        o += len(e)
    sdata = b"".join(enc)
    sdata += b"\0" * (-len(sdata) % 4)
    start = 28 + 4 * len(pool)
    spool = struct.pack("<HHIIIIII", 0x0001, 28, start + len(sdata), len(pool), 0, 0, start, 0)
    spool += b"".join(struct.pack("<I", x) for x in offs) + sdata
    out = spool + body
    return struct.pack("<HHI", 0x0003, 8, 8 + len(out)) + out


def make_apk(config_elements, extra=None):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "c.apk")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("AndroidManifest.xml", axml([("manifest", {"package": "com.x.c"}, 1)]))
        z.writestr("res/xml/config.xml", axml(config_elements))
        z.writestr("assets/www/index.html", "<html></html>")
        z.writestr("assets/www/cordova.js", "// cordova")
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return p


class AndroidCordova(unittest.TestCase):
    def scan(self, apk):
        fb, meta = engine.analyze_apk(apk, tempfile.mkdtemp())
        return fb, meta

    def test_wildcards_found_with_exact_tags(self):
        fb, meta = self.scan(make_apk([("widget", {"id": "com.x.c"}, 2),
                                       ("access", {"origin": "*"}, 3),
                                       ("allow-navigation", {"href": "*"}, 4),
                                       ("allow-intent", {"href": "https://*/*"}, 5)]))
        titles = [f.title for f in fb.items]
        self.assertTrue(any(t.startswith('Cordova <access origin="*">') for t in titles))
        self.assertTrue(any(t.startswith('Cordova <allow-navigation') for t in titles))
        self.assertFalse(any(t.startswith('Cordova <allow-intent') for t in titles))
        lines = meta["hybrid"]["config_lines"]
        self.assertEqual([x["text"] for x in lines], ['<access origin="*" />', '<allow-navigation href="*" />'])
        self.assertEqual(lines[0]["file"], "res/xml/config.xml")
        self.assertEqual(lines[0]["line"], 3)
        flags = info._flags([f.to_dict() for f in fb.items])
        self.assertTrue(flags["cordova_access_any_origin"] and flags["cordova_navigation_any_host"])

    def test_restricted_origin_not_flagged(self):
        fb, meta = self.scan(make_apk([("widget", {"id": "x"}, 2), ("access", {"origin": "https://a.example"}, 3)]))
        self.assertFalse(any(f.title.startswith("Cordova <access") for f in fb.items))
        self.assertFalse(meta["hybrid"].get("config_lines"))

    def test_renamed_resource_file_is_found(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "r.apk")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("AndroidManifest.xml", axml([("manifest", {"package": "com.x.c"}, 1)]))
            z.writestr("res/Ab.xml", axml([("widget", {"id": "x"}, 2), ("access", {"origin": "*"}, 3)]))
            z.writestr("assets/www/index.html", "<html></html>")
        fb, meta = self.scan(p)
        self.assertEqual(meta["hybrid"]["config_lines"][0]["file"], "res/Ab.xml")

    def test_web_assets_secrets_scanned(self):
        fb, meta = self.scan(make_apk([("widget", {"id": "x"}, 2)],
                                      {"assets/www/app.js": "var g='AIzaSyD4kQ9xV2mN7pL1rT8wZ3bC6hJ0eF5gYaM';"}))
        self.assertEqual(meta["hybrid"]["framework"], "Cordova")
        self.assertTrue(any(x["type"] == "Google API Key" for x in fb.secrets))


if __name__ == "__main__":
    unittest.main()
