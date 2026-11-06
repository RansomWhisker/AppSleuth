import io
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

from appsleuth import engine


def _zip(entries, encrypted_flag=False):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in entries:
            z.writestr(n, d)
    b = bytearray(bio.getvalue())
    if encrypted_flag:
        for sig, off in ((b"PK\x01\x02", 8), (b"PK\x03\x04", 6)):
            i = 0
            while (i := b.find(sig, i)) >= 0:
                struct.pack_into("<H", b, i + off, struct.unpack_from("<H", b, i + off)[0] | 1)
                i += 4
    return bytes(b)


def _extract(data):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "in.zip")
    with open(p, "wb") as fh:
        fh.write(data)
    out = os.path.join(d, "out")
    with engine.open_zip(p) as z:
        engine._safe_extractall(z, out)
    files = {}
    for root, _x, names in os.walk(out):
        for n in names:
            with open(os.path.join(root, n), "rb") as fh:
                files[os.path.relpath(os.path.join(root, n), out).replace(os.sep, "/")] = fh.read()
    return d, files


class RobustExtract(unittest.TestCase):
    def test_fake_encrypted_flag_is_ignored(self):
        _, f = _extract(_zip([("a.txt", b"hello")], encrypted_flag=True))
        self.assertEqual(f, {"a.txt": b"hello"})

    def test_case_and_file_dir_collisions_keep_every_entry(self):
        _, f = _extract(_zip([("res/a", b"file"), ("res/A/b.xml", b"dir"), ("x/X.txt", b"1"), ("x/x.txt", b"2")]))
        self.assertEqual(sorted(f.values()), [b"1", b"2", b"dir", b"file"])
        self.assertEqual(f["res/a"], b"file")

    def test_long_names_are_shortened(self):
        _, f = _extract(_zip([("assets/" + "a" * 300 + ".txt", b"x"), ("/".join(["d" * 200] * 6) + "/y", b"y")]))
        self.assertEqual(sorted(f.values()), [b"x", b"y"])

    def test_dotdot_and_absolute_stay_inside(self):
        d, f = _extract(_zip([("../../evil", b"e"), ("/abs", b"a")]))
        self.assertEqual(sorted(f.values()), [b"a", b"e"])
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(d), "evil")))

    def test_corrupt_entry_is_skipped_not_fatal(self):
        data = bytearray(_zip([("good.txt", b"good" * 100), ("bad.txt", os.urandom(4000))]))
        i = data.find(b"PK\x03\x04", 1)          # second local header: corrupt its compressed bytes
        for k in range(i + 60, i + 400):
            data[k] ^= 0x5A
        _, f = _extract(bytes(data))
        self.assertEqual(f.get("good.txt"), b"good" * 100)

    def test_damaged_central_directory_is_a_clean_value_error(self):
        data = bytearray(_zip([("a", b"a")]))
        i = data.find(b"PK\x01\x02")
        data[i:i + 4] = b"XXXX"
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(bytes(data))
        with self.assertRaises(ValueError):
            engine.open_zip(fh.name)


class CliErrors(unittest.TestCase):
    def test_no_traceback_on_bad_input(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as fh:
            fh.write(b"not a zip at all")
        for cmd in ("sbom", "endpoints", "links", "cloud", "info"):
            p = subprocess.run([sys.executable, "-m", "appsleuth", cmd, fh.name] +
                               (["-o", tempfile.mkdtemp()] if cmd != "info" else []),
                               capture_output=True, text=True, env=dict(os.environ, NO_BANNER="1", NO_COLOR="1"))
            self.assertNotIn("Traceback", p.stderr, cmd)
            self.assertNotEqual(p.returncode, 0, cmd)
            self.assertIn("error:", p.stderr, cmd)


if __name__ == "__main__":
    unittest.main()
