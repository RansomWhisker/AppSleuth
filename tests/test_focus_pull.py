import io
import os
import tarfile
import tempfile
import unittest

from appsleuth import devdata


def make_tar(path, files):
    with tarfile.open(path, "w") as t:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))


FILES = {
    "shared_prefs/auth.xml": b"<map><string name='token'>abc</string></map>",
    "databases/app.db": b"SQLite format 3\x00",
    "databases/app.db-shm": b"x",
    "databases/app.db-wal": b"x",
    "files/session.json": b'{"a":1}',
    "files/photo.png": b"\x89PNG",
    "files/big.dat": b"0" * 3_000_000,
    "files/datastore/user.preferences_pb": b"\x0a",
    "cache/http/blob": b"zzz",
    "code_cache/x.dex": b"dex",
    "app_webview/Default/Local Storage/leveldb/000003.log": b"log",
    "app_webview/Default/Cache/f_000001": b"c",
    "lib/arm64/libx.so": b"elf",
}


class FocusedPull(unittest.TestCase):
    def test_is_important(self):
        imp = {n for n, d in FILES.items() if devdata.is_important(n, len(d), "android")}
        self.assertEqual(imp, {"shared_prefs/auth.xml", "databases/app.db", "databases/app.db-wal", "files/session.json",
                               "files/datastore/user.preferences_pb",
                               "app_webview/Default/Local Storage/leveldb/000003.log"})

    def test_ios_rules(self):
        self.assertTrue(devdata.is_important("Library/Preferences/com.x.plist", 10, "ios"))
        self.assertTrue(devdata.is_important("Library/Caches/com.x/Cache.db", 10, "ios"))
        self.assertTrue(devdata.is_important("Documents/notes.json", 10, "ios"))
        self.assertFalse(devdata.is_important("Library/Caches/com.x/fsCachedData/AB12", 10, "ios"))
        self.assertFalse(devdata.is_important("Documents/video.mp4", 10, "ios"))
        self.assertFalse(devdata.is_important("Library/SplashBoard/Snapshots/a.ktx", 10, "ios"))

    def test_extract_filters_and_counts(self):
        d = tempfile.mkdtemp()
        tp = os.path.join(d, "t.tar")
        make_tar(tp, FILES)
        m = devdata.safe_extract_tar(tp, os.path.join(d, "out"), keep=lambda n, s: devdata.is_important(n, s, "android"))
        self.assertEqual(m["files"], 6)
        self.assertEqual(m["filtered_out"], len(FILES) - 6)
        self.assertTrue(os.path.isfile(os.path.join(d, "out", "shared_prefs", "auth.xml")))
        self.assertFalse(os.path.exists(os.path.join(d, "out", "cache")))

    def test_android_pull_only_asks_for_needed_dirs(self):
        d = tempfile.mkdtemp()
        seen = {}

        def fake_tar(serial, cmd, tar_path, max_bytes):
            seen["cmd"] = cmd
            make_tar(tar_path, FILES)
        old = (devdata._android_tar, devdata._is_root)
        devdata._android_tar, devdata._is_root = fake_tar, lambda s: True
        try:
            m = devdata.android_pull(None, "com.x.app", os.path.join(d, "o"), "root")
            self.assertIn("shared_prefs databases files app_webview", seen["cmd"])
            self.assertTrue(m["focused"])
            self.assertEqual(m["files"], 6)
            m = devdata.android_pull(None, "com.x.app", os.path.join(d, "full"), "root", focus=False)
            self.assertIn("-C /data/data/com.x.app .", seen["cmd"])
            self.assertEqual(m["files"], len(FILES))
        finally:
            devdata._android_tar, devdata._is_root = old


if __name__ == "__main__":
    unittest.main()
