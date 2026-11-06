import json
import os
import tempfile
import unittest
import zipfile

from appsleuth import appfiles, protections


def make_apk(files):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "t.apk")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x00")
        for name, data in files.items():
            z.writestr(name, data)
    return p


class Detect(unittest.TestCase):
    def run_on(self, files):
        return protections.detect_path(make_apk(files))

    def test_strong_signal_detected(self):
        r = self.run_on({"classes.dex": b"xx Lcom/scottyab/rootbeer/RootBeer; yy"})
        self.assertEqual(r["categories"]["root"]["level"], "detected")

    def test_nothing_found(self):
        r = self.run_on({"classes.dex": b"hello world"})
        self.assertTrue(all(c["level"] == "not found" for c in r["categories"].values()))

    def test_okhttp_pin_hash_literal_alone_is_weak(self):
        r = self.run_on({"classes.dex": b"sha256/ and more"})
        self.assertEqual(r["categories"]["pinning"]["level"], "weak signal")

    def test_two_weak_root_signals_are_likely(self):
        r = self.run_on({"classes.dex": b"/system/xbin/su test-keys"})
        self.assertEqual(r["categories"]["root"]["level"], "likely")

    def test_sdk_only_is_not_counted_as_app_protection(self):
        r = self.run_on({"lib/arm64-v8a/libsentry.so": b"goldfish ranchu"})
        self.assertEqual(r["categories"]["emulator"]["level"], "SDK only")


class CapacitorSql(unittest.TestCase):
    def sql(self, cfg):
        files = {"assets/capacitor.config.json": json.dumps({"plugins": {"CapacitorSQLite": cfg}}),
                 "assets/capacitor.plugins.json": '[{"pkg":"@capacitor-community/sqlite"}]'}
        return protections.detect_path(make_apk(files))["capacitor_sql"]

    def test_absent_when_plugin_missing(self):
        self.assertEqual(protections.detect_path(make_apk({"classes.dex": b"x"}))["capacitor_sql"], {})

    def test_on_and_off(self):
        self.assertEqual(self.sql({"androidIsEncryption": True})["status"], "on")
        self.assertEqual(self.sql({"androidIsEncryption": False})["status"], "off")

    def test_plain_bundled_db_flagged(self):
        files = {"assets/capacitor.plugins.json": "@capacitor-community/sqlite",
                 "assets/public/assets/x.db": b"SQLite format 3\x00" + b"\x00" * 100}
        r = protections.detect_path(make_apk(files))["capacitor_sql"]
        self.assertTrue(r["plain_bundled_dbs"])


class Binaries(unittest.TestCase):
    def test_non_elf_so_ignored(self):
        r = protections.detect_path(make_apk({"lib/arm64-v8a/libx.so": b"not elf"}))
        self.assertEqual(r["binaries"]["total"], 0)
