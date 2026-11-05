import base64
import io
import json
import os
import plistlib
import sqlite3
import tarfile
import tempfile
import unittest

from appsleuth import dataaudit, devdata


def make_tar(members):
    path = tempfile.mktemp(suffix=".tar")
    with tarfile.open(path, "w") as t:
        for name, kind, data in members:
            i = tarfile.TarInfo(name)
            if kind == "file":
                i.size, i.mode = len(data), 0o666
                t.addfile(i, io.BytesIO(data))
            elif kind == "sym":
                i.type, i.linkname = tarfile.SYMTYPE, data.decode()
                t.addfile(i)
    return path


class SafeExtract(unittest.TestCase):
    def run_extract(self, members, **kw):
        out = tempfile.mkdtemp()
        return out, devdata.safe_extract_tar(make_tar(members), out, **kw)

    def test_refuses_traversal_and_absolute(self):
        for name in ("../evil", "a/../../evil", "/etc/evil"):
            with self.assertRaises(devdata.PullError, msg=name):
                self.run_extract([(name, "file", b"x")])

    def test_symlinks_skipped_modes_recorded(self):
        out, m = self.run_extract([("link", "sym", b"/etc/passwd"), ("ok", "file", b"1")])
        self.assertEqual(os.listdir(out), ["ok"])
        self.assertEqual(m["skipped_links_or_special"], 1)
        self.assertEqual(m["modes"]["ok"], 0o666)
        self.assertEqual(os.stat(os.path.join(out, "ok")).st_mode & 0o777, 0o600)

    def test_caps(self):
        with self.assertRaises(devdata.PullError):
            self.run_extract([("big", "file", b"x" * 5000)], max_bytes=1000)
        with self.assertRaises(devdata.PullError):
            self.run_extract([(f"f{i}", "file", b"1") for i in range(5)], max_files=3)


class Inputs(unittest.TestCase):
    def test_validators(self):
        self.assertFalse(devdata.USER_RE.match("-oProxyCommand=x"))
        self.assertFalse(devdata.HOST_RE.match("-oProxyCommand=x"))
        self.assertFalse(devdata.PKG_RE.match("com.x; rm -rf /"))
        self.assertTrue(devdata.PKG_RE.match("com.example.app"))

    def test_expand_host(self):
        self.assertEqual([devdata.expand_host(x) for x in ("9", "0.5", "10.0.0.4", "256", "h.local")],
                         ["192.168.1.9", "192.168.0.5", "10.0.0.4", "256", "h.local"])


class Audit(unittest.TestCase):
    JWT = ("eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(json.dumps({"sub": "1"}).encode()).decode().rstrip("=")
           + ".c2lnbmF0dXJlLXNpZw")

    def setUp(self):
        self.root = tempfile.mkdtemp()

    def put(self, rel, data):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "wb").write(data)
        return p

    def titles(self, **kw):
        return [(f["severity"], f["title"], f["location"]) for f in dataaudit.audit_dir(self.root, **kw)["findings"]]

    def test_sensitive_key_logic(self):
        sk = dataaudit.sensitive_key
        for k in ("authToken", "access_token", "userPassword", "api_key", "refresh-token", "clientSecret"):
            self.assertTrue(sk(k), k)
        for k in ("isLoggedIn", "hasToken", "tokenExpiry", "passwordHint", "theme", "retryCount", "author", "pinned"):
            self.assertFalse(sk(k), k)

    def test_plist_flagged_and_redacted(self):
        self.put("Library/Preferences/a.plist", plistlib.dumps({"authToken": self.JWT, "isLoggedIn": True, "userPassword": "hunter2hunter2"}))
        r = dataaudit.audit_dir(self.root, "ios")
        self.assertEqual(r["summary"]["HIGH"], 1)
        self.assertNotIn("hunter2hunter2", json.dumps(r))
        self.assertNotIn(self.JWT, json.dumps(r))

    def test_reveal_shows_preview_only(self):
        self.put("a.plist", plistlib.dumps({"authToken": self.JWT}))
        r = dataaudit.audit_dir(self.root, "ios", reveal=True)
        self.assertNotIn(self.JWT, json.dumps(r))            # never the whole value

    def test_sqlite_column_with_quote_and_localstorage(self):
        os.makedirs(os.path.join(self.root, "Library/WebKit"))
        c = sqlite3.connect(os.path.join(self.root, "Library/app.sqlite"))
        c.execute('create table users(id int, access_token text, "we""ird" text)')
        c.execute("insert into users values(1,?,'x')", (self.JWT,))
        c.commit(); c.close()
        c = sqlite3.connect(os.path.join(self.root, "Library/WebKit/x.localstorage"))
        c.execute("create table ItemTable(key text, value blob)")
        c.execute("insert into ItemTable values('session_token',?)", ("s8Jd92LsPq0Zx7Vb3NmQw5RtYh1UeC6a".encode("utf-16-le"),))
        c.commit(); c.close()
        locs = {t[2] for t in self.titles()}
        self.assertEqual(locs, {"Library/app.sqlite", "Library/WebKit/x.localstorage"})

    def test_random_db_is_positive_signal(self):
        self.put("Library/enc.db", os.urandom(4096))
        self.assertEqual(self.titles(), [("INFO", "1 database(s) are not plain SQLite (likely encrypted)", None)])

    def test_symlinks_not_followed(self):
        os.symlink("/etc/passwd", os.path.join(self.root, "link.txt"))
        self.assertEqual(dataaudit.audit_dir(self.root)["meta"]["files"], 0)

    def test_sqlite_authorizer_blocks_writes(self):
        p = os.path.join(self.root, "x.db")
        c = sqlite3.connect(p); c.execute("create table t(a)"); c.commit(); c.close()
        conn = dataaudit._open_sqlite(p)
        with self.assertRaises(sqlite3.Error):
            conn.execute("insert into t values (1)")
        with self.assertRaises(sqlite3.Error):
            conn.execute("create table z(a)")

    def test_shared_prefs_and_xxe_rejected(self):
        self.put("shared_prefs/p.xml", b'<map><string name="refresh_token">r8Jd92LsPq0Zx7Vb3NmQw5RtYh1UeC6aXyz</string><boolean name="isAuthed" value="true" /></map>')
        self.put("shared_prefs/evil.xml", b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><map><string name="token">&a;</string></map>')
        locs = {t[2] for t in self.titles(platform="android")}
        self.assertEqual(locs, {"shared_prefs/p.xml"})

    def test_world_readable_needs_manifest(self):
        self.put("files/a.txt", b"x")
        r = dataaudit.audit_dir(self.root, "android", manifest={"modes": {"files/a.txt": 0o666}})
        self.assertIn("world-readable", r["findings"][0]["title"])


if __name__ == "__main__":
    unittest.main()


class WindowsSupport(unittest.TestCase):
    def test_win_safe_name(self):
        f = devdata.win_safe_name
        self.assertEqual(f("Library/Caches/a:b*c?.txt"), "Library/Caches/a_b_c_.txt")
        self.assertEqual(f("aux/NUL.txt/ok. "), "_aux/_NUL.txt/ok")
        self.assertEqual(f("a/b"), "a/b")

    def test_backslash_and_drive_traversal_refused(self):
        for name in ("..\\evil", "a/..\\..\\evil", "C:evil", "C:/evil"):
            with self.assertRaises(devdata.PullError, msg=name):
                out = tempfile.mkdtemp()
                devdata.safe_extract_tar(make_tar([(name, "file", b"x")]), out)

    def test_askpass_never_stores_password(self):
        pw = 'p@ss w0rd!&%^"\'$x'
        tmp = tempfile.mkdtemp()
        env = devdata.make_askpass(tmp, "APPSLEUTH_PW", pw)
        for f in os.listdir(tmp):
            self.assertNotIn(pw, open(os.path.join(tmp, f)).read())
        import subprocess
        out = subprocess.run([env["SSH_ASKPASS"]], env=env, capture_output=True, text=True).stdout
        self.assertEqual(out.rstrip("\r\n"), pw)
