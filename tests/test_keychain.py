import json
import os
import sqlite3
import tempfile
import unittest

from appsleuth import dataaudit, devdata


class FakeSSH:
    """Serves a local sqlite file as if it were the device's keychain-2.db."""
    def __init__(self, db):
        self.db = db

    def run(self, command, binary=False, check=True):
        return "y\n" if command.startswith("test -f") and command.split()[2].endswith("keychain-2.db") and "-wal" not in command and "-shm" not in command else ""

    def stream_to_file(self, command, path, max_bytes):
        with open(self.db, "rb") as src, open(path, "wb") as dst:
            dst.write(src.read())


def make_db():
    p = os.path.join(tempfile.mkdtemp(), "k.db")
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE genp (rowid INTEGER PRIMARY KEY, acct BLOB, svce BLOB, labl BLOB, agrp TEXT, pdmn TEXT, sync INT)")
    con.execute("CREATE TABLE inet (rowid INTEGER PRIMARY KEY, acct BLOB, srvr BLOB, agrp TEXT, pdmn TEXT, sync INT)")
    rows = [("token", "auth", "T1.com.x.app", "dku"), ("pin", "auth", "T1.com.x.app", "ak"),
            ("rt", "api", "T1.com.x.app", "cku"), ("other", "o", "T2.com.other", "dk")]
    for a, s_, g, d in rows:
        con.execute("INSERT INTO genp (acct, svce, labl, agrp, pdmn, sync) VALUES (?,?,?,?,?,0)", (a.encode(), s_.encode(), b"", g, d))
    con.execute("INSERT INTO inet (acct, srvr, agrp, pdmn, sync) VALUES (?,?,?,?,0)", (b"u", b"api.x.com", "T1.com.x.app", "akpu"))
    con.commit()
    con.close()
    return p


class Keychain(unittest.TestCase):
    def test_pull_filters_to_app_and_names_accessibility(self):
        kc = devdata.ios_pull_keychain(FakeSSH(make_db()), "com.x.app")
        self.assertEqual(len(kc["items"]), 4)                       # the other app's item is excluded
        names = {dataaudit.keychain_access_name(i["accessible"]) for i in kc["items"]}
        self.assertIn("kSecAttrAccessibleAlwaysThisDeviceOnly", names)
        self.assertIn("kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly", names)
        self.assertNotIn("kSecAttrAccessibleAlways", names)
        self.assertTrue(any(i["class"] == "internet password" and i["service"] == "api.x.com" for i in kc["items"]))

    def test_audit_flags_always_and_lists_items(self):
        kc = devdata.ios_pull_keychain(FakeSSH(make_db()), "com.x.app")
        res = dataaudit.audit_dir(tempfile.mkdtemp(), "ios", keychain=kc)
        titles = [(f["severity"], f["title"]) for f in res["findings"]]
        self.assertIn(("MEDIUM", "Keychain items readable while the device is locked (kSecAttrAccessibleAlwaysThisDeviceOnly)"), titles)
        self.assertTrue(any(t.startswith("Keychain items: 1 with kSecAttrAccessibleWhenUnlocked") for _s, t in titles))
        text = "\n".join(dataaudit.keychain_lines(kc))
        self.assertIn("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", text)
        self.assertIn("[password] auth / token", text)
        json.dumps(res)

    def test_no_items(self):
        res = dataaudit.audit_dir(tempfile.mkdtemp(), "ios", keychain={"items": []})
        self.assertTrue(any(f["title"].startswith("No keychain items") for f in res["findings"]))


if __name__ == "__main__":
    unittest.main()
