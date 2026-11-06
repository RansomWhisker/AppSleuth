import json
import unittest

from appsleuth import runtime

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXNpZw"


def titles(events, platform="android"):
    r = runtime.events_to_result(events, platform, "com.t.app")
    return [(f["severity"], f["title"]) for f in r["findings"]], r


class RuntimeFindings(unittest.TestCase):
    def test_credential_in_prefs_high_and_never_stored(self):
        t, r = titles([{"t": "prefs_write", "key": "auth_token", "value": JWT}])
        self.assertEqual(t[0][0], "HIGH")
        self.assertNotIn(JWT, json.dumps(r))

    def test_benign_prefs_ignored(self):
        t, _ = titles([{"t": "prefs_write", "key": "isLoggedIn", "value": "true"},
                       {"t": "prefs_write", "key": "theme", "value": "dark"},
                       {"t": "prefs_write", "key": "authToken", "value": ""}])
        self.assertEqual(t, [])

    def test_cleartext_noise_filtered(self):
        t, _ = titles([{"t": "cleartext", "url": "http://schemas.android.com/apk/res/android"},
                       {"t": "cleartext", "url": "http://api.ipify.org/"}])
        self.assertEqual(len(t), 1)
        self.assertEqual(t[0][0], "MEDIUM")

    def test_ciphers(self):
        t, _ = titles([{"t": "cipher", "alg": "AES"}, {"t": "cipher", "alg": "DES/CBC/PKCS5Padding"},
                       {"t": "cipher", "alg": "AES/GCM/NoPadding"}])
        self.assertEqual(sorted(x[1] for x in t), ["ECB mode used at runtime", "Weak cipher used at runtime"])

    def test_gcm_alone_is_clean(self):
        self.assertEqual(titles([{"t": "cipher", "alg": "AES/GCM/NoPadding"}])[0], [])

    def test_log_secrets(self):
        t, _ = titles([{"t": "log", "tag": "OkHttp", "msg": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"},
                       {"t": "log", "tag": "x", "msg": "started activity"}])
        self.assertEqual(t, [("HIGH", "Authorization header written to the system log")])

    def test_defensive_controls_are_info(self):
        t, _ = titles([{"t": "root_check", "how": "File.exists", "arg": "/system/xbin/su"},
                       {"t": "pinning", "how": "okhttp3.CertificatePinner", "host": "api.example.com"}])
        self.assertTrue(all(sev == "INFO" for sev, _ in t) and len(t) == 2)

    def test_garbage_events_ignored(self):
        t, r = titles([None, "x", {"nope": 1}, {"t": 5}, {"t": "unknown"}])
        self.assertEqual(t, [])
        self.assertEqual(r["meta"]["events"], 1)

    def test_run_probe_validates_without_frida(self):
        with self.assertRaises(RuntimeError):
            runtime.run_probe("android", "com.x; rm -rf /", seconds=1)


if __name__ == "__main__":
    unittest.main()
