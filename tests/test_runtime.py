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

    def test_keychain_accessibility(self):
        self.assertEqual(titles([{"t": "keychain_add", "accessible": "ck"},
                                 {"t": "keychain_add", "accessible": "ak"}])[0], [])
        t, _ = titles([{"t": "keychain_add", "accessible": "dk"}])
        self.assertEqual(t, [("MEDIUM", "Keychain item stored with weak accessibility")])

    def test_garbage_events_ignored(self):
        t, r = titles([None, "x", {"nope": 1}, {"t": 5}, {"t": "unknown"}])
        self.assertEqual(t, [])
        self.assertEqual(r["meta"]["events"], 1)

    def test_run_probe_validates_without_frida(self):
        with self.assertRaises(RuntimeError):
            runtime.run_probe("android", "com.x; rm -rf /", seconds=1)


class Breakdown(unittest.TestCase):
    STATS = {"t": "hook_stats", "hooks": {
        "NSURLSessionTask - resume": {"installed": True, "calls": 9, "emitted": 2, "optional": False},
        "WKWebView - loadRequest:": {"installed": True, "calls": 0, "emitted": 0, "optional": False},
        "WKWebView - setInspectable:": {"installed": False, "calls": 0, "emitted": 0, "optional": True},
        "Security!SecItemAdd": {"installed": False, "calls": 0, "emitted": 0, "optional": False}}}

    def test_per_hook_counts_silent_and_missing(self):
        ev = [self.STATS,
              {"t": "net", "hook": "NSURLSessionTask - resume", "how": "URLSessionTask resume", "scheme": "https",
               "host": "api.example.com", "path": "/v1"},
              {"t": "net", "hook": "NSURLSessionTask - resume", "scheme": "https", "host": "api.example.com", "path": "/v2"}]
        _, r = titles(ev, "ios")
        h = {x["name"]: x for x in r["meta"]["hooks"]}
        self.assertEqual((h["NSURLSessionTask - resume"]["calls"], h["NSURLSessionTask - resume"]["events"]), (9, 2))
        self.assertEqual(h["WKWebView - loadRequest:"]["calls"], 0)
        text = "\n".join(runtime.breakdown_lines(r))
        self.assertIn("1 fired, 1 installed but silent, 1 not found", text)
        self.assertIn("not found: Security!SecItemAdd", text)
        self.assertNotIn("setInspectable", text)                # optional hooks are not reported as missing
        t = [x[1] for x in titles(ev, "ios")[0]]
        self.assertIn("1 runtime hook(s) could not be installed", t)
        self.assertIn("Network requests observed to 1 host(s)", t)

    def test_dns_without_requests_is_a_coverage_gap(self):
        t, _ = titles([{"t": "dns", "host": "api.example.com"}, {"t": "dns", "host": "gsp.apple.com"}], "ios")
        self.assertEqual(t, [("LOW", "Network hooks saw no requests although the app resolved host names")])
        t, _ = titles([{"t": "dns", "host": "api.example.com"}, {"t": "net", "host": "api.example.com"}], "ios")
        self.assertNotIn("Network hooks saw no requests although the app resolved host names", [x[1] for x in t])

    def test_trust_and_webview_observations(self):
        t, _ = titles([{"t": "trust_eval", "by": "app"}, {"t": "trust_eval", "by": "system"},
                       {"t": "trust_override", "how": "SecTrustSetExceptions"},
                       {"t": "trust_override", "how": "SecTrustSetAnchorCertificatesOnly"},
                       {"t": "webview_load", "url": "https://m.example.com/home"}], "ios")
        got = dict((x[1], x[0]) for x in t)
        self.assertEqual(got["App code evaluates TLS trust itself (observed)"], "INFO")
        self.assertEqual(got["App code sets TLS trust exceptions at runtime (observed)"], "MEDIUM")
        self.assertEqual(got["WebView loaded 1 page(s) (observed)"], "INFO")
        self.assertEqual(got["App code customises TLS trust anchors (observed)"], "INFO")

    def test_sockets(self):
        t, _ = titles([{"t": "dns", "host": "api.example.com"}, {"t": "socket", "ip": "203.0.113.9", "port": 443},
                       {"t": "socket", "ip": "203.0.113.9", "port": 80}, {"t": "socket", "ip": "127.0.0.1", "port": 80}], "ios")
        got = dict((x[1], x[0]) for x in t)
        self.assertEqual(got["App opened a connection to port 80 (plaintext HTTP likely)"], "MEDIUM")
        self.assertEqual(got["Raw socket connections observed to 2 endpoint(s)"], "INFO")
        self.assertNotIn("Network hooks saw no requests although the app resolved host names", got)   # sockets count as seen

    def test_dump_redacts_values(self):
        import os, tempfile
        path = os.path.join(tempfile.mkdtemp(), "ev.jsonl")
        n = runtime.dump_events([{"t": "prefs_write", "key": "auth_token", "value": JWT},
                                 {"t": "log", "tag": "x", "msg": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345"},
                                 {"t": "net", "host": "a.example.com"}], path)
        text = open(path).read()
        self.assertEqual(n, 3)
        self.assertNotIn(JWT, text)
        self.assertNotIn("abcdefghijklmnop", text)
        self.assertIn("a.example.com", text)


if __name__ == "__main__":
    unittest.main()


class RuntimeFalsePositives(unittest.TestCase):
    def test_rsa_is_not_ecb_but_aes_default_is(self):
        r = runtime.events_to_result([{"t": "cipher", "alg": "RSA/ECB/PKCS1Padding"}], "android", "x")
        self.assertFalse([f for f in r["findings"] if "ECB" in f["title"]])
        r = runtime.events_to_result([{"t": "cipher", "alg": "AES"}], "android", "x")
        self.assertTrue([f for f in r["findings"] if "ECB" in f["title"]])

    def test_analytics_session_id_is_low_not_high(self):
        ev = [{"t": "prefs_write", "key": "session_id", "value": "0123456789abcdef0123456789abcdef"},
              {"t": "prefs_write", "key": "authToken", "value": "0123456789abcdef0123456789abcdef"}]
        sev = {f["evidence"].split(":")[0]: f["severity"] for f in runtime.events_to_result(ev, "android", "x")["findings"]}
        self.assertEqual(sev, {"session_id": "LOW", "authToken": "HIGH"})


class NewHooks(unittest.TestCase):
    def test_permissive_hostname_verifier_high(self):
        t, _ = titles([{"t": "hostname_verifier", "cls": "com.x.AllowAllHostnameVerifier"}])
        self.assertEqual(t[0][0], "HIGH")

    def test_normal_verifier_info(self):
        t, _ = titles([{"t": "hostname_verifier", "cls": "okhttp3.internal.tls.OkHostnameVerifier"}])
        self.assertEqual(t[0][0], "INFO")

    def test_cronet_cleartext_reported(self):
        t, _ = titles([{"t": "cleartext", "url": "http://api.shopfront-app.io/v1", "via": "cronet"}])
        self.assertEqual(t[0][0], "MEDIUM")

    def test_ios_early_exit_noted_not_bypassed(self):
        t, r = titles([{"t": "early_exit", "reason": "process-terminated"}], platform="ios")
        self.assertEqual(t[0][0], "INFO")
        self.assertIn("does not", r["findings"][0]["detail"])

    def test_early_exit_ignored_on_android(self):
        self.assertEqual(titles([{"t": "early_exit"}])[0], [])


class VersionMismatch(unittest.TestCase):
    def test_detects_protocol_error(self):
        class ProtocolError(Exception):
            pass
        self.assertTrue(runtime.looks_like_version_mismatch(ProtocolError("unexpected message")))
        self.assertFalse(runtime.looks_like_version_mismatch(RuntimeError("device not found")))

    def test_hint_names_version(self):
        self.assertIn("17.12.0", runtime.mismatch_hint("17.12.0"))
