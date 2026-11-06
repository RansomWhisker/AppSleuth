"""Each test pins one false-positive fix (or one true positive that must survive)."""
import base64
import json
import time
import unittest

from appsleuth import engine


def jwt(payload):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=")
    return b({"alg": "HS256", "typ": "JWT"}) + b"." + b(payload) + b".c2lnbmF0dXJlLXNpZw"


def secrets(blob):
    bag = engine.FindingsBag()
    engine.scan_bytes_for_patterns(blob, "t", bag)
    return [(f.severity, f.title) for f in bag.items]


class SecretClassification(unittest.TestCase):
    def test_public_identifiers_are_not_high(self):
        out = secrets(b"AIza" + b"A" * 35 + b" 123456789012-" + b"a" * 32 + b".apps.googleusercontent.com")
        self.assertTrue(out and all(sev == "INFO" for sev, _ in out), out)

    def test_documentation_samples_dropped(self):
        self.assertEqual(secrets(b"AKIAIOSFODNN7EXAMPLE"), [])
        self.assertEqual(secrets(b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"), [])

    def test_aws_key_alone_is_medium_not_high(self):
        self.assertEqual(secrets(b"AKIAQWERTYUIOPASDFGH"), [("MEDIUM", "AWS Access Key ID embedded (no secret key found alongside)")])

    def test_aws_lookalike_inside_long_run_dropped(self):
        self.assertEqual(secrets(b"ZZAAAAKIABIAAAAJAAAAIAAAJAAAA"), [])
        self.assertEqual(secrets(b"x=AKIAAAAAAAAAAAAAAAAA;"), [])         # low-entropy filler

    def test_aws_key_delimited_still_found(self):
        self.assertEqual(secrets(b'"AKIAQWERTYUIOPASDFGH"')[0][0], "MEDIUM")

    def test_aws_key_pair_is_high(self):
        out = secrets(b"AKIAQWERTYUIOPASDFGH\x00wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQWERTYUIO")
        self.assertEqual(out[0][0], "HIGH")

    def test_pem_marker_without_body_is_low(self):
        self.assertEqual(secrets(b"-----BEGIN RSA PRIVATE KEY-----")[0][0], "INFO")
        body = base64.b64encode(b"k" * 300)
        self.assertEqual(secrets(b"-----BEGIN PRIVATE KEY-----\n" + body + b"\n-----END PRIVATE KEY-----")[0][0], "HIGH")

    def test_jwt_must_decode(self):
        self.assertEqual(secrets(b"eyJabcdefghij.klmnopqrstuv.wxyzabcdefgh"), [])
        self.assertEqual(secrets(jwt({"sub": "42", "exp": int(time.time()) + 3600}))[0][0], "HIGH")
        self.assertEqual(secrets(jwt({"sub": "42", "exp": 1000}))[0][0], "LOW")      # expired

    def test_slack_placeholder_dropped(self):
        self.assertEqual(secrets(b"xoxb-your-token-here"), [])


class WeakCrypto(unittest.TestCase):
    def test_description_is_not_des(self):
        strong, md5 = engine._weak_crypto_hits(b"DESCRIPTION DESIGN DESTINATION PROMD5X")
        self.assertEqual((strong, md5), ([], []))

    def test_real_algorithms_found(self):
        strong, _ = engine._weak_crypto_hits(b"x\x00DES/CBC/PKCS5Padding\x00RC4\x00AES/ECB/PKCS7Padding\x00")
        self.assertEqual(len(strong), 3, strong)

    def test_md5_alone_is_info(self):
        bag = engine.FindingsBag()
        engine.scan_bytes_for_patterns(b"\x00MD5\x00", "t", bag)
        self.assertEqual([(f.severity) for f in bag.items], ["INFO"])


class EntropyFilter(unittest.TestCase):
    def keep(self, s):
        return engine._entropy_candidate(s) is not None

    def test_noise_dropped(self):
        for noise in ("123e4567-e89b-12d3-a456-426614174000", "d41d8cd98f00b204e9800998ecf8427e",
                      "getApplicationContextFromActivity", "androidx-core-ktx-version-1",
                      "WeyGZ8R6LXB0qgrMNVCUE2jdcHA", "androidx/core/app/NotificationCompat",
                      "eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoiYWRtaW4ifQ"):
            self.assertFalse(self.keep(noise), noise)

    def test_real_keys_kept(self):
        for key in ("k8Jd92LsPq0Zx7Vb3NmQw5RtYh1UeC6a", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"):
            self.assertTrue(self.keep(key), key)


class CleartextNoise(unittest.TestCase):
    def test_noise(self):
        for u in (b"http://ocsp.apple.com/ocsp03", b"http://crl.apple.com/root.crl", b"http://www.w3.org/2000/svg",
                  b"http://xmlpull.org/v1/doc/features.html", b"http://localhost/x", b"http://reactjs.org/docs",
                  b"http://%", b"http://%@/path", b"http://{host}/x", b"http://example.invalid"):
            self.assertTrue(engine._is_noise_cleartext_url(u), u)

    def test_real_endpoints_kept(self):
        for u in (b"http://api.ipify.org/", b"http://backoffice.example-broker.com/x", b"http://115.111.65.148"):
            self.assertFalse(engine._is_noise_cleartext_url(u), u)


if __name__ == "__main__":
    unittest.main()
