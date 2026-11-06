import os
import tempfile
import unittest

from appsleuth import triage


def F(sev, title, loc=None, conf="heuristic"):
    return {"severity": sev, "title": title, "detail": "d", "evidence": None, "location": loc, "confidence": conf}


def result(kind, findings, meta=None):
    return {"detected_type": kind, "meta": meta or {}, "findings": findings,
            "summary": {}}


class Corroboration(unittest.TestCase):
    CT = "Cleartext (http://) URLs embedded in binary"

    def test_ios_with_default_ats_demotes_cleartext(self):
        out = triage.apply(result("ipa", [F("MEDIUM", self.CT)]))
        self.assertEqual(out["findings"][0]["severity"], "INFO")
        self.assertEqual(out["triage"]["demoted"][0]["from"], "MEDIUM")

    def test_ios_with_ats_disabled_keeps_it(self):
        out = triage.apply(result("ipa", [F("HIGH", "App Transport Security disabled globally (x)"), F("MEDIUM", self.CT)]))
        self.assertEqual([f["severity"] for f in out["findings"] if f["title"] == self.CT], ["MEDIUM"])

    def test_android_target28_demotes_but_cleartext_flag_keeps(self):
        meta = {"targetSdkVersion": "33"}
        self.assertEqual(triage.apply(result("apk", [F("MEDIUM", self.CT)], meta))["findings"][0]["severity"], "INFO")
        kept = triage.apply(result("apk", [F("HIGH", 'android:usesCleartextTraffic="true"'), F("MEDIUM", self.CT)], meta))
        self.assertIn("MEDIUM", [f["severity"] for f in kept["findings"]])

    def test_old_target_sdk_not_demoted(self):
        out = triage.apply(result("apk", [F("MEDIUM", self.CT)], {"targetSdkVersion": "23"}))
        self.assertEqual(out["findings"][0]["severity"], "MEDIUM")


class SplitApks(unittest.TestCase):
    def test_config_split_noise_dropped_base_kept(self):
        fs = [F("MEDIUM", "No classes.dex found (heuristic)", "[split_config.en.apk] "),
              F("MEDIUM", "android:allowBackup not disabled", "[split_config.en.apk] AndroidManifest.xml <application>"),
              F("MEDIUM", "android:allowBackup not disabled", "AndroidManifest.xml <application>")]
        out = triage.apply(result("apks", fs))
        self.assertEqual([f["location"] for f in out["findings"]], ["AndroidManifest.xml <application>"])


class Rules(unittest.TestCase):
    def write(self, text):
        fd, path = tempfile.mkstemp(suffix=".ignore")
        os.write(fd, text.encode())
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_rules_and_reasons_recorded(self):
        rules = triage.load_ignore_file(self.write(
            "# comment\ntitle: MD5 hash -- cache keys only\nlocation: *vendor/sdk*\ntitle: /^Weak .* identifiers$/\n"))
        fs = [F("INFO", "MD5 hash identifier present"), F("LOW", "x", "a/vendor/sdk/b"),
              F("LOW", "Weak cipher identifiers"), F("MEDIUM", "keep me")]
        out = triage.apply(result("apk", fs), rules=rules)
        self.assertEqual([f["title"] for f in out["findings"]], ["keep me"])
        self.assertEqual(out["triage"]["ignored_by_rule"][0]["reason"], "cache keys only")

    def test_bad_rule_line_is_an_error(self):
        with self.assertRaises(ValueError):
            triage.load_ignore_file(self.write("nonsense line\n"))


class Thresholds(unittest.TestCase):
    def test_min_confidence_hides_but_records(self):
        fs = [F("HIGH", "a", conf="confirmed"), F("HIGH", "b", conf="heuristic")]
        out = triage.apply(result("apk", fs), min_confidence="confirmed", corroborate=False)
        self.assertEqual([f["title"] for f in out["findings"]], ["a"])
        self.assertEqual(out["triage"]["hidden_by_threshold"][0]["title"], "b")

    def test_duplicates_collapsed(self):
        out = triage.apply(result("apk", [F("LOW", "x", "l"), F("LOW", "x", "l")]))
        self.assertEqual(len(out["findings"]), 1)


if __name__ == "__main__":
    unittest.main()


class CoverageWarnings(unittest.TestCase):
    def test_encrypted_main_binary_warns(self):
        from appsleuth import info
        r = result("ipa", [], {"macho_encryption_verified": [{"verdict": "ciphertext"}]})
        self.assertIn("main binary is still FairPlay-encrypted", info.coverage_warnings(r)[0])

    def test_decrypted_is_silent(self):
        from appsleuth import info
        r = result("ipa", [], {"macho_encryption_verified": [{"verdict": "decrypted"}],
                               "embedded_binaries_still_encrypted": []})
        self.assertEqual(info.coverage_warnings(r), [])

    def test_embedded_listed(self):
        from appsleuth import info
        r = result("ipa", [], {"embedded_binaries_still_encrypted": ["Frameworks/X.framework/X"]})
        self.assertIn("X.framework", info.coverage_warnings(r)[0])


class TestFixtures(unittest.TestCase):
    T = "Possible hardcoded secret: JWT (decodes as a valid token)"

    def test_test_fixture_class_demoted(self):
        out = triage.apply(result("apk", [
            F("HIGH", self.T, "base.apk:dex (classes.dex) [Lcom/google/api/client/testing/json/webtoken/TestCertificates;->getJsonWebSignature()]"),
            F("HIGH", self.T, "base.apk:dex (classes.dex) [Lcom/example/app/Session;->token()]")]))
        sev = {f["location"].split("[")[-1][:25]: f["severity"] for f in out["findings"]}
        self.assertEqual(sorted(sev.values()), ["HIGH", "INFO"])
        self.assertEqual(sev["Lcom/example/app/Session;"], "HIGH")
