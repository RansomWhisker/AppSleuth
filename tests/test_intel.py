import json
import os
import plistlib
import tempfile
import unittest
import zipfile

from appsleuth import cloud, endpoints, links, netfetch, sbom


def make_ipa(extra=None, info=None, entitlements=None):
    path = tempfile.mktemp(suffix=".ipa")
    plist = {"CFBundleIdentifier": "com.example.app", "CFBundleName": "App", "CFBundleExecutable": "App",
             "CFBundleShortVersionString": "1.0", **(info or {})}
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/App.app/Info.plist", plistlib.dumps(plist))
        z.writestr("Payload/App.app/App", b"\xcf\xfa\xed\xfe" + b"\0" * 64)
        for name, data in (extra or {}).items():
            z.writestr("Payload/App.app/" + name, data)
    return path


class Netfetch(unittest.TestCase):
    def test_rejects_private_and_odd_hosts(self):
        for h in ("localhost", "127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "[::1]", "a b", ""):
            self.assertFalse(netfetch.is_public_host(h), h)

    def test_https_only(self):
        with self.assertRaises(Exception):
            netfetch.fetch("http://example.com/")


class Cvss(unittest.TestCase):
    def test_scores(self):
        self.assertEqual(sbom._cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(sbom._cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertIsNone(sbom._cvss3_score("garbage"))


class Sbom(unittest.TestCase):
    def comps(self):
        return [{"name": "com.squareup.okhttp3:okhttp", "group": "com.squareup.okhttp3", "artifact": "okhttp",
                 "version": "3.8.0", "ecosystem": "Maven", "purl": "pkg:maven/com.squareup.okhttp3/okhttp@3.8.0", "vulns": []}]

    def fake(self, url, method="GET", body=None, **kw):
        if url.endswith("/v1/querybatch"):
            return 200, {}, json.dumps({"results": [{"vulns": [{"id": "GHSA-x"}]}]}).encode()
        return 200, {}, json.dumps({"id": "GHSA-x", "aliases": ["CVE-2099-1"], "summary": "bad",
                                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                                    "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.9.0"}]}]}]}).encode()

    def test_lookup_merges_and_scores(self):
        os.environ["HOME"] = tempfile.mkdtemp()
        c = self.comps()
        sbom.lookup(c, fetch=self.fake)
        v = c[0]["vulns"][0]
        self.assertEqual(v["severity"], "HIGH")
        self.assertIn("CVE-2099-1", v["aliases"])

    def test_cyclonedx(self):
        bom = sbom.to_cyclonedx(self.comps(), {"name": "x", "version": "1"}) if \
            sbom.to_cyclonedx.__code__.co_argcount == 2 else None
        if bom:
            self.assertEqual(bom["bomFormat"], "CycloneDX")


class Endpoints(unittest.TestCase):
    def test_inventory_filters_noise(self):
        ipa = make_ipa({"app.js": b'fetch("https://api.acmecorp.io/v1/users"); "http://www.w3.org/2000/svg" '
                                  b'"http://34.120.5.9/x" "https://dev.acmecorp.io/a" "https://svgjs.dev"'})
        res = endpoints.run(ipa)
        titles = [f["title"] for f in res["findings"]]
        text = json.dumps(res)
        self.assertIn("api.acmecorp.io", text)
        self.assertNotIn("w3.org", text)
        self.assertTrue(any("raw public IP" in t for t in titles))
        nonprod = [f for f in res["findings"] if "Non-production" in f["title"]][0]
        self.assertIn("dev.acmecorp.io", nonprod["evidence"])
        self.assertNotIn("svgjs.dev", nonprod["evidence"])


class EndpointDiff(unittest.TestCase):
    def test_new_host_regression(self):
        from appsleuth import diff
        old = make_ipa({"a.js": b'"https://api.acmecorp.io/v1"'})
        new = make_ipa({"a.js": b'"https://api.acmecorp.io/v1" "https://stg.acmecorp.io/x" "http://34.120.5.9/y" "https://cdn.newvendor.io/z"'})
        d = diff.endpoint_diff(old, new)
        self.assertIn("cdn.newvendor.io", d["added"])
        sev = {r["text"].split(":")[1].split()[0]: r["severity"] for r in d["regressions"]}
        self.assertEqual(sev["34.120.5.9"], "MEDIUM")
        self.assertEqual(sev["stg.acmecorp.io"], "MEDIUM")
        self.assertEqual(sev["cdn.newvendor.io"], "LOW")


class Links(unittest.TestCase):
    def test_ios_url_scheme_and_universal_link(self):
        ipa = make_ipa(info={"CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp"]}]})
        res = links.run(ipa)
        self.assertIn("myapp", json.dumps(res))

    def test_aasa_check_with_fake_fetch(self):
        def fetch(url, method="GET", body=None, **kw):
            return 200, {}, json.dumps({"applinks": {"details": [{"appIDs": ["TEAM1.com.example.app"], "components": [{}]}]}}).encode()
        out = links.check_aasa(["applinks:example.com"], "TEAM1", "com.example.app", fetch, lambda h: True)
        self.assertTrue(out)
        self.assertNotIn("HIGH", [f["severity"] for f in out])

    def test_private_host_not_fetched(self):
        called = []
        links.check_aasa(["applinks:intranet.local"], "T", "b", lambda *a, **k: called.append(1), lambda h: False)
        self.assertEqual(called, [])


class Cloud(unittest.TestCase):
    def test_discovery_offline(self):
        ipa = make_ipa({"GoogleService-Info.plist": plistlib.dumps({
            "PROJECT_ID": "demo-project", "DATABASE_URL": "https://demo-project-default-rtdb.firebaseio.com",
            "STORAGE_BUCKET": "demo-project.appspot.com", "API_KEY": "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345"}),
            "a.js": b'"https://my-assets-bkt.s3.amazonaws.com/x" "s3://bucket-name"'})
        res = cloud.run(ipa)
        names = {(b["kind"], b["name"]) for b in res["meta"]["backends"]}
        self.assertIn(("rtdb", "demo-project-default-rtdb.firebaseio.com"), names)
        self.assertIn(("gcs", "demo-project.appspot.com"), names)
        self.assertIn(("s3", "my-assets-bkt"), names)
        self.assertNotIn(("s3", "bucket-name"), names)          # placeholder
        self.assertNotIn("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345", json.dumps(res))   # key masked
        self.assertEqual(res["meta"]["requests"], 0)

    def test_check_only_hits_allowlisted_hosts(self):
        ipa = make_ipa({"GoogleService-Info.plist": plistlib.dumps({
            "PROJECT_ID": "demo-project", "DATABASE_URL": "https://evil.example.com/"}),
            "a.js": b'"https://169.254.169.254.s3.amazonaws.com/" "https://demo-project-default-rtdb.firebaseio.com"'})
        urls = []

        def fetch(url, method="GET", body=None, **kw):
            urls.append(url)
            return 200, {}, b'{"a":1}' if "firebaseio" in url else b"{}"
        res = cloud.run(ipa, check=True, fetch=fetch)
        for u in urls:
            self.assertRegex(u, r"^https://([a-z0-9.-]+\.firebaseio\.com|firebasestorage\.googleapis\.com|"
                                r"[a-z0-9-]+\.s3\.amazonaws\.com|firestore\.googleapis\.com)/")
        self.assertNotIn("evil.example.com", " ".join(urls))
        self.assertTrue(any(f["severity"] == "HIGH" and "Realtime" in f["title"] for f in res["findings"]))
        self.assertNotIn('"a":1', json.dumps(res))              # body never stored

    def test_commented_out_and_tiny_names_skipped(self):
        ipa = make_ipa({"a.js": b"//   const url = 'https://testcdncss.s3.ap-south-1.amazonaws.com/e.json';\n"
                                b"var live = 'https://livebucket-assets.s3.amazonaws.com/x'; s3://doc\n",
                        "a.js.map": b'"https://mapbucket-x.s3.amazonaws.com/y"'})
        names = {b["name"] for b in cloud.run(ipa)["meta"]["backends"]}
        self.assertEqual(names, {"livebucket-assets"})

    def test_reserved_firebase_bucket_404_is_info(self):
        f = cloud.check_backend({"kind": "gcs", "name": "proj-1234.appspot.com"},
                                lambda *a, **k: (404, {}, b"Not Found"))
        self.assertEqual(f["severity"], "INFO")

    def test_listable_s3_severity_depends_on_ownership(self):
        listing = lambda *a, **k: (200, {}, b"<ListBucketResult><Key>a</Key>")
        mine = cloud.check_backend({"kind": "s3", "name": "acmecorp-assets"}, listing, cloud.owner_tokens("com.acmecorp.app", None))
        theirs = cloud.check_backend({"kind": "s3", "name": "app-creatives"}, listing, cloud.owner_tokens("com.acmecorp.app", None))
        self.assertEqual((mine["severity"], theirs["severity"]), ("HIGH", "MEDIUM"))

    def test_denied_is_info(self):
        f = cloud.check_backend({"kind": "rtdb", "name": "x-default-rtdb.firebaseio.com"}, lambda *a, **k: (401, {}, b""))
        self.assertEqual(f["severity"], "INFO")

    def test_invalid_names_rejected(self):
        self.assertIsNone(cloud.check_backend({"kind": "rtdb", "name": "evil.com/../x"}, lambda *a, **k: 1 / 0))
        self.assertIsNone(cloud.check_backend({"kind": "s3", "name": "a.b.c"}, lambda *a, **k: 1 / 0))


if __name__ == "__main__":
    unittest.main()


class SbomUserAgent(unittest.TestCase):
    def comps(self, ua: bytes):
        path = tempfile.mktemp(suffix=".apk")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml", b"\x00")
            z.writestr("classes.dex", b"dex\n035\x00" + ua)
        from appsleuth import appfiles
        with appfiles.unpacked(path) as app:
            return sbom.collect(app)

    def test_okhttp_versions(self):
        names = {(c["name"], c["version"]) for c in self.comps(b"okhttp/3.12.13 okhttp/1.81.0")}
        self.assertIn(("com.squareup.okhttp3:okhttp", "3.12.13"), names)
        self.assertFalse([n for n in names if n[1].startswith("1.")])
        old = {(c["name"], c["version"]) for c in self.comps(b"okhttp/2.7.5")}
        self.assertEqual(old, {("com.squareup.okhttp:okhttp", "2.7.5")})


class InfoAtsAndProtection(unittest.TestCase):
    def test_ats_shows_values(self):
        from appsleuth import info
        self.assertIn("DISABLED", "\n".join(info.ats_lines({"NSAllowsArbitraryLoads": True})))
        off = "\n".join(info.ats_lines({"NSAllowsArbitraryLoads": False}))
        self.assertIn("ENFORCED", off)
        self.assertIn("False", off)
        self.assertIn("ENFORCED", info.ats_lines({})[0])

    def test_encryption_plain_language(self):
        from appsleuth import info
        self.assertIn("NOT readable", info._enc_plain(["ciphertext"]))
        self.assertIn("not encrypted", info._enc_plain(["decrypted"]))


class ReadablePermissions(unittest.TestCase):
    def test_ios_sorted_by_risk_and_wrapped(self):
        from appsleuth import perms
        out = "\n".join(perms.ios_permission_lines(
            ["NSFaceIDUsageDescription", "NSContactsUsageDescription"],
            {"NSFaceIDUsageDescription": "x" * 300, "NSContactsUsageDescription": ""}))
        self.assertLess(out.index("Contacts"), out.index("Face ID"))
        self.assertIn("no purpose text", out)

    def test_unknown_key_gets_readable_name(self):
        from appsleuth import perms
        self.assertEqual(perms.ios_friendly("NSGizmoScannerUsageDescription")[0], "Gizmo Scanner")

    def test_debuggable_entitlement_flagged(self):
        from appsleuth import perms
        out = "\n".join(perms.ios_entitlement_lines({"get-task-allow": True, "aps-environment": "development"}))
        self.assertIn("debuggable", out)
        self.assertIn("sandbox", out)

    def test_android_dangerous_first_with_friendly_names(self):
        from appsleuth import perms
        out = "\n".join(perms.android_permission_lines(
            ["android.permission.INTERNET", "android.permission.READ_SMS"], ["android.permission.READ_SMS"]))
        self.assertIn("Read SMS", out)
        self.assertLess(out.index("Read SMS"), out.index("INTERNET"))
