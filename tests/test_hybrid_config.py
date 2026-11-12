import json
import os
import tempfile
import unittest

from appsleuth import engine
from tests.test_cordova_android import axml, make_apk

PLUGINS_JS = '''cordova.define('cordova/plugin_list', function(require, exports, module) {
module.exports = [];
module.exports.metadata = {
  "cordova-plugin-device": "2.0.3",
  "cordova-plugin-inappbrowser": "5.0.0"
};
});
'''


def ios_app(config_xml=None, capacitor=None, index="<html><head></head></html>", plugins=PLUGINS_JS):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "www"))
    if config_xml is not None:
        open(os.path.join(d, "config.xml"), "w").write(config_xml)
    if capacitor is not None:
        open(os.path.join(d, "capacitor.config.json"), "w").write(json.dumps(capacitor))
    open(os.path.join(d, "www", "index.html"), "w").write(index)
    if plugins:
        open(os.path.join(d, "www", "cordova_plugins.js"), "w").write(plugins)
    return d


def run(app_dir, frameworks=("Cordova.framework",)):
    fb, meta = engine.FindingsBag(), {}
    engine.analyze_hybrid_web(app_dir, list(frameworks), fb, meta, "App")
    return fb, meta


def titles(fb):
    return [f.title for f in fb.items]


CSP = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'">'


class CordovaConfig(unittest.TestCase):
    def test_remote_http_start_page_is_high_with_line(self):
        fb, _ = run(ios_app('<widget id="x">\n  <content src="http://dev.example.com/start" />\n</widget>'))
        f = next(f for f in fb.items if f.title.startswith("Cordova start page is a remote URL"))
        self.assertEqual((f.severity, f.location), ("HIGH", "config.xml:2"))

    def test_local_start_page_not_flagged(self):
        fb, _ = run(ios_app('<widget id="x"><content src="index.html" /></widget>'))
        self.assertFalse(any("start page" in t for t in titles(fb)))

    def test_risky_preferences(self):
        fb, _ = run(ios_app('<widget id="x">\n<preference name="AndroidInsecureFileModeEnabled" value="true" />\n'
                            '<preference name="AllowUntrustedCerts" value="true" />\n'
                            '<preference name="scheme" value="http" />\n'
                            '<preference name="BackupWebStorage" value="cloud" />\n'
                            '<preference name="Orientation" value="portrait" />\n</widget>'))
        got = {f.title: f.severity for f in fb.items}
        self.assertEqual(got["Cordova AndroidInsecureFileModeEnabled is on"], "MEDIUM")
        self.assertEqual(got["Cordova accepts untrusted TLS certificates (AllowUntrustedCerts)"], "HIGH")
        self.assertEqual(got["Cordova serves the app over http:// (scheme=http)"], "MEDIUM")
        self.assertEqual(got["Cordova web storage is included in iCloud backups (BackupWebStorage=cloud)"], "LOW")

    def test_safe_preferences_not_flagged(self):
        fb, _ = run(ios_app('<widget id="x"><preference name="AndroidInsecureFileModeEnabled" value="false" />'
                            '<preference name="scheme" value="https" /></widget>'))
        self.assertFalse(any(f.severity in ("MEDIUM", "HIGH") and "Cordova" in f.title for f in fb.items))

    def test_csp_missing_present_and_weak(self):
        fb, _ = run(ios_app('<widget id="x"></widget>'))
        f = next(f for f in fb.items if f.title == "No Content-Security-Policy in index.html")
        self.assertEqual((f.severity, f.location), ("MEDIUM", "www/index.html"))
        fb, meta = run(ios_app('<widget id="x"></widget>', index="<html><head>" + CSP + "</head></html>"))
        self.assertFalse(any("Content-Security-Policy" in t for t in titles(fb)))
        weak = '<meta http-equiv="Content-Security-Policy" content="default-src *; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'">'
        fb, _ = run(ios_app('<widget id="x"></widget>', index="<html><head>" + weak + "</head></html>"))
        f = next(f for f in fb.items if f.title == "Weak Content-Security-Policy in index.html")
        self.assertIn("unsafe-inline", f.detail)
        self.assertIn("unsafe-eval", f.detail)

    def test_plugin_versions(self):
        fb, meta = run(ios_app('<widget id="x"></widget>'))
        self.assertEqual(meta["hybrid"]["plugin_versions"],
                         {"cordova-plugin-device": "2.0.3", "cordova-plugin-inappbrowser": "5.0.0"})
        f = next(f for f in fb.items if f.title.startswith("2 plugin(s) bundled"))
        self.assertIn("cordova-plugin-device 2.0.3", f.evidence)


class CapacitorConfig(unittest.TestCase):
    def test_capacitor_settings(self):
        fb, _ = run(ios_app(capacitor={"server": {"androidScheme": "http"},
                                       "android": {"allowMixedContent": True, "webContentsDebuggingEnabled": True}},
                            plugins=None), frameworks=("Capacitor.framework",))
        t = titles(fb)
        self.assertIn("Capacitor allows mixed content (android.allowMixedContent)", t)
        self.assertIn("Capacitor serves the app over http:// (server.androidScheme/iosScheme)", t)
        self.assertIn("WebView debugging enabled in release config", t)
        self.assertIn("No Content-Security-Policy in index.html", t)


class AndroidCompiledConfig(unittest.TestCase):
    def test_binary_config_checked_with_lines(self):
        apk = make_apk([("widget", {"id": "x"}, 2), ("content", {"src": "https://app.example.com/"}, 3),
                        ("preference", {"name": "AndroidInsecureFileModeEnabled", "value": "true"}, 4)])
        fb, _ = engine.analyze_apk(apk, tempfile.mkdtemp())
        loc = {f.title: f.location for f in fb.items}
        self.assertEqual(loc["Cordova start page is a remote URL (<content src>)"], "res/xml/config.xml:3")
        self.assertEqual(loc["Cordova AndroidInsecureFileModeEnabled is on"], "res/xml/config.xml:4")


if __name__ == "__main__":
    unittest.main()
