// AppSleuth runtime probe (Android). OBSERVE ONLY: it logs what the app does and never
// changes behaviour (no bypasses). Events are sent to the host as {t: <kind>, ...}.
'use strict';
import Java from 'frida-java-bridge';
function emit(t, o) { send(Object.assign({ t: t }, o || {})); }
function trunc(s, n) { s = String(s); return s.length > n ? s.slice(0, n) : s; }

var SKIP = [];
function install() {
  function tryHook(name, fn) {
    if (SKIP.indexOf(name) >= 0) return;
   
    try { fn(); } catch (e) {
      var m = String(e);
      if (/ClassNotFoundException|NoSuchMethodError|no such method|not a function/i.test(m)) return;   // library not in this app
      emit('probe_error', { what: m.slice(0, 200) });
    }
  }

  // --- root / tamper checks the app performs --------------------------------------------
  tryHook('file_exists', function () {
    var File = Java.use('java.io.File');
    var ex = File.exists.overload();
    ex.implementation = function () {
      var p = this.getAbsolutePath();
      if (/\/su$|magisk|busybox|supersu|xbin/i.test(p)) emit('root_check', { how: 'File.exists', arg: trunc(p, 120) });
      return ex.call(this);
    };
  });
  tryHook('runtime_exec', function () {
    var Runtime = Java.use('java.lang.Runtime');
    var ex = Runtime.exec.overload('java.lang.String');
    ex.implementation = function (cmd) {
      if (/(^|\s|\/)su(\s|$)|which su/.test(cmd)) emit('root_check', { how: 'Runtime.exec', arg: trunc(cmd, 120) });
      return ex.call(this, cmd);
    };
  });

  // --- certificate pinning actually in use -----------------------------------------------
  tryHook('pinning', function () {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function (host, certs) {
      emit('pinning', { how: 'okhttp3.CertificatePinner', host: trunc(host, 120) });
      return this.check(host, certs);
    };
  });

  // --- plaintext HTTP the app really requests --------------------------------------------
  tryHook('cleartext', function () {
    var URL = Java.use('java.net.URL');
    var oc = URL.openConnection.overload();
    oc.implementation = function () {
      var u = this.toString();
      if (u.indexOf('http://') === 0) emit('cleartext', { url: trunc(u, 200) });
      return oc.call(this);
    };
  });

  // --- other HTTP stacks: Cronet, and TLS hostname verifiers (observe only) -----------------------------
  tryHook('cronet', function () {
    // Cronet builds requests through UrlRequest.Builder; the URL is the first constructor argument.
    var C = Java.use('org.chromium.net.impl.CronetUrlRequestContext');
    var nb = C.newUrlRequestBuilder.overload('java.lang.String', 'org.chromium.net.UrlRequest$Callback', 'java.util.concurrent.Executor');
    nb.implementation = function (url, cb, ex) {
      var u = String(url);
      if (u.indexOf('http://') === 0) emit('cleartext', { url: trunc(u, 200), via: 'cronet' });
      return nb.call(this, url, cb, ex);
    };
  });
  tryHook('hostname_verifier', function () {
    // HttpsURLConnection.setDefaultHostnameVerifier is where "accept any host" verifiers get installed.
    var H = Java.use('javax.net.ssl.HttpsURLConnection');
    var sv = H.setDefaultHostnameVerifier;
    sv.implementation = function (v) {
      emit('hostname_verifier', { cls: trunc(v ? v.$className : 'null', 120) });
      return sv.call(this, v);
    };
  });

  // --- crypto the app really uses ---------------------------------------------------------
  tryHook('cipher', function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    var gi = Cipher.getInstance.overload('java.lang.String');
    gi.implementation = function (t) { emit('cipher', { alg: trunc(t, 80) }); return gi.call(this, t); };
  });
  tryHook('digest', function () {
    var MD = Java.use('java.security.MessageDigest');
    var gi = MD.getInstance.overload('java.lang.String');
    gi.implementation = function (a) { emit('digest', { alg: trunc(a, 40) }); return gi.call(this, a); };
  });

  // --- secrets written to SharedPreferences / logcat --------------------------------------
  tryHook('prefs', function () {
    var Ed = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    var ps = Ed.putString.overload('java.lang.String', 'java.lang.String');
    ps.implementation = function (k, v) {
      emit('prefs_write', { key: trunc(k, 80), value: trunc(v === null ? '' : v, 400) });
      return ps.call(this, k, v);
    };
  });
  tryHook('log', function () {
    var Log = Java.use('android.util.Log');
    ['d', 'i', 'v', 'w', 'e'].forEach(function (lvl) {
      var o = Log[lvl].overload('java.lang.String', 'java.lang.String');
      o.implementation = function (tag, msg) {
        emit('log', { tag: trunc(tag, 40), msg: trunc(msg === null ? '' : msg, 400) });
        return o.call(this, tag, msg);
      };
    });
  });

  // --- debuggable WebViews -----------------------------------------------------------------
  tryHook('webview', function () {
    var WV = Java.use('android.webkit.WebView');
    var sd = WV.setWebContentsDebuggingEnabled;
    sd.implementation = function (on) { if (on) emit('webview_debug', {}); return sd.call(this, on); };
  });

  emit('ready', { platform: 'android' });
}

// The host sends {type:'config', skip:[hook names]} right after loading; hooks go in only then.
recv('config', function (m) {
  SKIP = (m && m.skip) || [];
  // Some apps crash if the Java bridge starts before they have booted; the host can ask for a delay.
  setTimeout(function () { Java.perform(install); }, (m && m.delay_ms) || 0);
});
