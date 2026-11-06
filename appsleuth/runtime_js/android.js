// AppSleuth runtime probe (Android). OBSERVE ONLY: it logs what the app does and never
// changes behaviour (no bypasses). Events are sent to the host as {t: <kind>, ...}.
'use strict';
function emit(t, o) { send(Object.assign({ t: t }, o || {})); }
function trunc(s, n) { s = String(s); return s.length > n ? s.slice(0, n) : s; }

Java.perform(function () {
  function tryHook(fn) { try { fn(); } catch (e) { emit('probe_error', { what: String(e) }); } }

  // --- root / tamper checks the app performs --------------------------------------------
  tryHook(function () {
    var File = Java.use('java.io.File');
    var ex = File.exists.overload();
    ex.implementation = function () {
      var p = this.getAbsolutePath();
      if (/\/su$|magisk|busybox|supersu|xbin/i.test(p)) emit('root_check', { how: 'File.exists', arg: trunc(p, 120) });
      return ex.call(this);
    };
  });
  tryHook(function () {
    var Runtime = Java.use('java.lang.Runtime');
    var ex = Runtime.exec.overload('java.lang.String');
    ex.implementation = function (cmd) {
      if (/(^|\s|\/)su(\s|$)|which su/.test(cmd)) emit('root_check', { how: 'Runtime.exec', arg: trunc(cmd, 120) });
      return ex.call(this, cmd);
    };
  });

  // --- certificate pinning actually in use -----------------------------------------------
  tryHook(function () {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function (host, certs) {
      emit('pinning', { how: 'okhttp3.CertificatePinner', host: trunc(host, 120) });
      return this.check(host, certs);
    };
  });

  // --- plaintext HTTP the app really requests --------------------------------------------
  tryHook(function () {
    var URL = Java.use('java.net.URL');
    var oc = URL.openConnection.overload();
    oc.implementation = function () {
      var u = this.toString();
      if (u.indexOf('http://') === 0) emit('cleartext', { url: trunc(u, 200) });
      return oc.call(this);
    };
  });

  // --- crypto the app really uses ---------------------------------------------------------
  tryHook(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    var gi = Cipher.getInstance.overload('java.lang.String');
    gi.implementation = function (t) { emit('cipher', { alg: trunc(t, 80) }); return gi.call(this, t); };
  });
  tryHook(function () {
    var MD = Java.use('java.security.MessageDigest');
    var gi = MD.getInstance.overload('java.lang.String');
    gi.implementation = function (a) { emit('digest', { alg: trunc(a, 40) }); return gi.call(this, a); };
  });

  // --- secrets written to SharedPreferences / logcat --------------------------------------
  tryHook(function () {
    var Ed = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    var ps = Ed.putString.overload('java.lang.String', 'java.lang.String');
    ps.implementation = function (k, v) {
      emit('prefs_write', { key: trunc(k, 80), value: trunc(v === null ? '' : v, 400) });
      return ps.call(this, k, v);
    };
  });
  tryHook(function () {
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
  tryHook(function () {
    var WV = Java.use('android.webkit.WebView');
    var sd = WV.setWebContentsDebuggingEnabled;
    sd.implementation = function (on) { if (on) emit('webview_debug', {}); return sd.call(this, on); };
  });

  emit('ready', { platform: 'android' });
});
