// AppSleuth runtime probe (iOS). OBSERVE ONLY: logs what the app does, changes nothing.
'use strict';
function emit(t, o) { send(Object.assign({ t: t }, o || {})); }
function trunc(s, n) { s = String(s); return s.length > n ? s.slice(0, n) : s; }
function tryHook(fn) { try { fn(); } catch (e) { emit('probe_error', { what: String(e) }); } }

var JB = /(Cydia|Sileo|Zebra|MobileSubstrate|\/bin\/bash|\/usr\/sbin\/sshd|\/etc\/apt|\/private\/var\/lib\/apt|\/Applications\/Filza|palera1n|\/var\/jb)/;

// --- jailbreak checks the app performs (file probes) ---------------------------------------
['stat', 'lstat', 'access', 'fopen', 'open'].forEach(function (name) {
  tryHook(function () {
    var addr = Module.findExportByName(null, name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          var p = args[0].readUtf8String();
          if (p && JB.test(p)) emit('root_check', { how: name, arg: trunc(p, 120) });
        } catch (e) {}
      }
    });
  });
});

if (ObjC.available) {
  // --- plaintext HTTP requests ---------------------------------------------------------------
  tryHook(function () {
    var m = ObjC.classes.NSURLRequest['+ requestWithURL:'];
    Interceptor.attach(m.implementation, { onEnter: function (a) {
      var u = new ObjC.Object(a[2]).absoluteString().toString();
      if (u.indexOf('http://') === 0) emit('cleartext', { url: trunc(u, 200) });
    }});
  });
  // --- NSUserDefaults writes -------------------------------------------------------------------
  tryHook(function () {
    var m = ObjC.classes.NSUserDefaults['- setObject:forKey:'];
    Interceptor.attach(m.implementation, { onEnter: function (a) {
      var k = new ObjC.Object(a[3]).toString();
      var v = a[2].isNull() ? '' : new ObjC.Object(a[2]).toString();
      emit('prefs_write', { key: trunc(k, 80), value: trunc(v, 400) });
    }});
  });
  // --- NSLog output ----------------------------------------------------------------------------
  tryHook(function () {
    var addr = Module.findExportByName('Foundation', 'NSLog');
    if (addr) Interceptor.attach(addr, { onEnter: function (a) {
      emit('log', { tag: 'NSLog', msg: trunc(new ObjC.Object(a[0]).toString(), 400) });
    }});
  });
  // --- keychain items stored with weak accessibility ---------------------------------------------
  tryHook(function () {
    var addr = Module.findExportByName('Security', 'SecItemAdd');
    if (addr) Interceptor.attach(addr, { onEnter: function (a) {
      var d = new ObjC.Object(a[0]);
      var acc = d.objectForKey_('pdmn');
      if (acc) emit('keychain_add', { accessible: trunc(acc.toString(), 60) });
    }});
  });
}
emit('ready', { platform: 'ios' });
