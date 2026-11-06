// AppSleuth runtime probe (iOS). OBSERVE ONLY: logs what the app does, changes nothing.
'use strict';
import ObjC from 'frida-objc-bridge';
function emit(t, o) { send(Object.assign({ t: t }, o || {})); }
function trunc(s, n) { s = String(s); return s.length > n ? s.slice(0, n) : s; }
function tryHook(fn) { try { fn(); } catch (e) { emit('probe_error', { what: String(e) }); } }

var JB = /(Cydia|Sileo|Zebra|MobileSubstrate|\/bin\/bash|\/usr\/sbin\/sshd|\/etc\/apt|\/private\/var\/lib\/apt|\/Applications\/Filza|palera1n|\/var\/jb)/;

// --- jailbreak checks the app performs (file probes) ---------------------------------------
['stat', 'lstat', 'access', 'fopen', 'open'].forEach(function (name) {
  tryHook(function () {
    var addr = Module.getGlobalExportByName(name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          // Count only probes made by the app's own code (main binary / embedded frameworks),
          // not by the jailbreak's tweak loader or system libraries touching the same paths.
          var mod = Process.findModuleByAddress(this.returnAddress);
          if (!mod || mod.path.indexOf('.app/') < 0) return;
          var p = args[0].readUtf8String();
          if (p && JB.test(p)) emit('root_check', { how: name, arg: trunc(p, 120) });
        } catch (e) {}
      }
    });
  });
});

// With --spawn the probe loads before the app has loaded its frameworks, so ObjC hooks retry
// until the class/selector exists (up to ~15 s) and report precisely what could not be hooked.
function hookObjC(cls, sel, onEnter, tries) {
  tries = tries || 0;
  var k = ObjC.classes[cls];
  var m = k && k[sel];
  if (m) {
    try { Interceptor.attach(m.implementation, { onEnter: onEnter }); return; }
    catch (e) { emit('probe_error', { what: cls + ' ' + sel + ': ' + String(e) }); return; }
  }
  if (tries < 30) setTimeout(function () { hookObjC(cls, sel, onEnter, tries + 1); }, 500);
  else emit('probe_error', { what: 'not found: ' + cls + ' ' + sel });
}
function hookExport(mod, name, onEnter, tries) {
  tries = tries || 0;
  try {
    var addr = Process.getModuleByName(mod).findExportByName(name);
    if (addr) { Interceptor.attach(addr, { onEnter: onEnter }); return; }
  } catch (e) {}
  if (tries < 30) setTimeout(function () { hookExport(mod, name, onEnter, tries + 1); }, 500);
  else emit('probe_error', { what: 'not found: ' + mod + '!' + name });
}

if (ObjC.available) {
  var seenUrl = {};
  function noteUrl(urlObj) {
    try {
      var u = new ObjC.Object(urlObj).absoluteString().toString();
      if (u.indexOf('http://') === 0 && !seenUrl[u]) { seenUrl[u] = 1; emit('cleartext', { url: trunc(u, 200) }); }
    } catch (e) {}
  }
  hookObjC('NSURLRequest', '+ requestWithURL:', function (a) { noteUrl(a[2]); });
  hookObjC('NSURLRequest', '- initWithURL:', function (a) { noteUrl(a[2]); });
  hookObjC('NSMutableURLRequest', '- setURL:', function (a) { noteUrl(a[2]); });
  hookObjC('NSURLSession', '- dataTaskWithURL:', function (a) { noteUrl(a[2]); });
  hookObjC('NSUserDefaults', '- setObject:forKey:', function (a) {
    try {
      var k = new ObjC.Object(a[3]).toString();
      var v = a[2].isNull() ? '' : new ObjC.Object(a[2]).toString();
      emit('prefs_write', { key: trunc(k, 80), value: trunc(v, 400) });
    } catch (e) {}
  });
  hookExport('Foundation', 'NSLog', function (a) {
    try { emit('log', { tag: 'NSLog', msg: trunc(new ObjC.Object(a[0]).toString(), 400) }); } catch (e) {}
  });
  hookExport('Security', 'SecItemAdd', function (a) {
    try {
      var acc = new ObjC.Object(a[0]).objectForKey_('pdmn');
      if (acc) emit('keychain_add', { accessible: trunc(acc.toString(), 60) });
    } catch (e) {}
  });
}
emit('ready', { platform: 'ios' });
