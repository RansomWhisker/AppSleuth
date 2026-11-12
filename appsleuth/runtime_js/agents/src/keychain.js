// AppSleuth keychain reader (iOS). Runs inside the target app and asks the keychain for the items that
// app itself can see (its own access groups), including their values. Read-only: nothing is written.
'use strict';
import ObjC from 'frida-objc-bridge';
function emit(t, o) { send(Object.assign({ t: t }, o || {})); }
function trunc(s, n) { s = String(s); return s.length > n ? s.slice(0, n) : s; }
function sym(name) { return Module.getGlobalExportByName(name); }
function constant(name) { return new ObjC.Object(sym(name).readPointer()); }

var CLASSES = [['kSecClassGenericPassword', 'password'], ['kSecClassInternetPassword', 'internet password'],
               ['kSecClassCertificate', 'certificate'], ['kSecClassKey', 'key'], ['kSecClassIdentity', 'identity']];

function field(d, k) {
  var v = d.objectForKey_(k);
  return v ? v.toString() : '';
}

// Text if it is valid UTF-8 without control characters; otherwise base64.
function readValue(d) {
  var data = d.objectForKey_('v_Data');
  if (!data) return null;
  var len = data.length().valueOf();
  if (len === 0) return { kind: 'empty', value: '', length: 0 };
  var text = null;
  try { text = data.bytes().readUtf8String(len); } catch (e) {}
  if (text !== null && text.length > 0 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f�]/.test(text))
    return { kind: 'text', value: trunc(text, 4096), length: len };
  return { kind: 'binary', value: 'base64:' + trunc(data.base64EncodedStringWithOptions_(0).toString(), 4096), length: len };
}

function run() {
  var copy = new NativeFunction(sym('SecItemCopyMatching'), 'int', ['pointer', 'pointer']);
  var yes = ObjC.classes.NSNumber.numberWithBool_(1);
  var total = 0;
  CLASSES.forEach(function (c) {
    try {
      var q = ObjC.classes.NSMutableDictionary.alloc().init();
      q.setObject_forKey_(constant(c[0]), constant('kSecClass'));
      q.setObject_forKey_(constant('kSecMatchLimitAll'), constant('kSecMatchLimit'));
      q.setObject_forKey_(yes, constant('kSecReturnAttributes'));
      q.setObject_forKey_(yes, constant('kSecReturnData'));
      q.setObject_forKey_(constant('kSecAttrSynchronizableAny'), constant('kSecAttrSynchronizable'));   // include iCloud-synced items
      var out = Memory.alloc(Process.pointerSize);
      out.writePointer(NULL);
      var st = copy(q.handle, out);
      emit('kc_status', { class: c[1], status: st });
      if (st !== 0 || out.readPointer().isNull()) return;
      var arr = new ObjC.Object(out.readPointer());
      var n = arr.count().valueOf();
      for (var i = 0; i < n; i++) {
        var d = arr.objectAtIndex_(i);
        var v = readValue(d);
        total++;
        emit('kc_item', {
          class: c[1], service: field(d, 'svce') || field(d, 'srvr'), account: field(d, 'acct'),
          label: field(d, 'labl'), group: field(d, 'agrp'), accessible: field(d, 'pdmn'),
          value: v ? v.value : null, kind: v ? v.kind : 'none', length: v ? v.length : 0
        });
      }
    } catch (e) { emit('kc_error', { class: c[1], what: String(e) }); }
  });
  emit('kc_done', { items: total });
}
// Give a freshly spawned app a moment to load Security.framework.
setTimeout(function () {
  try { run(); } catch (e) { emit('kc_error', { what: String(e) }); emit('kc_done', { items: 0 }); }
}, 1500);
