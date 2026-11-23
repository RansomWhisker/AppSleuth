// AppSleuth runtime probe (iOS). OBSERVE ONLY: logs what the app does, changes nothing.
'use strict';
import ObjC from 'frida-objc-bridge';

// ---- hook registry -------------------------------------------------------------------------
// Every hook has a name, a "found" flag and a call counter, so the report can show which hooks
// installed, which never fired, and which classes/functions were missing on this iOS version.
var HOOKS = {};
var EMIT_CAP = 500;           // per hook; counters keep counting past this
var CUR = null;               // name of the hook whose callback is running (tags emitted events)
function hk(name, optional) {
  var h = HOOKS[name];
  if (!h) h = HOOKS[name] = { installed: false, calls: 0, emitted: 0, optional: !!optional };
  return h;
}
function emit(t, o) {
  var m = Object.assign({ t: t }, o || {});
  if (CUR) {
    var h = HOOKS[CUR];
    if (h.emitted >= EMIT_CAP) return;
    h.emitted++;
    if (m.hook === undefined) m.hook = CUR;
  }
  send(m);
}
function counted(name, fn) {
  var h = hk(name);
  return function (a) {
    h.calls++;
    CUR = name;
    try { return fn.call(this, a); } catch (e) {} finally { CUR = null; }
  };
}
function trunc(s, n) { s = String(s); return s.length > n ? s.slice(0, n) : s; }
function tryHook(fn) { try { fn(); } catch (e) { emit('probe_error', { what: String(e) }); } }
var IMPLS = {};               // implementation address -> already hooked (subclasses share implementations)

recv('stats', function onStats() {
  send({ t: 'hook_stats', hooks: HOOKS });
  recv('stats', onStats);
});

var JB = /(Cydia|Sileo|Zebra|MobileSubstrate|\/bin\/bash|\/usr\/sbin\/sshd|\/etc\/apt|\/private\/var\/lib\/apt|\/Applications\/Filza|palera1n|\/var\/jb)/;

function fromApp(retAddr) {
  try {
    var mod = Process.findModuleByAddress(retAddr);
    return !!(mod && mod.path.indexOf('.app/') >= 0);
  } catch (e) { return false; }
}

// --- jailbreak checks the app performs (file probes) ---------------------------------------
['stat', 'lstat', 'access', 'fopen', 'open'].forEach(function (name) {
  tryHook(function () {
    var addr = Module.getGlobalExportByName(name);
    if (!addr) return;
    var hname = 'libc ' + name + '()';
    hk(hname).installed = true;
    Interceptor.attach(addr, {
      onEnter: counted(hname, function (args) {
        // Count only probes made by the app's own code (main binary / embedded frameworks),
        // not by the jailbreak's tweak loader or system libraries touching the same paths.
        if (!fromApp(this.returnAddress)) return;
        var p = args[0].readUtf8String();
        if (p && JB.test(p)) emit('root_check', { how: name, arg: trunc(p, 120) });
      })
    });
  });
});

// With --spawn the probe loads before the app has loaded its frameworks, so hooks retry
// until the class/selector exists (up to ~15 s) and report precisely what could not be hooked.
// opts.optional: private/version-specific classes; a miss is not reported as a problem.
function hookObjC(cls, sel, onEnter, tries, opts) {
  tries = tries || 0;
  opts = opts || {};
  var name = cls + ' ' + sel;
  var h = hk(name, opts.optional);
  var k = ObjC.classes[cls];
  var m = k && k[sel];
  if (m) {
    var key = String(m.implementation);
    if (IMPLS[key]) { h.installed = true; h.alias = IMPLS[key]; return; }   // inherited; counted under the first name
    try {
      Interceptor.attach(m.implementation, { onEnter: counted(name, onEnter) });
      IMPLS[key] = name;
      h.installed = true;
      return;
    } catch (e) { emit('probe_error', { what: name + ': ' + String(e) }); return; }
  }
  if (tries < 30) setTimeout(function () { hookObjC(cls, sel, onEnter, tries + 1, opts); }, 500);
  else if (!opts.optional) emit('probe_error', { what: 'not found: ' + name });
}
function hookExport(mod, name, onEnter, tries, opts) {
  tries = tries || 0;
  opts = opts || {};
  var hname = mod + '!' + name;
  var h = hk(hname, opts.optional);
  try {
    var addr = Process.getModuleByName(mod).findExportByName(name);
    if (addr) {
      Interceptor.attach(addr, { onEnter: counted(hname, onEnter) });
      h.installed = true;
      return;
    }
  } catch (e) {}
  if (tries < 30) setTimeout(function () { hookExport(mod, name, onEnter, tries + 1, opts); }, 500);
  else if (!opts.optional) emit('probe_error', { what: 'not found: ' + hname });
}

// ---- URL helpers. Query strings and fragments are dropped (they often carry tokens). --------
function urlOf(p) {
  try {
    if (!p || p.isNull()) return null;
    var o = new ObjC.Object(p);
    var u = o.isKindOfClass_(ObjC.classes.NSURL) ? o : (o.respondsToSelector_('URL') ? o.URL() : null);
    return u ? u.absoluteString().toString() : null;
  } catch (e) { return null; }
}
var URL_RE = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/(?:[^\/@?#]*@)?([^\/:?#]+)(?::\d+)?([^?#]*)/;
function parts(u) {
  var m = URL_RE.exec(u || '');
  return m ? { scheme: m[1].toLowerCase(), host: m[2].toLowerCase(), path: trunc(m[3] || '', 120) } : null;
}
var seenUrl = {};
function noteCleartext(u, via) {
  var p = parts(u);
  if (!p || p.scheme !== 'http') return;
  var clean = 'http://' + p.host + p.path;
  if (seenUrl[clean]) return;
  seenUrl[clean] = 1;
  emit('cleartext', { url: trunc(clean, 200), via: via });
}
function noteNet(how, u) {
  var p = parts(u);
  if (!p || (p.scheme !== 'http' && p.scheme !== 'https' && p.scheme !== 'ws' && p.scheme !== 'wss')) return;
  emit('net', { how: how, scheme: p.scheme, host: p.host, path: p.path });
  noteCleartext(u, how);
}
function noteWeb(how, u) {
  var p = parts(u);
  emit('webview_load', { how: how, url: p ? p.scheme + '://' + p.host + p.path : (u ? trunc(u.split(/[?#]/)[0], 120) : '(inline HTML)') });
  noteCleartext(u, how);
}

if (ObjC.available) {
  // --- network: every task goes through -[NSURLSessionTask resume], whatever library created it
  // (URLSession directly, Alamofire, AFNetworking, SDKs). The private subclasses are optional.
  ['NSURLSessionTask', '__NSCFLocalSessionTask', '__NSCFLocalDataTask', '__NSCFLocalUploadTask',
   '__NSCFLocalDownloadTask', '__NSCFURLSessionTask'].forEach(function (c) {
    hookObjC(c, '- resume', function (a) {
      var t = new ObjC.Object(a[0]);
      noteNet('URLSessionTask resume', urlOf(t.currentRequest ? t.currentRequest() : t.originalRequest()));
    }, 0, { optional: c !== 'NSURLSessionTask' });
  });
  // creation-time hooks: cheap, and they catch cleartext URLs even for tasks that never resume
  hookObjC('NSURLRequest', '+ requestWithURL:', function (a) { noteCleartext(urlOf(a[2]), 'NSURLRequest'); });
  hookObjC('NSURLRequest', '- initWithURL:', function (a) { noteCleartext(urlOf(a[2]), 'NSURLRequest'); });
  hookObjC('NSMutableURLRequest', '- setURL:', function (a) { noteCleartext(urlOf(a[2]), 'NSMutableURLRequest'); });
  hookObjC('NSURLSession', '- dataTaskWithURL:', function (a) { noteCleartext(urlOf(a[2]), 'NSURLSession'); });
  hookObjC('NSURLConnection', '- initWithRequest:delegate:startImmediately:',
           function (a) { noteNet('NSURLConnection', urlOf(a[2])); }, 0, { optional: true });
  hookObjC('NSURLConnection', '- initWithRequest:delegate:',
           function (a) { noteNet('NSURLConnection', urlOf(a[2])); }, 0, { optional: true });
  hookObjC('NSURLConnection', '+ sendSynchronousRequest:returningResponse:error:',
           function (a) { noteNet('NSURLConnection', urlOf(a[2])); }, 0, { optional: true });
  hookExport('CFNetwork', 'CFHTTPMessageCreateRequest', function (a) { noteNet('CFNetwork', urlOf(a[2])); }, 0, { optional: true });

  // DNS lookups from any stack: an independent signal. If hosts are resolved but no request
  // hook fires, the app uses a networking path these hooks do not see.
  var seenDns = {};
  tryHook(function () {
    var gai = Module.getGlobalExportByName('getaddrinfo');
    if (!gai) return;
    hk('libc getaddrinfo()').installed = true;
    Interceptor.attach(gai, { onEnter: counted('libc getaddrinfo()', function (a) {
      if (a[0].isNull()) return;
      var host = a[0].readUtf8String();
      if (host && !seenDns[host]) { seenDns[host] = 1; emit('dns', { host: trunc(host.toLowerCase(), 120) }); }
    }) });
  });

  // Raw sockets (Flutter/Dart, custom or embedded HTTP stacks, SDKs with their own networking):
  // connect() from the app's own modules, with the destination IP and port.
  tryHook(function () {
    var cn = Module.getGlobalExportByName('connect');
    if (!cn) return;
    hk('libc connect()').installed = true;
    Interceptor.attach(cn, { onEnter: counted('libc connect()', function (a) {
      if (!fromApp(this.returnAddress)) return;
      var sa = a[1], fam = sa.add(1).readU8(), port = (sa.add(2).readU8() << 8) | sa.add(3).readU8(), ip = null;
      if (fam === 2) {
        ip = [4, 5, 6, 7].map(function (i) { return sa.add(i).readU8(); }).join('.');
      } else if (fam === 30) {
        var b = []; for (var i = 8; i < 24; i++) b.push(sa.add(i).readU8());
        var v4 = b.slice(0, 10).every(function (x) { return x === 0; }) && b[10] === 255 && b[11] === 255;
        if (v4) ip = b.slice(12).join('.');
        else { var g = []; for (var j = 0; j < 16; j += 2) g.push(((b[j] << 8) | b[j + 1]).toString(16)); ip = g.join(':'); }
      }
      if (ip) emit('socket', { ip: ip, port: port });
    }) });
  });

  // --- TLS trust: system evaluation vs evaluation driven by the app's own code (pinning, custom trust)
  ['SecTrustEvaluateWithError', 'SecTrustEvaluate', 'SecTrustEvaluateAsyncWithError'].forEach(function (fn) {
    hookExport('Security', fn, function () {
      emit('trust_eval', { how: fn, by: fromApp(this.returnAddress) ? 'app' : 'system' });
    }, 0, { optional: true });
  });
  ['SecTrustSetExceptions', 'SecTrustSetAnchorCertificates', 'SecTrustSetAnchorCertificatesOnly'].forEach(function (fn) {
    hookExport('Security', fn, function () {
      if (fromApp(this.returnAddress)) emit('trust_override', { how: fn });
    }, 0, { optional: true });
  });
  // Delegates that answer server-trust challenges (where pinning libraries such as TrustKit and
  // Alamofire's ServerTrustManager hook in). Found by looking at the app's own classes.
  var CH_SELS = ['- URLSession:didReceiveChallenge:completionHandler:',
                 '- URLSession:task:didReceiveChallenge:completionHandler:'];
  var CH_GROUP = 'URLSession challenge delegates (app classes)';
  function hookChallengeDelegates() {
    try {
      var mods = ObjC.enumerateLoadedClassesSync();
      Object.keys(mods).forEach(function (path) {
        if (path.indexOf('.app/') < 0) return;
        mods[path].forEach(function (cn) {
          var k = ObjC.classes[cn];
          if (!k) return;
          CH_SELS.forEach(function (sel) {
            var m;
            try { m = k[sel]; } catch (e) { return; }
            if (!m) return;
            var key = String(m.implementation);
            if (IMPLS[key]) return;
            var idx = sel.indexOf('task:') >= 0 ? 4 : 3;
            try {
              Interceptor.attach(m.implementation, { onEnter: counted(CH_GROUP, function (a) {
                var ps = new ObjC.Object(a[idx]).protectionSpace();
                if (ps.authenticationMethod().toString() === 'NSURLAuthenticationMethodServerTrust')
                  emit('pinning', { how: 'URLSession challenge delegate ' + cn, host: trunc(ps.host().toString(), 120) });
              }) });
              IMPLS[key] = CH_GROUP;
              hk(CH_GROUP).installed = true;
            } catch (e) {}
          });
        });
      });
    } catch (e) { emit('probe_error', { what: 'challenge delegate scan: ' + String(e) }); }
  }
  hk(CH_GROUP, true);
  setTimeout(hookChallengeDelegates, 1500);
  setTimeout(hookChallengeDelegates, 8000);     // frameworks loaded lazily after launch

  // --- WebViews
  hookObjC('WKWebView', '- loadRequest:', function (a) { noteWeb('WKWebView loadRequest', urlOf(a[2])); });
  hookObjC('WKWebView', '- loadHTMLString:baseURL:', function (a) { noteWeb('WKWebView loadHTMLString', urlOf(a[3])); });
  hookObjC('WKWebView', '- loadFileURL:allowingReadAccessToURL:', function (a) { noteWeb('WKWebView loadFileURL', urlOf(a[2])); });
  hookObjC('WKWebView', '- loadData:MIMEType:characterEncodingName:baseURL:',
           function (a) { noteWeb('WKWebView loadData', urlOf(a[5])); }, 0, { optional: true });
  hookObjC('WKWebView', '- setInspectable:', function (a) {
    if (a[2].toInt32() & 0xff) emit('webview_debug', { how: 'WKWebView isInspectable' });
  }, 0, { optional: true });
  hookObjC('UIWebView', '- loadRequest:', function (a) { noteWeb('UIWebView loadRequest', urlOf(a[2])); }, 0, { optional: true });

  // --- data at rest and logs
  hookObjC('NSUserDefaults', '- setObject:forKey:', function (a) {
    var k = new ObjC.Object(a[3]).toString();
    var v = a[2].isNull() ? '' : new ObjC.Object(a[2]).toString();
    emit('prefs_write', { key: trunc(k, 80), value: trunc(v, 400) });
  });
  hookExport('Foundation', 'NSLog', function (a) {
    emit('log', { tag: 'NSLog', msg: trunc(new ObjC.Object(a[0]).toString(), 400) });
  });
  hookExport('Security', 'SecItemAdd', function (a) {
    var acc = new ObjC.Object(a[0]).objectForKey_('pdmn');
    if (acc) emit('keychain_add', { accessible: trunc(acc.toString(), 60) });
  });
}
emit('ready', { platform: 'ios' });


// --- crypto operations with keys, IVs and data (only with --dump-crypto) ---------------------
// The host posts {type:'config', crypto:true} after loading. Covers CommonCrypto (CCCrypt, CCCryptor*, CCHmac and
// the CC_MD5 / CC_SHA* one-shots) called from the app's own code and embedded frameworks. CryptoKit and
// corecrypto called directly are not covered.
var CRYPTO_CAP = 3000, cryptoSent = 0, CRYPTO_BYTES = 4096;
var CC_ALG = ['AES', 'DES', '3DES', 'CAST', 'RC4', 'RC2', 'Blowfish'];
var HMAC_ALG = ['SHA1', 'MD5', 'SHA256', 'SHA384', 'SHA512', 'SHA224'];
function hexAt(p, n) {
  if (!p || p.isNull() || n <= 0) return null;
  try {
    var m = Math.min(n, CRYPTO_BYTES), b = new Uint8Array(p.readByteArray(m)), s = '';
    for (var i = 0; i < b.length; i++) s += (b[i] + 0x100).toString(16).slice(1);
    return s;
  } catch (e) { return null; }
}
function cryptoSend(o) {
  if (cryptoSent++ >= CRYPTO_CAP) return;
  send(Object.assign({ t: 'crypto' }, o));
}
function cc(name, cb) {
  tryHook(function () {
    var addr = Module.getGlobalExportByName(name);
    if (!addr) return;
    Interceptor.attach(addr, cb);
  });
}
function installCrypto() {
  cc('CCCrypt', {
    onEnter: function (a) {
      this.ok = fromApp(this.returnAddress);
      if (!this.ok) return;
      this.op = a[0].toInt32(); this.alg = a[1].toInt32(); this.opts = a[2].toInt32();
      this.key = a[3]; this.keyLen = a[4].toInt32(); this.iv = a[5];
      this.inp = a[6]; this.inLen = a[7].toInt32(); this.out = a[8]; this.moved = a[10];
    },
    onLeave: function () {
      if (!this.ok) return;
      var outLen = 0; try { outLen = this.moved.isNull() ? 0 : this.moved.readUInt(); } catch (e) {}
      cryptoSend({ kind: 'cipher', alg: (CC_ALG[this.alg] || 'alg' + this.alg) + ((this.opts & 2) ? '/ECB' : '/CBC') +
                   ((this.opts & 1) ? '/PKCS7Padding' : '/NoPadding'),
                   mode: this.op === 0 ? 'encrypt' : 'decrypt', key: hexAt(this.key, this.keyLen), key_len: this.keyLen,
                   iv: (this.opts & 2) ? null : hexAt(this.iv, 16),
                   input: hexAt(this.inp, this.inLen), in_len: this.inLen, output: hexAt(this.out, outLen), out_len: outLen });
    }
  });
  var cryptors = {};
  cc('CCCryptorCreate', {
    onEnter: function (a) {
      this.ok = fromApp(this.returnAddress);
      if (!this.ok) return;
      this.info = { op: a[0].toInt32(), alg: a[1].toInt32(), opts: a[2].toInt32(), key: a[3], keyLen: a[4].toInt32(), iv: a[5] };
      this.ref = a[6];
    },
    onLeave: function () {
      if (!this.ok) return;
      var i = this.info;
      try { cryptors[this.ref.readPointer().toString()] = i; } catch (e) {}
      cryptoSend({ kind: 'cipher_init', alg: (CC_ALG[i.alg] || 'alg' + i.alg) + ((i.opts & 2) ? '/ECB' : '/CBC') +
                   ((i.opts & 1) ? '/PKCS7Padding' : '/NoPadding'),
                   mode: i.op === 0 ? 'encrypt' : 'decrypt', key: hexAt(i.key, i.keyLen), key_len: i.keyLen,
                   iv: (i.opts & 2) ? null : hexAt(i.iv, 16) });
    }
  });
  cc('CCCryptorUpdate', {
    onEnter: function (a) {
      this.ok = fromApp(this.returnAddress);
      if (!this.ok) return;
      this.ref = a[0].toString(); this.inp = a[1]; this.inLen = a[2].toInt32(); this.out = a[3]; this.moved = a[5];
    },
    onLeave: function () {
      if (!this.ok) return;
      var outLen = 0; try { outLen = this.moved.isNull() ? 0 : this.moved.readUInt(); } catch (e) {}
      var i = cryptors[this.ref];
      cryptoSend({ kind: 'cipher_update', alg: i ? (CC_ALG[i.alg] || 'alg' + i.alg) : 'CCCryptor',
                   input: hexAt(this.inp, this.inLen), in_len: this.inLen, output: hexAt(this.out, outLen), out_len: outLen });
    }
  });
  cc('CCHmac', {
    onEnter: function (a) {
      this.ok = fromApp(this.returnAddress);
      if (!this.ok) return;
      this.alg = a[0].toInt32(); this.key = a[1]; this.keyLen = a[2].toInt32();
      this.data = a[3]; this.dataLen = a[4].toInt32(); this.mac = a[5];
    },
    onLeave: function () {
      if (!this.ok) return;
      var n = { 0: 20, 1: 16, 2: 32, 3: 48, 4: 64, 5: 28 }[this.alg] || 32;
      cryptoSend({ kind: 'mac', alg: 'HMAC-' + (HMAC_ALG[this.alg] || this.alg), key: hexAt(this.key, this.keyLen), key_len: this.keyLen,
                   input: hexAt(this.data, this.dataLen), in_len: this.dataLen, output: hexAt(this.mac, n), out_len: n });
    }
  });
  [['CC_MD5', 'MD5', 16], ['CC_SHA1', 'SHA-1', 20], ['CC_SHA256', 'SHA-256', 32], ['CC_SHA512', 'SHA-512', 64]].forEach(function (d) {
    cc(d[0], {
      onEnter: function (a) { this.ok = fromApp(this.returnAddress); this.data = a[0]; this.len = a[1].toInt32(); this.md = a[2]; },
      onLeave: function () {
        if (!this.ok) return;
        cryptoSend({ kind: 'digest', alg: d[1], input: hexAt(this.data, this.len), in_len: this.len, output: hexAt(this.md, d[2]), out_len: d[2] });
      }
    });
  });
}
recv('config', function (m) { if (m && m.crypto) installCrypto(); });
