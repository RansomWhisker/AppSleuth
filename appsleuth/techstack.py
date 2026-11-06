"""What is this app built with? (static)

Cross-platform framework / game engine, languages, UI toolkit, networking, storage, analytics / crash / ads /
payment SDKs and the build toolchain, read from the package contents (native libraries, frameworks, bundled
assets, dex class names, Info.plist build keys, Maven metadata).  Versions come from the same metadata the
SBOM uses when it is available.
"""
from __future__ import annotations

import json
import os
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from . import appfiles, engine, sbom

MAX_READ = 80 << 20


def _item(cat: str, name: str, version: Optional[str] = None, evidence: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"category": cat, "name": name, "version": version, "evidence": (evidence or [])[:4]}


# ---- Android: (category, name, regex over file paths) -- first match wins evidence
ANDROID_PATH_RULES: List[Tuple[str, str, str]] = [
    ("Framework", "Flutter", r"(^|/)lib/[^/]+/libflutter\.so$|assets/flutter_assets/"),
    ("Framework", "React Native", r"libreactnativejni\.so$|libreactnative\.so$|libhermes\.so$|libjsc\.so$|assets/index\.android\.bundle$"),
    ("Framework", "Capacitor", r"assets/capacitor\.config\.json$|assets/public/native-bridge\.js$"),
    ("Framework", "Cordova", r"assets/www/cordova\.js$|assets/www/cordova_plugins\.js$"),
    ("Framework", "Xamarin / .NET MAUI", r"libmonodroid\.so$|libmonosgen-2\.0\.so$|assemblies/[^/]+\.dll$|assemblies/assemblies\.blob$|libxamarin-app\.so$"),
    ("Framework", "Unity", r"libunity\.so$|assets/bin/Data/|libil2cpp\.so$"),
    ("Framework", "Unreal Engine", r"libUE4\.so$|libUnreal\.so$"),
    ("Framework", "Godot", r"libgodot_android\.so$"),
    ("Framework", "Cocos2d-x / Cocos Creator", r"libcocos2dcpp\.so$|libcocos\.so$|libcocos2djs\.so$"),
    ("Framework", "libGDX", r"libgdx\.so$"),
    ("Framework", "NativeScript", r"libNativeScript\.so$"),
    ("Framework", "Qt", r"libQt\d?Core[^/]*\.so$"),
    ("Framework", "Titanium", r"libti\.[^/]+\.so$|libtiverify\.so$"),
    ("Framework", "Corona / Solar2D", r"libcorona\.so$"),
    ("Framework", "Defold", r"libdmengine\.so$"),
    ("Framework", "Kotlin Multiplatform / Compose Multiplatform", r"composeResources/|META-INF/.*kotlin-multiplatform"),
    ("Engine", "Hermes (JS engine)", r"libhermes\.so$"),
    ("Engine", "JavaScriptCore", r"libjsc\.so$"),
    ("Engine", "V8", r"libv8[^/]*\.so$|libj2v8\.so$"),
    ("Engine", "Mono runtime", r"libmonosgen-2\.0\.so$|libmonodroid\.so$"),
    ("Engine", "IL2CPP", r"libil2cpp\.so$|global-metadata\.dat$"),
    ("Engine", "Dart AOT", r"lib/[^/]+/libapp\.so$"),
    ("Engine", "Chromium WebView / Cronet", r"libcronet[^/]*\.so$|libmonochrome[^/]*\.so$"),
    ("Media", "FFmpeg", r"libffmpeg[^/]*\.so$|libavcodec[^/]*\.so$"),
    ("Media", "WebRTC", r"libjingle_peerconnection_so\.so$|libwebrtc[^/]*\.so$"),
    ("Media", "ExoPlayer / Media3 (native decoders)", r"libexo[^/]*\.so$|libmedia3[^/]*\.so$"),
    ("Storage", "SQLCipher (encrypted SQLite)", r"libsqlcipher\.so$|libsqlcipher[^/]*\.so$"),
    ("Storage", "Realm", r"librealm[^/]*\.so$"),
    ("Storage", "MMKV", r"libmmkv\.so$"),
    ("Security", "App shielding / packer library", r"libjiagu|libDexHelper|libsecexe|libprotectClass|libbangcle|libnqshield|libmobisec|libijiami|libegis|libAppGuard|libshield"),
    ("Native", "libsodium / OpenSSL / BoringSSL", r"libsodium\.so$|libssl\.so$|libcrypto\.so$|libconscrypt[^/]*\.so$"),
]

# ---- Android: dex package prefixes (slash form) -> (category, name)
DEX_RULES: List[Tuple[str, str, str]] = [
    ("Architecture", "Kotlin coroutines", "kotlinx/coroutines/"),
    ("UI", "Jetpack Compose", "androidx/compose/"),
    ("UI", "Material Components", "com/google/android/material/"),
    ("UI", "AppCompat / AndroidX", "androidx/appcompat/"),
    ("UI", "Jetpack Navigation", "androidx/navigation/"),
    ("UI", "Epoxy", "com/airbnb/epoxy/"),
    ("UI", "Lottie", "com/airbnb/lottie/"),
    ("UI", "Fragments / ViewPager2", "androidx/viewpager2/"),
    ("Architecture", "Jetpack Lifecycle / ViewModel", "androidx/lifecycle/"),
    ("Architecture", "WorkManager", "androidx/work/"),
    ("Architecture", "Dagger", "dagger/"),
    ("Architecture", "Hilt", "dagger/hilt/"),
    ("Architecture", "Koin", "org/koin/"),
    ("Architecture", "RxJava", "io/reactivex/"),
    ("Architecture", "EventBus", "org/greenrobot/eventbus/"),
    ("Networking", "OkHttp", "okhttp3/"),
    ("Networking", "Retrofit", "retrofit2/"),
    ("Networking", "Volley", "com/android/volley/"),
    ("Networking", "Ktor", "io/ktor/"),
    ("Networking", "gRPC", "io/grpc/"),
    ("Networking", "Apollo GraphQL", "com/apollographql/"),
    ("Networking", "Cronet", "org/chromium/net/"),
    ("Networking", "Socket.IO", "io/socket/"),
    ("Networking", "Firebase Cloud Messaging", "com/google/firebase/messaging/"),
    ("Serialization", "Gson", "com/google/gson/"),
    ("Serialization", "Moshi", "com/squareup/moshi/"),
    ("Serialization", "Jackson", "com/fasterxml/jackson/"),
    ("Serialization", "kotlinx.serialization", "kotlinx/serialization/"),
    ("Serialization", "Protocol Buffers", "com/google/protobuf/"),
    ("Images", "Glide", "com/bumptech/glide/"),
    ("Images", "Picasso", "com/squareup/picasso/"),
    ("Images", "Coil", "coil/"),
    ("Images", "Fresco", "com/facebook/fresco/"),
    ("Storage", "Room", "androidx/room/"),
    ("Storage", "Realm", "io/realm/"),
    ("Storage", "SQLCipher", "net/sqlcipher/"),
    ("Storage", "Jetpack DataStore", "androidx/datastore/"),
    ("Storage", "Firebase Firestore / Realtime DB", "com/google/firebase/firestore/"),
    ("Media", "ExoPlayer", "com/google/android/exoplayer2/"),
    ("Media", "Media3", "androidx/media3/"),
    ("Media", "CameraX", "androidx/camera/"),
    ("Media", "ML Kit", "com/google/mlkit/"),
    ("Media", "TensorFlow Lite", "org/tensorflow/lite/"),
    ("Maps", "Google Maps", "com/google/android/gms/maps/"),
    ("Maps", "Mapbox", "com/mapbox/"),
    ("Analytics & crash", "Firebase Analytics", "com/google/firebase/analytics/"),
    ("Analytics & crash", "Firebase Crashlytics", "com/google/firebase/crashlytics/"),
    ("Analytics & crash", "Sentry", "io/sentry/"),
    ("Analytics & crash", "Bugly", "com/tencent/bugly/"),
    ("Analytics & crash", "Datadog", "com/datadog/"),
    ("Analytics & crash", "New Relic", "com/newrelic/"),
    ("Analytics & crash", "Mixpanel", "com/mixpanel/"),
    ("Analytics & crash", "Amplitude", "com/amplitude/"),
    ("Analytics & crash", "CleverTap", "com/clevertap/"),
    ("Analytics & crash", "MoEngage", "com/moengage/"),
    ("Analytics & crash", "Segment", "com/segment/analytics/"),
    ("Analytics & crash", "UXCam / Hotjar / Smartlook", "com/uxcam/"),
    ("Attribution & ads", "AppsFlyer", "com/appsflyer/"),
    ("Attribution & ads", "Adjust", "com/adjust/sdk/"),
    ("Attribution & ads", "Branch", "io/branch/"),
    ("Attribution & ads", "Facebook SDK", "com/facebook/appevents/"),
    ("Attribution & ads", "Google AdMob", "com/google/android/gms/ads/"),
    ("Attribution & ads", "AppLovin", "com/applovin/"),
    ("Attribution & ads", "Unity Ads", "com/unity3d/ads/"),
    ("Attribution & ads", "ironSource", "com/ironsource/"),
    ("Push & messaging", "OneSignal", "com/onesignal/"),
    ("Push & messaging", "Braze", "com/braze/"),
    ("Push & messaging", "Intercom", "io/intercom/"),
    ("Push & messaging", "Zendesk", "zendesk/"),
    ("Payments", "Razorpay", "com/razorpay/"),
    ("Payments", "Stripe", "com/stripe/"),
    ("Payments", "Braintree / PayPal", "com/braintreepayments/"),
    ("Payments", "Google Pay / Play Billing", "com/android/billingclient/"),
    ("Payments", "PhonePe / Paytm / UPI SDK", "com/phonepe/"),
    ("Auth & security", "Firebase Auth", "com/google/firebase/auth/"),
    ("Auth & security", "Google Sign-In", "com/google/android/gms/auth/api/signin/"),
    ("Auth & security", "Biometric (AndroidX)", "androidx/biometric/"),
    ("Auth & security", "Play Integrity", "com/google/android/play/core/integrity/"),
    ("Auth & security", "AppAuth / OAuth", "net/openid/appauth/"),
    ("Auth & security", "RootBeer", "com/scottyab/rootbeer/"),
    ("Auth & security", "Zimperium / Promon / Appdome / Talsec", "com/zimperium/"),
    ("Updates", "Google Play Core / In-app updates", "com/google/android/play/core/"),
    ("Updates", "CodePush / Expo Updates", "expo/modules/updates/"),
    ("Framework", "Expo", "expo/modules/"),
    ("Framework", "React Native", "com/facebook/react/"),
    ("Framework", "Capacitor", "com/getcapacitor/"),
    ("Framework", "Cordova", "org/apache/cordova/"),
    ("Framework", "Flutter", "io/flutter/"),
    ("Framework", "Xamarin / .NET MAUI", "mono/android/"),
    ("Framework", "Unity", "com/unity3d/player/"),
]

# iOS framework / library names -> (category, name)
IOS_FRAMEWORK_RULES: List[Tuple[str, str, str]] = [
    ("Framework", "Flutter", r"^Flutter$|^App$"),
    ("Framework", "React Native", r"^React(Native)?$|^RCT|^hermes$|^ReactCommon$|^React-Core"),
    ("Framework", "Capacitor", r"^Capacitor$|^CapacitorCordova$"),
    ("Framework", "Cordova", r"^Cordova$"),
    ("Framework", "Xamarin / .NET MAUI", r"^Xamarin|^Microsoft\.Maui"),
    ("Framework", "Unity", r"^UnityFramework$"),
    ("Framework", "Unreal Engine", r"^UE4$|^UnrealEngine"),
    ("Framework", "NativeScript", r"^NativeScript$|^TNSWidgets$"),
    ("Framework", "Kotlin Multiplatform", r"^shared$|^Shared$|^KotlinShared$|^ComposeApp$"),
    ("Framework", "Qt", r"^Qt[A-Z]"),
    ("Networking", "Alamofire", r"^Alamofire$"),
    ("Networking", "AFNetworking", r"^AFNetworking$"),
    ("Networking", "Moya", r"^Moya$"),
    ("Networking", "Apollo GraphQL", r"^Apollo"),
    ("Networking", "SocketIO / Starscream", r"^SocketIO$|^Starscream$"),
    ("Networking", "gRPC", r"^grpc|^GRPC"),
    ("Images", "SDWebImage", r"^SDWebImage"),
    ("Images", "Kingfisher", r"^Kingfisher$"),
    ("Images", "Nuke", r"^Nuke"),
    ("UI", "Lottie", r"^Lottie$"),
    ("UI", "SnapKit", r"^SnapKit$"),
    ("UI", "RxSwift / RxCocoa", r"^Rx"),
    ("UI", "Texture / AsyncDisplayKit", r"^AsyncDisplayKit$|^Texture$"),
    ("Storage", "Realm", r"^Realm"),
    ("Storage", "SQLCipher", r"^SQLCipher$"),
    ("Storage", "GRDB", r"^GRDB$"),
    ("Storage", "FMDB", r"^FMDB$"),
    ("Storage", "Firebase Firestore / Database", r"^FirebaseFirestore|^FirebaseDatabase"),
    ("Analytics & crash", "Firebase Analytics / Core", r"^FirebaseAnalytics$|^FirebaseCore$|^FirebaseInstallations$|^GoogleAppMeasurement"),
    ("Analytics & crash", "Firebase Crashlytics", r"^FirebaseCrashlytics$"),
    ("Analytics & crash", "Sentry", r"^Sentry"),
    ("Analytics & crash", "Datadog", r"^Datadog"),
    ("Analytics & crash", "Mixpanel", r"^Mixpanel"),
    ("Analytics & crash", "Amplitude", r"^Amplitude"),
    ("Analytics & crash", "CleverTap", r"^CleverTap"),
    ("Analytics & crash", "MoEngage", r"^MoEngage"),
    ("Attribution & ads", "AppsFlyer", r"^AppsFlyer"),
    ("Attribution & ads", "Adjust", r"^Adjust"),
    ("Attribution & ads", "Branch", r"^Branch$"),
    ("Attribution & ads", "Facebook SDK", r"^FBSDK|^FBAEM|^FBSDKCoreKit"),
    ("Attribution & ads", "Google Mobile Ads", r"^GoogleMobileAds$|^UserMessagingPlatform$"),
    ("Push & messaging", "Firebase Messaging", r"^FirebaseMessaging$"),
    ("Push & messaging", "OneSignal", r"^OneSignal"),
    ("Push & messaging", "Braze", r"^Appboy|^BrazeKit"),
    ("Payments", "Razorpay", r"^Razorpay"),
    ("Payments", "Stripe", r"^Stripe"),
    ("Payments", "Braintree / PayPal", r"^Braintree|^PayPal"),
    ("Maps", "Mapbox", r"^Mapbox"),
    ("Media", "Google Maps", r"^GoogleMaps$"),
    ("Auth & security", "Firebase Auth", r"^FirebaseAuth$"),
    ("Auth & security", "Google Sign-In", r"^GoogleSignIn$"),
    ("Auth & security", "TrustKit", r"^TrustKit$"),
    ("Auth & security", "IOSSecuritySuite", r"^IOSSecuritySuite$"),
    ("Auth & security", "OpenSSL", r"^OpenSSL|^openssl"),
    ("Architecture", "Swift runtime libraries (bundled)", r"^libswift"),
    ("Architecture", "Swift Concurrency / Combine back-deploy", r"^libswift_Concurrency|^libswiftCombine"),
]

_ABI_ORDER = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86", "riscv64"]


def _read(path: str, limit: int = MAX_READ) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


def _xcode(v: Optional[str]) -> Optional[str]:
    if v and str(v).isdigit() and len(str(v)) == 4:
        s = str(v)
        return "%d.%d.%d" % (int(s[:2]), int(s[2]), int(s[3])) if s[3] != "0" else "%d.%d" % (int(s[:2]), int(s[2]))
    return v


def _versions(app: appfiles.App) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for c in sbom.collect(app):
            v = c.get("version")
            if v:
                out[(c.get("artifact") or c["name"]).lower()] = str(v)
                out[c["name"].lower()] = str(v)
    except Exception:
        pass
    return out


def _dex_prefixes(app: appfiles.App, wanted: List[str]) -> Tuple[Dict[str, int], Dict[str, Any]]:
    """-> ({prefix: number of classes}, obfuscation stats) across every dex."""
    counts = {w: 0 for w in wanted}
    total = short = 0
    for p in app.files():
        if not p.endswith(".dex"):
            continue
        try:
            dx = engine.DexFile(_read(p))
        except Exception:
            continue
        for c in dx.classes:
            name = c["name"]
            total += 1
            simple = name.rsplit("/", 1)[-1].rstrip(";")
            if len(simple.split("$")[0]) <= 2:
                short += 1
            lname = name[1:]
            for w in wanted:
                if lname.startswith(w):
                    counts[w] += 1
    return counts, {"classes": total, "short_named": short}


def _flutter_versions(app: appfiles.App) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {"dart": None, "flutter": None}
    for p in app.files():
        b = os.path.basename(p)
        if b in ("libapp.so", "App") or b == "libflutter.so":
            data = _read(p, 64 << 20)
            m = re.search(rb"(\d+\.\d+\.\d+) \((?:stable|beta|dev|main)\)", data)
            if m and not out["dart"]:
                out["dart"] = m.group(1).decode()
            m = re.search(rb"Flutter/(\d+\.\d+\.\d+)", data)
            if m and not out["flutter"]:
                out["flutter"] = m.group(1).decode()
    return out


def _android(app: appfiles.App) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    rels = [(app.rel(p), p) for p in app.files()]
    names = [r for r, _p in rels]
    vers = _versions(app)

    for cat, name, rx in ANDROID_PATH_RULES:
        pat = re.compile(rx)
        ev = [n for n in names if pat.search(n)]
        if ev:
            items.append(_item(cat, name, None, ev))
    fl = next((i for i in items if i["name"] == "Flutter"), None)
    if fl:
        fv = _flutter_versions(app)
        fl["version"] = fv["flutter"]
        if fv["dart"]:
            items.append(_item("Language", "Dart", fv["dart"], ["lib/*/libapp.so"]))
    rn = next((i for i in items if i["name"] == "React Native"), None)
    if rn:
        for n, p in rels:
            if n.endswith("index.android.bundle"):
                head = _read(p, 8)
                rn["evidence"].append("Hermes bytecode bundle" if head[:4] == b"\xc6\x1f\xbc\x03" else "plain JavaScript bundle")
                break
    un = next((i for i in items if i["name"] == "Unity"), None)
    if un:
        for n, p in rels:
            if n.endswith("libunity.so") or n.endswith("globalgamemanagers") or n.endswith("data.unity3d"):
                m = re.search(rb"(20\d\d\.\d+\.\d+[fpab]\d+)", _read(p, 40 << 20))
                if m:
                    un["version"] = m.group(1).decode()
                    break

    prefixes = [w for _c, _n, w in DEX_RULES] + ["kotlin/"]
    counts, obf = _dex_prefixes(app, prefixes)
    have = {(i["category"], i["name"]) for i in items}
    ver_keys = {"OkHttp": "okhttp", "Retrofit": "retrofit", "Glide": "glide", "Room": "room-runtime", "Gson": "gson", "Moshi": "moshi",
                "Kotlin coroutines": "kotlinx-coroutines-core", "Jetpack Compose": "compose", "Firebase Crashlytics": "firebase-crashlytics",
                "Sentry": "sentry"}
    for cat, name, w in DEX_RULES:
        if counts.get(w):
            if (cat, name) in have:
                continue
            ev = ["%s* (%d classes)" % (w.replace("/", "."), counts[w])]
            v = None
            k = ver_keys.get(name)
            if k:
                v = next((vers[x] for x in vers if x.endswith(k)), None)
                if v is None:
                    v = next((vers[x] for x in vers if k in x), None)
            items.append(_item(cat, name, v, ev))
            have.add((cat, name))
    # Hilt implies Dagger; drop the duplicate generic Dagger when Hilt is present
    if ("Architecture", "Hilt") in have:
        items = [i for i in items if i["name"] != "Dagger"]

    langs: List[Dict[str, Any]] = []
    kot = counts.get("kotlin/", 0)
    kot_files = [n for n in names if n.endswith((".kotlin_module", ".kotlin_builtins"))]
    total = obf["classes"]
    if kot or kot_files:
        kv = None
        for n, p in rels:
            if n.endswith("kotlin-tooling-metadata.json"):
                try:
                    kv = (json.loads(_read(p, 1 << 20).decode("utf-8", "replace")).get("buildPluginVersion"))
                except Exception:
                    pass
        langs.append(_item("Language", "Kotlin", kv, (["kotlin/* (%d classes)" % kot] if kot else []) + kot_files[:2]))
    if total:
        langs.append(_item("Language", "Java", None, ["%d classes in dex" % total]))
    if any(n.endswith(".so") for n in names):
        native = []
        for n, p in rels:
            if n.endswith(".so"):
                data = _read(p, 8 << 20)
                if b"rust_eh_personality" in data or b"/rustc/" in data:
                    native.append("Rust")
                if b"runtime.goexit" in data or b"Go build ID" in data:
                    native.append("Go")
        langs.append(_item("Language", "C / C++ (NDK native libraries)", None, [n for n in names if n.endswith(".so")][:3]))
        for l in sorted(set(native)):
            langs.append(_item("Language", l, None, ["native library"]))
    if any(n.endswith(".dll") for n in names):
        langs.append(_item("Language", "C# (.NET)", None, ["assemblies/*.dll"]))
    # Languages implied by the framework
    if next((i for i in items if i["name"] == "React Native"), None) or next((i for i in items if i["name"] in ("Capacitor", "Cordova")), None):
        langs.append(_item("Language", "JavaScript / TypeScript", None, ["bundled web / JS layer"]))
    items = langs + items

    # toolchain
    tool: Dict[str, Any] = {}
    bare = [n.split(":", 1)[1] if ":" in n.split("/", 1)[0] else n for n in names]  # drop "splitN_x_apk:" prefix
    abis = sorted({n.split("/")[1] for n in bare if n.startswith("lib/") and n.count("/") >= 2},
                  key=lambda a: _ABI_ORDER.index(a) if a in _ABI_ORDER else 99)
    if abis:
        tool["abis"] = abis
    for n, p in rels:
        if n.endswith("app-metadata.properties") and "gradle" in n:
            for line in _read(p, 1 << 16).decode("utf-8", "replace").splitlines():
                if line.startswith("androidGradlePluginVersion="):
                    tool["agp"] = line.split("=", 1)[1].strip()
        if n.endswith("version-control-info.textproto"):
            tool["vcs_info"] = True
    man = app.manifest
    if man is not None:
        for k in ("compileSdkVersion", "platformBuildVersionCode"):
            v = man.get(k)
            if v:
                tool["compile_sdk"] = v
                break
        v = man.get("platformBuildVersionName")
        if v:
            tool["platform_build"] = v
    tool["obfuscation"] = None
    if obf["classes"]:
        pct = 100.0 * obf["short_named"] / obf["classes"]
        tool["obfuscation"] = {"percent_short_names": round(pct, 1), "classes": obf["classes"]}
    return {"items": items, "toolchain": tool}


def _macho_archs(path: str) -> List[str]:
    data = _read(path, 4096)
    names = {0x0100000C: "arm64", 0x0000000C: "armv7", 0x01000007: "x86_64", 7: "i386"}
    try:
        if data[:4] in (b"\xca\xfe\xba\xbe",):
            n = struct.unpack_from(">I", data, 4)[0]
            return [names.get(struct.unpack_from(">I", data, 8 + i * 20)[0], "?") for i in range(min(n, 6))]
        if data[:4] == b"\xcf\xfa\xed\xfe":
            ct, sub = struct.unpack_from("<II", data, 4)
            nm = names.get(ct, "?")
            return [("arm64e" if nm == "arm64" and (sub & 0xff) == 2 else nm)]
    except Exception:
        pass
    return []


def _ios(app: appfiles.App) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    base = app.main_root or ""
    plist = app.info_plist or {}
    names = [app.rel(p) for p in app.files()]
    vers = _versions(app)
    fw: List[str] = []
    fwdir = os.path.join(base, "Frameworks")
    if os.path.isdir(fwdir):
        fw = sorted(os.listdir(fwdir))
    seen = set()
    for f in fw:
        stem = f[:-len(".framework")] if f.endswith(".framework") else (f[:-len(".dylib")] if f.endswith(".dylib") else f)
        for cat, name, rx in IOS_FRAMEWORK_RULES:
            if re.search(rx, stem) and (cat, name) not in seen:
                if name == "Flutter" and stem == "App" and not os.path.isdir(os.path.join(fwdir, "Flutter.framework")):
                    continue
                seen.add((cat, name))
                items.append(_item(cat, name, vers.get(stem.lower()), ["Frameworks/" + f]))
    # asset based
    def has(rx):
        pat = re.compile(rx)
        return [n for n in names if pat.search(n)]
    rules = [("Framework", "React Native", r"main\.jsbundle$|/Frameworks/React"),
             ("Framework", "Capacitor", r"capacitor\.config\.json$|/public/native-bridge\.js$"),
             ("Framework", "Cordova", r"/www/cordova\.js$"),
             ("Framework", "Flutter", r"flutter_assets/"),
             ("Framework", "Unity", r"Data/Managed/|Data/Raw/|UnityFramework"),
             ("Framework", "Xamarin / .NET MAUI", r"Xamarin\.iOS\.dll$|mscorlib\.dll$"),
             ("Storage", "Core Data model", r"\.momd/|\.mom$"),
             ("UI", "Storyboards / XIBs", r"\.storyboardc/|\.nib$"),
             ("UI", "Asset catalog", r"Assets\.car$"),
             ("Storage", "Realm database file", r"\.realm$"),
             ("Storage", "SQLite database (bundled)", r"\.(sqlite3?|db)$")]
    for cat, name, rx in rules:
        ev = has(rx)
        if ev and (cat, name) not in seen:
            seen.add((cat, name))
            items.append(_item(cat, name, None, ev))
    fl = next((i for i in items if i["name"] == "Flutter"), None)
    if fl:
        fv = _flutter_versions(app)
        fl["version"] = fl["version"] or fv["flutter"]
        if fv["dart"]:
            items.append(_item("Language", "Dart", fv["dart"], ["App.framework"]))
    rn = next((i for i in items if i["name"] == "React Native"), None)
    if rn:
        hermes = any("hermes" in n.lower() for n in names)
        rn["evidence"].append("Hermes engine" if hermes else "JavaScriptCore")
    # main binary: Swift / ObjC / SwiftUI / Rust and friends
    exe = os.path.join(base, plist.get("CFBundleExecutable", "")) if base else ""
    langs: List[Dict[str, Any]] = []
    data = _read(exe, 120 << 20) if exe and os.path.isfile(exe) else b""
    swift = b"__swift5_" in data or b"libswiftCore.dylib" in data or any(f.startswith("libswift") for f in fw)
    if swift:
        langs.append(_item("Language", "Swift", None, ["__swift5_* sections / libswift*.dylib"]))
    if b"__objc_classlist" in data or b"objc_msgSend" in data:
        langs.append(_item("Language", "Objective-C", None, ["Objective-C runtime metadata"]))
    if b"rust_eh_personality" in data or b"/rustc/" in data:
        langs.append(_item("Language", "Rust", None, ["main binary"]))
    if b"kotlin." in data and b"KotlinBase" in data:
        langs.append(_item("Language", "Kotlin (Multiplatform / Native)", None, ["KotlinBase runtime classes"]))
    if any(re.search(r"\.(cpp|mm)$", n) for n in names) or b"libc++.1.dylib" in data:
        langs.append(_item("Language", "C / C++ / Objective-C++", None, ["libc++ linked"]))
    if b"libswiftSwiftUI.dylib" in data or b"SwiftUI.framework/SwiftUI" in data:
        items.append(_item("UI", "SwiftUI", None, ["links SwiftUI.framework"]))
    if b"UIKit.framework/UIKit" in data:
        items.append(_item("UI", "UIKit", None, ["links UIKit.framework"]))
    if b"libswiftCombine.dylib" in data or b"Combine.framework/Combine" in data:
        items.append(_item("Architecture", "Combine", None, ["links Combine.framework"]))
    if b"libswift_Concurrency.dylib" in data or b"_swift_task_" in data:
        items.append(_item("Architecture", "Swift Concurrency (async/await)", None, ["swift_task_* symbols"]))
    if b"StoreKit.framework/StoreKit" in data:
        items.append(_item("Payments", "StoreKit (in-app purchase)", None, ["links StoreKit.framework"]))
    if b"WebKit.framework/WebKit" in data:
        items.append(_item("UI", "WKWebView (WebKit)", None, ["links WebKit.framework"]))
    if b"LocalAuthentication.framework" in data:
        items.append(_item("Auth & security", "LocalAuthentication (Face ID / Touch ID)", None, ["links LocalAuthentication"]))
    if b"CoreData.framework/CoreData" in data and ("Storage", "Core Data model") not in seen:
        items.append(_item("Storage", "Core Data", None, ["links CoreData.framework"]))
    if b"AppTrackingTransparency" in data:
        items.append(_item("Attribution & ads", "App Tracking Transparency", None, ["links AppTrackingTransparency"]))
    items = langs + items
    tool: Dict[str, Any] = {}
    if plist.get("DTXcode"):
        tool["xcode"] = _xcode(str(plist.get("DTXcode")))
    if plist.get("DTXcodeBuild"):
        tool["xcode_build"] = plist.get("DTXcodeBuild")
    for k_in, k_out in (("DTSDKName", "sdk"), ("DTPlatformVersion", "platform_version"), ("DTPlatformName", "platform"),
                        ("DTCompiler", "compiler"), ("MinimumOSVersion", "min_os"), ("BuildMachineOSBuild", "build_machine_os")):
        if plist.get(k_in):
            tool[k_out] = plist.get(k_in)
    if exe and os.path.isfile(exe):
        tool["archs"] = _macho_archs(exe)
    return {"items": items, "toolchain": tool}


def detect(app: appfiles.App) -> Dict[str, Any]:
    r = _ios(app) if app.platform == "ios" else _android(app)
    # Capacitor ships a Cordova-compatibility layer: only report Cordova when it is really the app shell
    if any(i["name"] == "Capacitor" for i in r["items"]):
        r["items"] = [i for i in r["items"] if i["name"] != "Cordova" or any("cordova.js" in e for e in i["evidence"])]
    # one-line verdict
    fw = [i for i in r["items"] if i["category"] == "Framework" and i["name"] not in ("Expo",)]
    primary = fw[0]["name"] if fw else "Native " + ("iOS" if app.platform == "ios" else "Android")
    r["primary"] = primary
    r["platform"] = app.platform
    return r


def detect_path(path: str) -> Dict[str, Any]:
    with appfiles.unpacked(path) as app:
        return detect(app)
