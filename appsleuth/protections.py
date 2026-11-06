"""Which client-side protections does an app ship? (static detection)

Looks for the indicators of root / jailbreak detection, Frida and hook-framework detection,
debugger detection, emulator / simulator detection, SSL pinning, tamper / integrity checks,
screen-capture protection, obfuscation / packing and commercial RASP SDKs, in the app's
code, native libraries, web assets and config. It reports what the app *contains*: a
detection that is present may still be weak or bypassable, and an app that is packed or
heavily obfuscated can hide indicators, so "not found" is not proof of absence.
Observe-only: nothing here bypasses or disables any protection.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Set, Tuple

import json

from . import appfiles, engine

MAX_FILE = 120 << 20
SCAN_EXT = {".dex", ".so", ".dylib", ".js", ".mjs", ".json", ".plist", ".xml", ".html", ".properties", ".txt"}
MACHO_MAGIC = (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")

# Display order and labels.
CATEGORIES = [
    ("root", {"android": "Root detection", "ios": "Jailbreak detection"}),
    ("frida", {"android": "Frida detection", "ios": "Frida detection"}),
    ("hooking", {"android": "Hook framework detection (Xposed etc.)", "ios": "Hook / tweak detection"}),
    ("debugger", {"android": "Debugger detection", "ios": "Debugger detection"}),
    ("emulator", {"android": "Emulator detection", "ios": "Simulator detection"}),
    ("pinning", {"android": "SSL / certificate pinning", "ios": "SSL / certificate pinning"}),
    ("tamper", {"android": "Tamper / integrity checks", "ios": "Tamper / integrity checks"}),
    ("screen", {"android": "Screen capture protection", "ios": "Screen capture / screenshot detection"}),
    ("obfuscation", {"android": "Obfuscation / packing", "ios": "Obfuscation / packing"}),
    ("rasp", {"android": "Commercial protection SDK", "ios": "Commercial protection SDK"}),
]

# (category, label, platform, strength, needles). strong = one hit is enough; weak = needs a second weak
# label in the same category. Class names are given with "/" and are also matched with "." separators.
S, W = "strong", "weak"
SIGS: List[Tuple[str, str, str, str, List[str]]] = [
    # ---- root (android) ----
    ("root", "RootBeer library", "android", S, ["com/scottyab/rootbeer", "RootBeerNative"]),
    ("root", "JailMonkey / root-detection plugin", "android", S, ["JailMonkey", "com/gantix/JailMonkey", "flutter_jailbreak_detection",
                                                                  "safe_device", "root_detector", "RootDetector"]),
    ("root", "su binary probes", "android", W, ["/system/xbin/su", "/system/bin/su", "/sbin/su", "/system/sd/xbin/su", "/data/local/xbin/su"]),
    ("root", "Magisk / SuperSU package probes", "android", W, ["com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
                                                              "com.koushikdutta.superuser", "com.thirdparty.superuser", "me.phh.superuser"]),
    ("root", "test-keys build check", "android", W, ["test-keys"]),
    ("root", "isRooted-style helper", "android", W, ["isRooted", "isDeviceRooted", "checkRootMethod", "detectRootManagementApps", "checkForSuBinary"]),
    ("root", "Play Integrity / SafetyNet attestation", "android", S, ["com/google/android/play/core/integrity", "com/google/android/gms/safetynet",
                                                                       "IntegrityManager", "SafetyNetApi"]),
    ("root", "Magisk / KernelSU / APatch / Zygisk artefacts", "android", S, ["/sbin/.magisk", "/data/adb/magisk", "/data/adb/modules", "/data/adb/ksu",
                                                                              "/data/adb/ap/", "me.weishu.kernelsu", "me.bmax.apatch", "KernelSU", "APatch",
                                                                              "zygisk", "Zygisk", "magiskhide", "MagiskHide", "/cache/magisk.log", "magisk.db"]),
    ("root", "Other su / busybox / root-app file probes", "android", W, ["/system/app/Superuser.apk", "/system/xbin/busybox", "/system/bin/failsafe/su",
                                                                           "/cache/su", "/data/local/su", "/system/xbin/daemonsu", "/su/bin/su", "/system/xbin/mu",
                                                                           "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup", "/data/su", "/dev/com.koushikdutta.superuser.daemon"]),
    ("root", "Root-management / root-cloak package probes", "android", W, ["com.devadvance.rootcloak", "com.devadvance.rootcloakplus", "com.amphoras.hidemyroot",
                                                                           "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.zachspong.temprootremovejb",
                                                                           "com.ramdroid.appquarantine", "com.yellowes.su", "stericson.RootTools", "com/stericson/RootTools"]),
    ("root", "Runtime.exec('su' / 'which su')", "android", W, ["which su", "\"su\" -c", "/system/xbin/which"]),
    ("root", "Root system-property checks (ro.debuggable / ro.secure / ro.build.tags)", "android", W, ["ro.debuggable", "ro.secure", "ro.build.tags"]),
    ("root", "Mount-table inspection (/proc/mounts, mountinfo)", "android", W, ["/proc/mounts", "/proc/self/mounts", "/proc/self/mountinfo", "/proc/self/mountstats"]),
    ("root", "SELinux mode check", "android", W, ["/sys/fs/selinux/enforce", "/sys/fs/selinux", "getenforce", "isSELinuxEnforced"]),
    ("root", "Unix-socket probe (/proc/net/unix)", "android", W, ["/proc/net/unix"]),
    ("root", "Verified-boot / bootloader-lock state", "android", W, ["ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.boot.vbmeta.device_state",
                                                                      "ro.boot.veritymode", "ro.oem_unlock_supported", "sys.oem_unlock_allowed"]),
    ("root", "Hardware key attestation", "android", S, ["setAttestationChallenge", "KeyAttestationException", "key_attestation"]),
    ("root", "More su file locations", "android", W, ["/data/local/bin/su", "/vendor/bin/su", "/system/sbin/su", "/system/bin/.ext/su"]),
    # ---- jailbreak (ios) ----
    ("root", "IOSSecuritySuite", "ios", S, ["IOSSecuritySuite", "amIJailbroken"]),
    ("root", "JailMonkey / jailbreak plugin", "ios", S, ["JailMonkey", "DTTJailbreakDetection", "flutter_jailbreak_detection",
                                                         "jailbreak_detection", "RNJailMonkey"]),
    ("root", "Jailbreak file probes", "ios", W, ["/Applications/Cydia.app", "/Library/MobileSubstrate", "/usr/sbin/sshd", "/etc/apt",
                                                 "/private/var/lib/apt", "/var/jb", "/Applications/Sileo.app", "/bin/bash",
                                                 "/usr/bin/ssh", "/private/var/stash"]),
    ("root", "Cydia / Sileo URL scheme probe", "ios", W, ["cydia://", "sileo://", "zbra://", "filza://"]),
    ("root", "isJailbroken-style helper", "ios", W, ["isJailbroken", "isJailBroken", "jailbreakDetected", "checkJailbreak", "isDeviceJailbroken"]),
    ("root", "Dopamine / palera1n / rootless jailbreak artefacts", "ios", S, ["Dopamine", "dopamine", "palera1n", "checkra1n", "unc0ver", "Taurine", "Odyssey",
                                                                               "XinaA15", "Fugu15", "libjailbreak", ".jbroot", "/var/jb/", "/var/binpack",
                                                                               "/.bootstrapped", "/.installed_unc0ver", "/.installed_palera1n", "procursus", "Procursus"]),
    ("root", "Tweak / package-manager file probes", "ios", W, ["/Applications/Zebra.app", "/Applications/Filza.app", "/Applications/Installer.app", "/usr/libexec/cydia",
                                                              "/usr/lib/libsubstitute.dylib", "/usr/lib/libsubstrate.dylib", "/usr/lib/substitute-inserter.dylib",
                                                              "/usr/lib/TweakInject", "/Library/Frameworks/CydiaSubstrate.framework", "/var/lib/dpkg", "/var/cache/apt",
                                                              "/private/var/lib/cydia", "/usr/bin/cycript", "/usr/lib/libcycript.dylib", "/Library/PreferenceBundles",
                                                              "/Library/PreferenceLoader", "/var/mobile/Library/SBSettings", "/usr/lib/libhooker.dylib", "/usr/lib/libellekit.dylib"]),
    ("root", "TrollStore (sideload-installer) probe", "ios", W, ["TrollStore", "trollstore"]),
    ("root", "Sandbox-escape write probes", "ios", W, ["/private/jailbreak.txt", "/private/jb.txt", "/private/test.txt", "/private/var/mobile/jb", "/private/jailbreak"]),
    ("root", "Symlinked-system-directory probes", "ios", W, ["/Library/Ringtones", "/Library/Wallpaper", "/usr/arm-apple-darwin9", "/usr/include",
                                                              "/usr/libexec", "/usr/share", "destinationOfSymbolicLinkAtPath"]),
    # ---- frida ----
    ("frida", "frida artefact strings", "any", S, ["frida-server", "frida-agent", "re.frida.server", "FridaGadget", "frida-gadget",
                                                   "gum-js-loop", "linjector", "LIBFRIDA"]),
    ("frida", "Thread-name probes (gmain / gdbus)", "android", W, ["gmain", "gdbus", "pool-frida"]),
    ("frida", "Frida default port probe (27042)", "any", W, [":27042", "\x0027042\x00", "\"27042\"", "'27042'", "=27042", "port 27042"]),
    ("frida", "/proc/self/maps scan", "android", W, ["/proc/self/maps", "/proc/%d/maps"]),
    ("frida", "Frida on-disk / network probes", "android", W, ["/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server", "frida_agent_main", "frida-helper",
                                                              "/proc/net/tcp", "libfrida-gadget", "frida-gadget.so"]),
    ("frida", "Frida on-disk / network probes", "ios", W, ["/usr/sbin/frida-server", "/usr/lib/frida", "/usr/bin/frida-server", "frida-core", "FridaGadget.dylib"]),
    ("frida", "D-Bus handshake probe (AUTH)", "any", W, ["AUTH\r\n"]),
    ("frida", "Thread / fd enumeration under /proc/self", "android", W, ["/proc/self/task", "/proc/%d/task", "/proc/self/fd", "/proc/%d/fd"]),
    ("frida", "Inline-hook / library-integrity probes (libc on-disk path)", "android", W, ["/system/lib64/libc.so", "/system/lib/libc.so",
                                                                                           "/apex/com.android.runtime/lib64/bionic/libc.so",
                                                                                           "/apex/com.android.runtime/lib/bionic/libc.so"]),
    ("frida", "IOSSecuritySuite runtime-hook checks", "ios", S, ["amIRuntimeHooked", "amIReverseEngineered", "amIProxied"]),
    # ---- hook frameworks ----
    ("hooking", "Xposed / LSPosed / EdXposed", "android", S, ["de/robv/android/xposed", "XposedBridge", "LSPosed", "EdXposed", "XposedHelpers"]),
    ("hooking", "Xposed / Riru / Lucky Patcher on-disk probes", "android", W, ["de.robv.android.xposed.installer", "org.lsposed.manager", "io.va.exposed",
                                                                          "/system/framework/XposedBridge.jar", "libxposed", "riru", "Riru", "libriru", "edxp", "Shamiko",
                                                                          "com.chelpus.lackypatch", "com.dimonvideo.luckypatcher", "com.android.vending.billing.InAppBillingService.COIN"]),
    ("hooking", "Java-layer hook anomalies (zygote / Xposed frames)", "android", W, ["com.android.internal.os.ZygoteInit", "XposedBridge.main",
                                                                                      "com.saurik.substrate.MS$2"]),
    ("hooking", "Substrate / Substitute", "android", S, ["com/saurik/substrate", "com.saurik.substrate"]),
    ("hooking", "Substrate / libhooker / ElleKit", "ios", S, ["MobileSubstrate", "SubstrateLoader", "libhooker", "ellekit", "TweakInject"]),
    ("hooking", "DYLD_INSERT_LIBRARIES check", "ios", S, ["DYLD_INSERT_LIBRARIES"]),
    ("hooking", "Loaded-image enumeration", "ios", W, ["_dyld_image_count", "_dyld_get_image_name"]),
    # ---- debugger ----
    ("debugger", "Debug.isDebuggerConnected", "android", S, ["isDebuggerConnected", "waitingForDebugger"]),
    ("debugger", "TracerPid check", "android", S, ["TracerPid"]),
    ("debugger", "FLAG_DEBUGGABLE check", "android", W, ["FLAG_DEBUGGABLE", "ApplicationInfo.flags"]),
    ("debugger", "ptrace anti-attach", "any", W, ["ptrace"]),
    ("debugger", "sysctl P_TRACED check", "ios", W, ["sysctl", "P_TRACED", "kinfo_proc"]),
    ("debugger", "amIDebugged-style helper", "ios", S, ["amIDebugged", "AmIBeingDebugged", "isDebuggerAttached", "PT_DENY_ATTACH"]),
    ("debugger", "/proc/self/status or jdwp probe", "android", W, ["/proc/self/status", "jdwp", "JDWP"]),
    ("debugger", "USB / ADB debugging setting check", "android", W, ["adb_enabled", "development_settings_enabled"]),
    # ---- emulator / simulator ----
    ("emulator", "Emulator build properties", "android", S, ["ro.kernel.qemu", "ro.boot.qemu", "goldfish", "ranchu", "Genymotion", "vbox86", "google_sdk"]),
    ("emulator", "Emulator device files and vendor strings", "android", W, ["/dev/qemu_pipe", "/dev/socket/qemud", "/sys/qemu_trace", "/system/bin/qemu-props",
                                                                          "/system/lib/libc_malloc_debug_qemu.so", "sdk_gphone", "Android SDK built for", "generic_x86",
                                                                          "BlueStacks", "bluestacks", "/data/.bluestacks.prop", "Droid4X", "microvirt", "memu", "LDPlayer",
                                                                          "ttVM_Hdragon", "10.0.2.15"]),
    ("emulator", "isEmulator-style helper", "android", W, ["isEmulator", "isRunningOnEmulator", "detectEmulator", "EmulatorDetector"]),
    ("emulator", "Simulator checks", "ios", S, ["SIMULATOR_DEVICE_NAME", "amIRunInEmulator"]),
    ("emulator", "Simulator flag (also used by device-info plugins)", "ios", W, ["isSimulator", "TARGET_OS_SIMULATOR"]),
    # ---- pinning ----
    ("pinning", "OkHttp CertificatePinner", "android", S, ["okhttp3/CertificatePinner", "CertificatePinner$Builder"]),
    ("pinning", "TrustKit", "any", S, ["com/datatheorem/android/trustkit", "TrustKit", "TSKPinningValidator"]),
    ("pinning", "Pinning plugin (RN / Flutter / Cordova / Capacitor)", "any", S, ["react-native-ssl-pinning", "com/toyberman", "ssl_pinning_plugin",
                                                                                 "http_certificate_pinning", "SSLCertificatePinning", "cordova-plugin-advanced-http"]),
    ("pinning", "Pin-hash literals (sha256/...)", "any", W, ["sha256/", "sha1/"]),
    ("pinning", "Custom TrustManager / pin check", "android", W, ["X509TrustManager", "checkServerTrusted", "getAcceptedIssuers"]),
    ("pinning", "Alamofire / AFNetworking pinning", "ios", S, ["PinnedCertificatesTrustEvaluator", "PublicKeysTrustEvaluator", "AFSecurityPolicy",
                                                              "AFSSLPinningMode", "ServerTrustManager"]),
    ("pinning", "URLSession trust-challenge handling", "ios", W, ["didReceiveChallenge", "SecTrustEvaluate", "SecTrustSetAnchorCertificates",
                                                                 "SecTrustCopyKey", "SecTrustEvaluateWithError", "NSURLAuthenticationMethodServerTrust"]),
    ("pinning", "Approov", "any", S, ["io/approov", "Approov"]),
    # ---- tamper / integrity ----
    ("tamper", "Play Integrity / SafetyNet attestation", "android", S, ["com/google/android/play/core/integrity", "com/google/android/gms/safetynet"]),
    ("tamper", "App signature verification", "android", W, ["GET_SIGNATURES", "GET_SIGNING_CERTIFICATES", "checkSignatures", "getSigningInfo", "verifySignature"]),
    ("tamper", "Installer-source check", "android", W, ["getInstallerPackageName", "getInstallSourceInfo"]),
    ("tamper", "APK / dex integrity (CRC) check", "android", W, ["getCrc", "CRC32", "classes.dex"]),
    ("tamper", "App Attest / DeviceCheck", "ios", S, ["DCAppAttestService", "DeviceCheck", "DCDevice"]),
    ("tamper", "IOSSecuritySuite integrity checks", "ios", S, ["amITampered", "MachOIntegrity", "SignerIdentity"]),
    ("tamper", "Code-signature / entitlement APIs", "ios", W, ["SecStaticCodeCheckValidity", "SecCodeCopySigningInformation", "SecTaskCopyValueForEntitlement", "get-task-allow"]),
    ("tamper", "Code-signature / provisioning check", "ios", W, ["embedded.mobileprovision", "_CodeSignature", "LC_CODE_SIGNATURE"]),
    # ---- screen capture ----
    ("screen", "FLAG_SECURE / secure-screen plugin", "android", S, ["FLAG_SECURE", "flutter_windowmanager", "privacy-screen", "PrivacyScreen", "secureScreen"]),
    ("screen", "Capture / screenshot observers", "ios", S, ["UIScreenCapturedDidChangeNotification", "isCaptured", "UIApplicationUserDidTakeScreenshotNotification",
                                                           "CapacitorCommunityPrivacyScreen", "PrivacyScreen", "screenshotPrevent", "preventScreenshot"]),
    # ---- obfuscation / packing ----
    ("obfuscation", "Packer / app-shielding native library", "android", S, ["libjiagu", "libDexHelper", "libsecexe", "libprotectClass", "libbangcle",
                                                                            "libnqshield", "libexecmain", "libmobisec", "libijiami", "libegis", "libapktoolplus",
                                                                            "libshella", "libtup.so", "libAppGuard"]),
    ("obfuscation", "DexGuard / iXGuard", "any", S, ["com/guardsquare", "DexGuard", "iXGuard"]),
    ("obfuscation", "Hermes / JS bytecode (React Native, non-plain JS)", "any", W, ["libhermes"]),
    ("obfuscation", "Swift obfuscator / symbol stripping marker", "ios", W, ["SwiftShield", "Obfuscator-LLVM", "ollvm"]),
    # ---- commercial RASP / shielding SDKs ----
    ("rasp", "Promon SHIELD", "any", S, ["no/promon", "PromonShield", "libshield"]),
    ("rasp", "Appdome", "any", S, ["com/appdome", "AppdomeSDK", "appdome-"]),
    ("rasp", "Zimperium zDefend", "any", S, ["com/zimperium", "ZimperiumZDefend", "ZDefend"]),
    ("rasp", "Talsec freeRASP / AppiCrypt", "any", S, ["com/aheaditec/talsec", "com/ahead/freerasp", "TalsecRuntime", "freeRASP"]),
    ("rasp", "Arxan / Digital.ai", "any", S, ["com/arxan", "ai/digital/", "TransformIT", "GuardIT"]),
    ("rasp", "Verimatrix", "any", S, ["com/verimatrix", "VerimatrixAppShield"]),
    ("rasp", "Approov", "any", S, ["io/approov", "Approov"]),
    ("rasp", "Build38 T.A.K.", "any", S, ["com/build38", "Build38"]),
    ("rasp", "Cybereason / Lookout / Checkmarx runtime", "any", W, ["com/lookout/", "LookoutSDK"]),
]


def _needle_bytes(n: str) -> List[bytes]:
    out = [n.encode()]
    if "/" in n and "." not in n and n[0].isalpha() and n.count("/") >= 2:   # class-ish path: also match dotted form
        out.append(n.replace("/", ".").encode())
    return out


_COMPILED: List[Tuple[str, str, str, str, List[bytes]]] = [
    (cat, label, plat, strength, [b for n in needles for b in _needle_bytes(n)])
    for cat, label, plat, strength, needles in SIGS
]
_LIB_NAME = re.compile(r"(?i)(libjiagu|libdexhelper|libsecexe|libprotectclass|libbangcle|libnqshield|libmobisec|libijiami|libegis|libshella|libappguard|libshield|libfrida)")


# Frameworks / libraries that are well-known third-party SDKs. Indicators found only inside these are
# reported as "SDK only": the SDK contains them, which does not mean the app itself uses them.
_THIRD_PARTY = re.compile(r"(?i)(sentry|firebase|google|gtm|crashlytics|appsflyer|adjust|branch|mixpanel|amplitude|segment|"
                          r"fbsdk|facebook|afnetworking|sdwebimage|alamofire|appcheck|nanopb|promises|razorpay|clevertap|"
                          r"moengage|onesignal|datadog|newrelic|kingfisher|lottie|realm|libsentry|libfirebase|libflutter|"
                          r"libreactnative|libhermes|libjsc|libfbjni|libc\+\+|libmonochrome|libwebview|libcrashlytics)")


def _is_sdk_path(rel: str) -> bool:
    base = rel.rsplit("/", 1)[-1]
    parent = rel.rsplit("/", 2)[-2] if "/" in rel else ""
    return bool(_THIRD_PARTY.search(base) or (parent.endswith(".framework") and _THIRD_PARTY.search(parent)))


def _is_macho(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) in MACHO_MAGIC
    except OSError:
        return False


def _strip_codesig(data: bytes) -> bytes:
    """Blank the LC_CODE_SIGNATURE blob of every Mach-O slice: its embedded entitlements / requirements
    (get-task-allow, team ids ...) are signing metadata, not code that performs a check."""
    import struct
    if len(data) < 32:
        return data
    magic = struct.unpack_from(">I", data, 0)[0]
    slices = []
    if magic in (0xcafebabe, 0xcafebabf):
        n = struct.unpack_from(">I", data, 4)[0]
        wide = magic == 0xcafebabf
        for i in range(min(n, 16)):
            if wide:
                off = struct.unpack_from(">Q", data, 8 + i * 32 + 8)[0]
            else:
                off = struct.unpack_from(">I", data, 8 + i * 20 + 8)[0]
            slices.append(off)
    else:
        slices.append(0)
    spans = []
    for base in slices:
        if base + 32 > len(data):
            continue
        m = struct.unpack_from("<I", data, base)[0]
        if m not in (0xfeedface, 0xfeedfacf):
            continue
        ncmds = struct.unpack_from("<I", data, base + 16)[0]
        p = base + (32 if m == 0xfeedfacf else 28)
        for _ in range(min(ncmds, 4096)):
            if p + 8 > len(data):
                break
            cmd, size = struct.unpack_from("<II", data, p)
            if cmd == 0x1d and p + 16 <= len(data):
                off, sz = struct.unpack_from("<II", data, p + 8)
                spans.append((base + off, base + off + sz))
            if size < 8:
                break
            p += size
    if not spans:
        return data
    b = bytearray(data)
    for s, e in spans:
        s, e = max(0, s), min(len(b), e)
        if s < e:
            b[s:e] = bytes(e - s)
    return bytes(b)


# Needles that, inside a dex, are an unrelated identifier rather than a check. WindowManager's FLAG_SECURE is a
# compile-time constant (javac / d8 inline 0x2000), so the bare string "FLAG_SECURE" in a dex is a field of some other class
# (androidx.media AudioAttributesCompat.FLAG_SECURE, an audio-routing flag). Real secure-window code is found through
# the Window.addFlags / setFlags probe instead.
BENIGN_DEX_FIELDS = {"FLAG_SECURE": ()}
_BENIGN_DEX = {k.encode() for k in BENIGN_DEX_FIELDS}


def _benign(needle: bytes, rel: str, data: bytes) -> bool:
    """True when every occurrence of the needle in a dex is the bare identifier string (MUTF-8 length byte + name + NUL),
    i.e. a field / constant name; a longer string containing it (a config key, a log message) still counts."""
    if needle not in _BENIGN_DEX or not rel.endswith(".dex"):
        return False
    return data.count(needle) == data.count(bytes([len(needle)]) + needle + b"\0")


def _candidate_files(app: appfiles.App) -> Iterable[str]:
    for p in app.files():
        ext = os.path.splitext(p)[1].lower()
        try:
            size = os.path.getsize(p)
        except OSError:
            continue
        if size == 0 or size > MAX_FILE:
            continue
        if ext in SCAN_EXT or (app.platform == "ios" and ext == "" and _is_macho(p)):
            yield p


def detect(app: appfiles.App) -> Dict[str, Any]:
    """-> {"categories": {cat: {"label", "detected", "evidence": [labels], "files": [paths]}}, "packed": bool}"""
    plat = app.platform
    hits: Dict[Tuple[str, str], Set[str]] = {}          # (category, label) -> files that matched
    sigs = [s for s in _COMPILED if s[2] in (plat, "any")]
    names_seen: List[str] = []
    for p in _candidate_files(app):
        rel = app.rel(p)
        names_seen.append(os.path.basename(p))
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if data[:4] in MACHO_MAGIC:
            data = _strip_codesig(data)
        # Frida's own libraries ship inside gadget-style repackaged apps; a frida *library* is not a detector.
        for cat, label, _pl, _st, needles in sigs:
            key = (cat, label)
            if len(hits.get(key, ())) >= 3:
                continue
            if any(n in data and not _benign(n, rel, data) for n in needles):
                hits.setdefault(key, set()).add(rel)
    # file-name based indicators (packer libraries) and Android network-security-config pins
    for p in app.files():
        base = os.path.basename(p)
        if app.platform == "android" and _LIB_NAME.search(base) and not base.lower().startswith("libfrida"):
            hits.setdefault(("obfuscation", "Packer / app-shielding native library"), set()).add(app.rel(p))
        if app.platform == "android" and "/res/xml/" in p.replace(os.sep, "/") and p.endswith(".xml"):
            try:
                with open(p, "rb") as fh:
                    d = fh.read()
                if b"pin-set" in d or "pin-set".encode("utf-16le") in d:
                    hits.setdefault(("pinning", "network_security_config <pin-set>"), set()).add(app.rel(p))
            except OSError:
                pass
    if app.platform == "ios":
        pinned = (app.info_plist.get("NSAppTransportSecurity") or {}).get("NSPinnedDomains")
        if pinned:
            hits.setdefault(("pinning", "Info.plist NSPinnedDomains"), set()).add("Info.plist")
        for p in app.files():
            if p.lower().endswith((".cer", ".der", ".crt")):
                hits.setdefault(("pinning", "Bundled certificate file (.cer/.der/.crt)"), set()).add(app.rel(p))
                break

    result: Dict[str, Any] = {"categories": {}, "platform": plat}
    for cat, labels in CATEGORIES:
        evid_all = [(label, sorted(files)) for (c, label), files in hits.items() if c == cat]
        # indicators that appear only inside well-known third-party SDK binaries are not the app's own checks
        evid = [(l, [f for f in fs if not _is_sdk_path(f)]) for l, fs in evid_all]
        evid = [(l, fs) for l, fs in evid if fs]
        sdk_only = [l for l, fs in evid_all if fs and l not in {x[0] for x in evid}]
        strong_labels = {s[1] for s in _COMPILED if s[0] == cat and s[3] == S}
        strong = [e for e in evid if e[0] in strong_labels or e[0].startswith(("network_security_config", "Info.plist", "Bundled"))]
        weak = [e for e in evid if e not in strong]
        if strong:
            level = "detected"
        elif len(weak) >= 2:
            level = "likely"
        elif weak:
            level = "weak signal"
        elif sdk_only:
            level = "SDK only"
        else:
            level = "not found"
        shown = strong + weak
        if level == "SDK only":
            shown = [(l, []) for l in sdk_only]
        result["categories"][cat] = {
            "label": labels[plat], "level": level,
            "evidence": [e[0] for e in shown],
            "files": sorted({f for e in shown for f in e[1]})[:5],
            "sdk_evidence": sdk_only if level != "SDK only" else [],
        }
    obf = result["categories"]["obfuscation"]
    result["packed"] = obf["level"] == "detected" and any("Packer" in e for e in obf["evidence"])
    return result


def binaries(app: appfiles.App) -> Dict[str, Any]:
    """Hardening of every native binary: Mach-O (main + frameworks + extensions) or ELF (.so)."""
    rows: List[Dict[str, Any]] = []
    for p in app.files():
        rel = app.rel(p)
        try:
            if app.platform == "ios":
                if not (os.path.splitext(p)[1].lower() in ("", ".dylib") and _is_macho(p)):
                    continue
                h = engine.analyze_macho_hardening(p)
                enc = engine.macho_encryption_report(p)
                is_exec = "/Frameworks/" not in rel and not rel.endswith(".dylib")
                rows.append({
                    "name": rel.split("Payload/", 1)[-1], "main": is_exec and rel.count("/") <= 3,
                    "pie": h.get("pie"), "canary": h.get("stack_canary_symbol"), "swift": h.get("is_swift"),
                    "exec_stack": h.get("allow_stack_execution"),
                    "encrypted": any(e.get("verdict") == "ciphertext" for e in enc),
                })
            else:
                if not p.endswith(".so"):
                    continue
                h = engine.analyze_elf_hardening(p)
                if h.get("error"):
                    continue
                rows.append({"name": rel, "nx": h.get("nx_stack"), "relro": h.get("relro"),
                             "canary": h.get("stack_canary"), "fortify": h.get("fortify_source"),
                             "pie": None})
        except Exception:
            continue
    weak = []
    for r in rows:
        issues = []
        if app.platform == "ios":
            if r["main"] and r["pie"] is False:
                issues.append("not PIE")
            if r["exec_stack"]:
                issues.append("executable stack")
            if r["canary"] is False and not r["swift"]:
                issues.append("no stack canary")
            if r["encrypted"]:
                issues.append("still FairPlay-encrypted")
        else:
            if r["nx"] is False:
                issues.append("executable stack")
            if r["relro"] == "none":
                issues.append("no RELRO")
            if r["canary"] is False:
                issues.append("no stack canary")
        r["issues"] = issues
        if issues:
            weak.append(r)
    return {"platform": app.platform, "total": len(rows), "weak": weak, "rows": rows}


_SQL_PLUGIN = (b"CapacitorSQLite", b"capacitor-community-sqlite", b"CapacitorCommunitySqlite", b"@capacitor-community/sqlite",
               b"capacitor-sqlite")
_SQLCIPHER = (b"sqlcipher", b"SQLCipher", b"net/zetetic")


def capacitor_sql(app: appfiles.App) -> Dict[str, Any]:
    """Capacitor SQLite plugin database-encryption state. Empty dict when the plugin is not in the app."""
    plugin = False
    cfg: Dict[str, Any] = {}
    cipher_files: List[str] = []
    modes: Set[str] = set()
    hard_coded = False
    plain_dbs: List[str] = []
    for p in app.files():
        rel = app.rel(p)
        base = os.path.basename(p)
        ext = os.path.splitext(p)[1].lower()
        try:
            size = os.path.getsize(p)
        except OSError:
            continue
        if ext in (".db", ".sqlite", ".sqlite3") and size > 0:
            try:
                with open(p, "rb") as fh:
                    if fh.read(16).startswith(b"SQLite format 3"):
                        plain_dbs.append(rel)
            except OSError:
                pass
        if base in ("capacitor.config.json", "capacitor.plugins.json"):
            try:
                with open(p, "rb") as fh:
                    raw = fh.read()
                if any(n in raw for n in _SQL_PLUGIN):
                    plugin = True
                if base == "capacitor.config.json":
                    c = (json.loads(raw).get("plugins") or {}).get("CapacitorSQLite")
                    if isinstance(c, dict):
                        cfg = c
                        plugin = True
            except Exception:
                pass
        if ext in (".js", ".mjs", ".dex", ".so", ".dylib", ".json") or (app.platform == "ios" and ext == "" and size < MAX_FILE and _is_macho(p)):
            if size > MAX_FILE:
                continue
            try:
                with open(p, "rb") as fh:
                    d = fh.read()
            except OSError:
                continue
            if ext in (".js", ".mjs"):
                if any(n in d for n in _SQL_PLUGIN):
                    plugin = True
                if b"createConnection" in d:
                    for m in re.finditer(rb'createConnection\([^)]{0,200}?["\'](no-encryption|encryption|secret|newsecret)["\']', d):
                        modes.add(m.group(1).decode())
                if re.search(rb'setEncryptionSecret\(\s*["\'][^"\']{4,}["\']', d):
                    hard_coded = True
            else:
                if any(n in d for n in _SQL_PLUGIN):
                    plugin = True
                if any(n in d for n in _SQLCIPHER) and not _is_sdk_path(rel):
                    cipher_files.append(rel)
    if not plugin:
        return {}
    key = "iosIsEncryption" if app.platform == "ios" else "androidIsEncryption"
    cfg_flag = cfg.get(key)
    enc_modes = modes & {"encryption", "secret", "newsecret"}
    if cfg_flag is True or enc_modes:
        status = "on"
    elif cfg_flag is False or "no-encryption" in modes:
        status = "off"
    else:
        status = "off" if not cipher_files else "unclear"
    return {
        "status": status, "config_flag": cfg_flag, "config_key": key if key in cfg else None,
        "modes": sorted(modes), "sqlcipher": sorted(cipher_files)[:3], "hard_coded_secret": hard_coded,
        "plain_bundled_dbs": plain_dbs[:5],
        "biometric": bool(cfg.get("iosBiometric" if app.platform == "ios" else "androidBiometric")),
        "keychain_prefix": cfg.get("iosKeychainPrefix"),
    }


def capacitor_flags(app: appfiles.App) -> Dict[str, Any]:
    """PrivacyScreen plugin config (screen-capture protection) when present."""
    for p in app.files():
        if os.path.basename(p) == "capacitor.config.json":
            try:
                with open(p, "rb") as fh:
                    c = (json.loads(fh.read()).get("plugins") or {}).get("PrivacyScreen")
                if isinstance(c, dict):
                    return {"privacy_screen_enabled": c.get("enable")}
            except Exception:
                pass
    return {}


def detect_all(app: appfiles.App) -> Dict[str, Any]:
    r = detect(app)
    r["binaries"] = binaries(app)
    r["capacitor_sql"] = capacitor_sql(app)
    r["capacitor"] = capacitor_flags(app)
    return r


def detect_path(path: str) -> Dict[str, Any]:
    with appfiles.unpacked(path) as app:
        return detect_all(app)
