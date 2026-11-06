"""Readable rendering of permissions and entitlements for `info`."""
import re
import shutil
import textwrap
from typing import Any, Dict, List, Tuple

from .style import bad, dim, good, head, warn

# iOS usage-description key -> (friendly name, risk) ; risk: high | med | low
IOS_PERMS: Dict[str, Tuple[str, str]] = {
    "NSCameraUsageDescription": ("Camera", "med"),
    "NSMicrophoneUsageDescription": ("Microphone", "med"),
    "NSPhotoLibraryUsageDescription": ("Photo library (read)", "med"),
    "NSPhotoLibraryAddUsageDescription": ("Photo library (save only)", "low"),
    "NSLocationWhenInUseUsageDescription": ("Location (while using the app)", "med"),
    "NSLocationAlwaysUsageDescription": ("Location (always, legacy key)", "high"),
    "NSLocationAlwaysAndWhenInUseUsageDescription": ("Location (always + while using)", "high"),
    "NSLocationUsageDescription": ("Location", "med"),
    "NSContactsUsageDescription": ("Contacts", "high"),
    "NSCalendarsUsageDescription": ("Calendars", "med"),
    "NSRemindersUsageDescription": ("Reminders", "med"),
    "NSFaceIDUsageDescription": ("Face ID", "low"),
    "NSBiometricsUsageDescription": ("Biometrics", "low"),
    "NSBluetoothAlwaysUsageDescription": ("Bluetooth", "med"),
    "NSBluetoothPeripheralUsageDescription": ("Bluetooth (peripheral, legacy key)", "med"),
    "NSMotionUsageDescription": ("Motion & fitness", "low"),
    "NSSpeechRecognitionUsageDescription": ("Speech recognition", "med"),
    "NSHealthShareUsageDescription": ("Health data (read)", "high"),
    "NSHealthUpdateUsageDescription": ("Health data (write)", "high"),
    "NSUserTrackingUsageDescription": ("Cross-app tracking", "med"),
    "NSLocalNetworkUsageDescription": ("Local network", "med"),
    "NSAppleMusicUsageDescription": ("Media library", "low"),
    "NFCReaderUsageDescription": ("NFC", "med"),
    "NSHomeKitUsageDescription": ("HomeKit", "med"),
    "NSSiriUsageDescription": ("Siri", "low"),
}

# Android permissions worth naming: raw suffix -> (friendly name, risk)
ANDROID_PERMS: Dict[str, Tuple[str, str]] = {
    "CAMERA": ("Camera", "med"), "RECORD_AUDIO": ("Microphone", "med"),
    "ACCESS_FINE_LOCATION": ("Precise location", "med"), "ACCESS_COARSE_LOCATION": ("Approximate location", "low"),
    "ACCESS_BACKGROUND_LOCATION": ("Location in background", "high"),
    "READ_CONTACTS": ("Read contacts", "high"), "WRITE_CONTACTS": ("Modify contacts", "high"),
    "READ_SMS": ("Read SMS", "high"), "RECEIVE_SMS": ("Receive SMS", "high"), "SEND_SMS": ("Send SMS", "high"),
    "READ_CALL_LOG": ("Read call log", "high"), "WRITE_CALL_LOG": ("Modify call log", "high"),
    "READ_PHONE_STATE": ("Phone state / identifiers", "med"), "READ_PHONE_NUMBERS": ("Phone number", "med"),
    "CALL_PHONE": ("Place calls", "med"),
    "READ_EXTERNAL_STORAGE": ("Read shared storage", "med"), "WRITE_EXTERNAL_STORAGE": ("Write shared storage", "med"),
    "MANAGE_EXTERNAL_STORAGE": ("All files access", "high"),
    "READ_MEDIA_IMAGES": ("Read photos", "med"), "READ_MEDIA_VIDEO": ("Read videos", "med"), "READ_MEDIA_AUDIO": ("Read audio", "med"),
    "POST_NOTIFICATIONS": ("Show notifications", "low"),
    "SYSTEM_ALERT_WINDOW": ("Draw over other apps", "high"), "REQUEST_INSTALL_PACKAGES": ("Install apps", "high"),
    "BIND_ACCESSIBILITY_SERVICE": ("Accessibility service (can read screen)", "high"),
    "USE_BIOMETRIC": ("Biometric prompt", "low"), "USE_FINGERPRINT": ("Fingerprint", "low"),
    "BLUETOOTH_CONNECT": ("Bluetooth connect", "low"), "BLUETOOTH_SCAN": ("Bluetooth scan", "med"),
    "GET_ACCOUNTS": ("List accounts", "med"), "READ_CALENDAR": ("Read calendar", "med"), "WRITE_CALENDAR": ("Modify calendar", "med"),
    "BODY_SENSORS": ("Body sensors", "med"), "ACTIVITY_RECOGNITION": ("Physical activity", "low"),
    "USE_FULL_SCREEN_INTENT": ("Full-screen intents", "low"), "SCHEDULE_EXACT_ALARM": ("Exact alarms", "low"),
}

_RISK_STYLE = {"high": bad, "med": warn, "low": lambda t: t}
_RISK_MARK = {"high": "●", "med": "●", "low": "○"}
_RISK_ORDER = {"high": 0, "med": 1, "low": 2}


def _width() -> int:
    return max(78, min(110, shutil.get_terminal_size((100, 24)).columns))


def ios_friendly(key: str) -> Tuple[str, str]:
    if key in IOS_PERMS:
        return IOS_PERMS[key]
    base = re.sub(r"UsageDescription$", "", re.sub(r"^NS", "", key))
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", base) or key, "med"


def ios_permission_lines(perms: List[str], purposes: Dict[str, Any], *, full: bool = False) -> List[str]:
    L = ["", head(f"Permissions requested ({len(perms)})")]
    rows = sorted(((ios_friendly(k), k) for k in perms), key=lambda r: (_RISK_ORDER[r[0][1]], r[0][0]))
    name_w = max([len(r[0][0]) for r in rows] + [10])
    text_w = _width() - (6 + name_w)
    for (name, risk), key in rows:
        purpose = str(purposes.get(key, "") or "").strip()
        lines = textwrap.wrap(purpose, width=text_w) if purpose else []
        first = dim(lines[0]) if lines else bad("(no purpose text)")
        L.append(f"  {_RISK_STYLE[risk](_RISK_MARK[risk])} {_RISK_STYLE[risk](name.ljust(name_w))}  {first}")
        extra = lines[1:] if full else lines[1:2]
        for ln in extra:
            L.append(" " * (6 + name_w) + dim(ln))
        if not full and len(lines) > 2:
            L[-1] += dim(" …")
    L.append("  " + dim("● higher-risk   ○ low-risk   (sorted by risk; --full shows complete purpose text)"))
    return L


_ENT_NOTES = {
    "application-identifier": "app ID (team + bundle id)",
    "com.apple.application-identifier": "app ID (team + bundle id)",
    "com.apple.developer.team-identifier": "developer team",
    "beta-reports-active": "TestFlight crash reports",
    "keychain-access-groups": "shared keychain access groups",
    "com.apple.developer.associated-domains": "universal links / web credentials",
    "com.apple.security.application-groups": "shared app-group container",
    "com.apple.developer.applesignin": "Sign in with Apple",
    "com.apple.developer.healthkit": "HealthKit",
    "com.apple.developer.in-app-payments": "Apple Pay merchant ids",
    "com.apple.developer.networking.wifi-info": "reads the current Wi-Fi network",
    "com.apple.developer.nfc.readersession.formats": "NFC reading",
    "com.apple.developer.usernotifications.time-sensitive": "time-sensitive notifications",
    "com.apple.developer.devicecheck.appattest-environment": "App Attest",
    "inter-app-audio": "inter-app audio",
}


def ios_entitlement_lines(ents: Dict[str, Any], *, full: bool = False) -> List[str]:
    if not ents:
        return []
    L = ["", head(f"Entitlements ({len(ents)})")]
    keys = sorted(ents, key=lambda k: (k != "get-task-allow", str(k)))
    w = min(48, max(len(str(k)) for k in keys))
    for k in keys:
        v = ents[k]
        if k == "get-task-allow":
            val = bad("true") if v else good("false")
            note = bad("debuggable: other processes can attach") if v else dim("not debuggable (release build)")
            L.append(f"  {str(k).ljust(w)}  {val}  {note}")
            continue
        if k == "aps-environment":
            val = good(str(v)) if v == "production" else warn(str(v))
            L.append(f"  {str(k).ljust(w)}  {val}  " + dim("push notifications" + ("" if v == "production" else " (development/sandbox build)")))
            continue
        if isinstance(v, bool):
            val = str(v).lower()
        elif isinstance(v, (list, tuple)):
            val = ", ".join(str(x) for x in v)
        else:
            val = str(v)
        shown = val if full or len(val) <= 70 else val[:67] + "…"
        note = _ENT_NOTES.get(k, "")
        L.append(f"  {str(k).ljust(w)}  {shown}" + (("  " + dim(note)) if note else ""))
    return L


def android_permission_lines(perms: List[str], dangerous: List[str], *, full: bool = False) -> List[str]:
    dang = set(dangerous)
    L = ["", head(f"Permissions declared in the manifest ({len(perms)}, {len(dang)} dangerous)")]
    danger, other = [], []
    for p in perms:
        short = p.rsplit(".", 1)[-1]
        if p in dang:
            name, risk = ANDROID_PERMS.get(short, (short.replace("_", " ").title(), "med"))
            danger.append((risk, name, short))
        else:
            other.append(short)
    danger.sort(key=lambda r: (_RISK_ORDER[r[0]], r[1]))
    if danger:
        w = max(len(r[1]) for r in danger)
        for risk, name, short in danger:
            L.append(f"  {_RISK_STYLE[risk](_RISK_MARK[risk])} {_RISK_STYLE[risk](name.ljust(w))}  {dim(short)}")
    L.append("  " + dim("Android may add implicit permissions at install (e.g. notifications, media access); those are not listed here."))
    if other:
        L.append("  " + dim("Other (normal) permissions:"))
        shown = other if full else other[:12]
        tail = "" if full or len(other) <= 12 else f" … +{len(other) - 12} more (use --full)"
        for ln in textwrap.wrap(", ".join(shown) + tail, width=_width() - 4):
            L.append("    " + dim(ln))
    return L
