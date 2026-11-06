"""False-positive control applied after the engine has produced its findings.

The engine already filters at detection time (whole-word crypto matching, validated
JWTs, placeholder secrets, noise URLs...). This layer adds the checks that need the
*whole picture*:

  * corroboration  - a hardcoded http:// URL cannot be fetched if the platform blocks
                     cleartext traffic, so it is demoted rather than reported as an issue
  * user rules     - a .appsleuth-ignore file with reasons, for the accepted-risk cases
  * de-duplication - identical title+location findings are collapsed
  * transparency   - everything demoted or dropped is recorded in result["triage"], never
                     silently discarded
"""
import fnmatch
import json
import os
import re
from typing import Any, Dict, List, Optional

SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")
_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
_CONF_ORDER = {"heuristic": 0, "confirmed": 1}


# ---------------------------------------------------------------- ignore rules

class IgnoreRule:
    def __init__(self, kind: str, pattern: str, reason: str = "", line_no: int = 0):
        self.kind, self.pattern, self.reason, self.line_no = kind, pattern, reason, line_no
        self._rx = None
        if kind in ("title", "evidence") and len(pattern) > 2 and pattern.startswith("/") and pattern.endswith("/"):
            self._rx = re.compile(pattern[1:-1], re.I)

    def matches(self, f: Dict[str, Any]) -> bool:
        if self.kind == "fingerprint":
            return f.get("fingerprint", "") == self.pattern
        if self.kind == "severity":
            return f.get("severity", "").upper() == self.pattern.upper()
        value = str(f.get(self.kind) or "")
        if self.kind == "location":
            return fnmatch.fnmatch(value, self.pattern)
        if self._rx is not None:
            return bool(self._rx.search(value))
        return self.pattern.lower() in value.lower()


def load_ignore_file(path: str) -> List[IgnoreRule]:
    """Lines look like:

        title: Cleartext (http://) URLs        # substring match, or /regex/
        location: *Lcom/vendor/sdk/*           # glob
        evidence: /^https?:\\/\\/localhost/
        fingerprint: 3fa9c21be07d4a55
        # anything after ' -- ' is the recorded reason
        title: MD5 hash identifier -- used for cache keys only
    """
    rules = []
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            reason = ""
            if " -- " in line:
                line, reason = line.split(" -- ", 1)
            kind, sep, pattern = line.partition(":")
            kind, pattern = kind.strip().lower(), pattern.strip()
            if not sep or kind not in ("title", "location", "evidence", "fingerprint", "severity") or not pattern:
                raise ValueError(f"{path}:{n}: expected 'title|location|evidence|fingerprint: <pattern>'")
            rules.append(IgnoreRule(kind, pattern, reason.strip(), n))
    return rules


def find_default_ignore_file(start: str) -> Optional[str]:
    for d in (os.getcwd(), os.path.dirname(os.path.abspath(start))):
        p = os.path.join(d, ".appsleuth-ignore")
        if os.path.isfile(p):
            return p
    return None


# ------------------------------------------------------------------ corroboration

def _titles(findings: List[Dict[str, Any]]) -> List[str]:
    return [f.get("title", "") for f in findings]


def _cleartext_blocked(result: Dict[str, Any]) -> Optional[str]:
    """If the platform configuration prevents plaintext HTTP, return a short explanation."""
    meta, titles = result.get("meta", {}), _titles(result.get("findings", []))
    kind = result.get("detected_type")
    if kind == "ipa":
        loosened = any(t.startswith(("App Transport Security disabled globally",
                                     "Cleartext HTTP allowed for domain",
                                     "Capacitor cleartext traffic enabled",
                                     "Capacitor loads app content from a remote URL"))
                       for t in titles)
        if not loosened:
            return "App Transport Security is enabled with no cleartext exception, so iOS blocks these requests"
    elif kind in ("apk", "apks", "aab"):
        base = meta
        if kind == "apks":
            for sp in meta.get("splits", []):
                if sp.get("name") == meta.get("base_split"):
                    base = sp.get("meta", {})
        try:
            target = int(base.get("targetSdkVersion"))
        except (TypeError, ValueError):
            target = None
        allowed = any(t.startswith(("android:usesCleartextTraffic", "Cleartext traffic permitted for specific"))
                      for t in titles)
        if target is not None and target >= 28 and not allowed:
            return (f"targetSdkVersion={target} blocks cleartext traffic by default and no manifest or "
                    "network-security-config exception re-enables it")
    return None


_CLEARTEXT_TITLES = ("Cleartext (http://) URLs embedded in binary",
                     "Cleartext HTTP URL pointing at a raw public IP address")


# ---------------------------------------------------------------------- main API

def _fp(f: Dict[str, Any]) -> str:
    import hashlib
    basis = f"{f.get('title', '')}|{f.get('location', '')}"
    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()[:16]


_TEST_CLASS = re.compile(r"\[L[^;\]]*(/testing/|/test/|Test[A-Z][A-Za-z]*;|Tests;|/Test[A-Za-z]*;)")


def apply(result: Dict[str, Any], *, rules: Optional[List[IgnoreRule]] = None,
          min_severity: Optional[str] = None, min_confidence: Optional[str] = None,
          corroborate: bool = True) -> Dict[str, Any]:
    """Return `result` with findings triaged. Original findings stay available in
    result['triage'] so the process is always auditable."""
    rules = rules or []
    kept: List[Dict[str, Any]] = []
    demoted, dropped, ignored = [], [], []
    seen = set()

    blocked = _cleartext_blocked(result) if corroborate else None

    for f in result.get("findings", []):
        f = dict(f)
        f["fingerprint"] = _fp(f)

        # 1. explicit user rules always win
        hit = next((r for r in rules if r.matches(f)), None)
        if hit:
            ignored.append({"title": f["title"], "location": f.get("location"), "rule": f"{hit.kind}: {hit.pattern}",
                            "reason": hit.reason, "fingerprint": f["fingerprint"]})
            continue

        # 2. corroboration
        if blocked and f["title"] in _CLEARTEXT_TITLES and f["severity"] != "INFO":
            demoted.append({"title": f["title"], "from": f["severity"], "to": "INFO", "why": blocked})
            f["original_severity"] = f["severity"]
            f["severity"] = "INFO"
            f["detail"] += (f" Triage: demoted because {blocked}. It becomes relevant only if that "
                            "configuration is loosened, or the URL is opened outside the app's own network stack.")

        # 2b. split APKs: config splits carry only resources/ABI libs, never code, and
        #     repeat the base manifest's application-level findings.
        loc = f.get("location") or ""
        m = re.match(r"\[(split_config\.[^\]]+|config\.[^\]]+)\]\s*(.*)", loc)
        if m:
            if f["title"].startswith("No classes.dex"):
                dropped.append({"title": f["title"], "why": "config split has no code by design"})
                continue
            if "AndroidManifest.xml" in m.group(2):
                dropped.append({"title": f["title"], "why": "repeats base manifest finding"})
                continue

        # 2c. secrets that live in a library's own test fixtures are sample data, not the app's secrets
        if (f["severity"] in ("HIGH", "MEDIUM") and f["title"].startswith("Possible hardcoded secret")
                and _TEST_CLASS.search(loc)):
            demoted.append({"title": f["title"], "from": f["severity"], "to": "INFO",
                            "why": "found in a test-fixture class of a library"})
            f["original_severity"] = f["severity"]
            f["severity"] = "INFO"
            f["detail"] += " Triage: demoted because the string is referenced only from a test-fixture class."

        # 3. de-duplication
        key = (f["title"], f.get("location"), f.get("evidence"))
        if key in seen:
            dropped.append({"title": f["title"], "why": "duplicate"})
            continue
        seen.add(key)
        kept.append(f)

    # 4. thresholds (applied last, and recorded)
    def passes(f):
        if min_severity and _ORDER[f["severity"]] < _ORDER[min_severity]:
            return False
        if min_confidence and _CONF_ORDER.get(f.get("confidence", "heuristic"), 0) < _CONF_ORDER[min_confidence]:
            return False
        return True

    shown = [f for f in kept if passes(f)]
    below = [f for f in kept if not passes(f)]
    shown.sort(key=lambda f: -_ORDER[f["severity"]])

    out = dict(result)
    out["findings"] = shown
    out["summary"] = {s: sum(1 for f in shown if f["severity"] == s) for s in SEVERITIES}
    out["triage"] = {
        "demoted": demoted, "dropped": dropped, "ignored_by_rule": ignored,
        "hidden_by_threshold": [{"severity": f["severity"], "title": f["title"],
                                 "confidence": f.get("confidence")} for f in below],
        "min_severity": min_severity, "min_confidence": min_confidence,
    }
    out["suppressed_count"] = len(ignored) + len(below)
    return out
