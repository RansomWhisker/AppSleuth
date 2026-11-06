"""Unpack an IPA / APK / APKS-XAPK / AAB once, safely, and expose what the intel features
(sbom, endpoints, links, cloud) need: the file tree, platform identity and parsed manifest."""
from __future__ import annotations

import contextlib
import os
import plistlib
import re
import shutil
import tempfile
import zipfile
from typing import Any, Dict, Iterator, List, Optional

from . import engine


class App:
    def __init__(self, path: str, kind: str, workdir: str):
        self.path = path
        self.kind = kind                      # apk | apks | aab | ipa
        self.platform = "ios" if kind == "ipa" else "android"
        self.workdir = workdir
        self.roots: List[str] = []            # unpacked directories (one per APK / the IPA)
        self.main_root: Optional[str] = None  # base APK dir, or the .app dir for iOS
        self.manifest = None                  # engine.ManifestNode (Android) or None
        self.info_plist: Dict[str, Any] = {}  # iOS Info.plist
        self.package: Optional[str] = None    # Android package / iOS bundle id
        self.main_apk_bytes: Optional[bytes] = None

    def files(self, roots: Optional[List[str]] = None) -> Iterator[str]:
        """Every regular file (symlinks ignored) under the unpacked roots."""
        for root in roots or self.roots:
            for d, _dirs, names in os.walk(root, followlinks=False):
                for n in names:
                    p = os.path.join(d, n)
                    if os.path.isfile(p) and not os.path.islink(p):
                        yield p

    def rel(self, full: str) -> str:
        for root in self.roots:
            if full.startswith(root + os.sep):
                label = os.path.relpath(full, root).replace(os.sep, "/")
                return label if len(self.roots) == 1 else f"{os.path.basename(root)}:{label}"
        return full


def _unzip(src: str, dest: str):
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(src) as z:
        engine._safe_extractall(z, dest)


def _load_manifest(root: str):
    p = os.path.join(root, "AndroidManifest.xml")
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "rb") as fh:
            return engine.build_manifest_tree(fh.read())
    except Exception:
        return None


@contextlib.contextmanager
def unpacked(path: str) -> Iterator[App]:
    if not os.path.isfile(path):
        raise ValueError(f"file not found: {path}")
    kind = engine.detect_kind(path)
    if kind not in ("apk", "apks", "aab", "ipa"):
        raise ValueError(f"Could not recognise '{path}' as an APK, APKS/XAPK, AAB or IPA file.")
    work = tempfile.mkdtemp(prefix="appsleuth_")
    try:
        app = App(path, kind, work)
        if kind == "ipa":
            root = os.path.join(work, "ipa")
            _unzip(path, root)
            app.roots = [root]
            apps = [os.path.join(root, "Payload", d) for d in sorted(os.listdir(os.path.join(root, "Payload")))
                    if d.endswith(".app")] if os.path.isdir(os.path.join(root, "Payload")) else []
            if apps:
                app.main_root = apps[0]
                try:
                    with open(os.path.join(apps[0], "Info.plist"), "rb") as fh:
                        app.info_plist = plistlib.load(fh)
                except Exception:
                    app.info_plist = {}
                app.package = app.info_plist.get("CFBundleIdentifier")
        elif kind == "apk":
            root = os.path.join(work, "apk")
            _unzip(path, root)
            app.roots = [root]
            app.main_root = root
            app.manifest = _load_manifest(root)
        elif kind == "aab":
            root = os.path.join(work, "aab")
            _unzip(path, root)
            app.roots = [root]
            app.main_root = os.path.join(root, "base")      # proto manifest: not parsed
        else:  # apks / xapk
            outer = os.path.join(work, "container")
            _unzip(path, outer)
            apks = sorted(os.path.join(d, f) for d, _x, fs in os.walk(outer) for f in fs if f.endswith(".apk"))
            best = None
            for i, apk in enumerate(apks):
                dest = os.path.join(work, f"split{i}_" + re.sub(r"\W+", "_", os.path.basename(apk)))
                _unzip(apk, dest)
                app.roots.append(dest)
                tree = _load_manifest(dest)
                if tree is not None and not tree.get("split") and best is None:
                    best, app.manifest, app.main_root = dest, tree, dest
                    with open(apk, "rb") as fh:
                        app.main_apk_bytes = fh.read()
            if best is None and app.roots:
                app.main_root = app.roots[0]
                app.manifest = _load_manifest(app.roots[0])
        if kind in ("apk", "apks"):
            if app.manifest is not None:
                app.package = app.manifest.get("package")
            if kind == "apk":
                with open(path, "rb") as fh:
                    app.main_apk_bytes = fh.read()
        yield app
    finally:
        shutil.rmtree(work, ignore_errors=True)


def new_result(app: App, kind: str, findings: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
    """Wrap findings in the scan-style result dict used by triage / reports."""
    meta = dict(meta, package=app.package, platform=app.platform)
    return {
        "input_file": os.path.abspath(app.path), "detected_type": kind, "meta": meta,
        "findings": findings,
        "summary": {s: sum(1 for f in findings if f["severity"] == s) for s in ("HIGH", "MEDIUM", "LOW", "INFO")},
    }


def finding(sev: str, title: str, detail: str, evidence: Optional[str] = None, location: Optional[str] = None,
            confidence: str = "heuristic") -> Dict[str, Any]:
    return {"severity": sev, "title": title, "detail": detail, "evidence": evidence,
            "location": location, "confidence": confidence}
