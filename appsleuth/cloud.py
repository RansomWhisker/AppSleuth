"""Cloud backend discovery (Firebase, S3, GCS, Azure Blob) and opt-in exposure checks.

Offline: find the backends the app is configured for (google-services values, GoogleService-
Info.plist, URLs in code and assets).

Online (`--check`, explicit opt-in): ask each discovered backend, *unauthenticated and read-only*,
whether it answers a list/read request. Only the HTTP status and a yes/no are recorded;
response bodies are never stored or printed, nothing is ever written, and every target is
validated against a strict allow-list of cloud hostnames before a request is made, so a
hostile app cannot point this tool at an arbitrary or internal address.

Run the online checks only against apps you are authorised to test: you are sending requests
to the vendor's cloud resources.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import appfiles, engine, endpoints, netfetch

MAX_REQUESTS = 30
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,62}$")
PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,29}$")
RTDB_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}(?:-default-rtdb)?\.(?:firebaseio\.com|(?:[a-z0-9-]+\.)?firebasedatabase\.app)$")
S3_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")                  # no dots: virtual-hosted TLS needs it
PATTERNS = [
    ("rtdb", re.compile(rb"https://([a-z0-9][a-z0-9-]{2,62}(?:-default-rtdb)?\.(?:firebaseio\.com|(?:[a-z0-9-]+\.)?firebasedatabase\.app))")),
    ("gcs", re.compile(rb"firebasestorage\.googleapis\.com/v0/b/([a-z0-9][a-z0-9._-]{2,62})")),
    ("gcs", re.compile(rb"gs://([a-z0-9][a-z0-9._-]{2,62})")),
    ("gcs", re.compile(rb"\bstorage\.googleapis\.com/(?!storage/|v1/|upload/|download/|batch)([a-z0-9][a-z0-9._-]{2,62})[/\"'\s]")),
    ("s3", re.compile(rb"https?://([a-z0-9][a-z0-9.-]{2,62})\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com")),
    ("s3", re.compile(rb"https?://s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.-]{2,62})")),
    ("s3", re.compile(rb"\bs3://([a-z0-9][a-z0-9.-]{2,62})")),
    ("azure", re.compile(rb"https://([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-z0-9-]{3,63})")),
]
_PLACEHOLDER = re.compile(r"(?i)(example|your[-_]?|my[-_]?bucket|bucket[-_]?name|placeholder|test[-_]?bucket|xxxx|\{|\$)")
_FB_KEYS = {"project_id": "project_id", "firebase_database_url": "database_url", "google_storage_bucket": "storage_bucket",
            "google_app_id": "app_id", "gcm_defaultSenderId": "sender_id", "google_api_key": "api_key",
            "default_web_client_id": "web_client_id"}
_PLIST_KEYS = {"PROJECT_ID": "project_id", "DATABASE_URL": "database_url", "STORAGE_BUCKET": "storage_bucket",
               "GOOGLE_APP_ID": "app_id", "GCM_SENDER_ID": "sender_id", "API_KEY": "api_key", "CLIENT_ID": "web_client_id"}


def _commented_out(blob: bytes, pos: int) -> bool:
    """True if the match sits on a line that starts with a comment marker (`//`, `#`, `*`)."""
    start = blob.rfind(b"\n", max(0, pos - 400), pos) + 1
    return blob[start:pos].lstrip()[:2] in (b"//", b"* ", b"/*") or blob[start:pos].lstrip()[:1] == b"#"


def firebase_config(app: appfiles.App) -> Dict[str, str]:
    cfg: Dict[str, str] = {}
    if app.platform == "android":
        for root in app.roots:
            table = engine.parse_resources_arsc(root)
            if table:
                strings = table.string_entries_by_key()
                for k, name in _FB_KEYS.items():
                    if strings.get(k) and name not in cfg:
                        cfg[name] = str(strings[k])
    elif app.main_root:
        p = os.path.join(app.main_root, "GoogleService-Info.plist")
        if os.path.isfile(p):
            try:
                with open(p, "rb") as fh:
                    d = plistlib.load(fh)
                for k, name in _PLIST_KEYS.items():
                    if d.get(k):
                        cfg[name] = str(d[k])
            except Exception:
                pass
    return cfg


def discover(app: appfiles.App) -> Dict[str, Any]:
    cfg = firebase_config(app)
    found: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add(kind: str, name: str, source: str, extra: Optional[str] = None):
        key = (kind, name)
        if key not in found and not _PLACEHOLDER.search(name):
            found[key] = {"kind": kind, "name": name, "source": source, **({"container": extra} if extra else {})}

    if cfg.get("database_url"):
        host = re.sub(r"^https?://", "", cfg["database_url"]).strip("/").lower()
        add("rtdb", host, "app config")
    if cfg.get("storage_bucket"):
        add("gcs", cfg["storage_bucket"].replace("gs://", "").lower(), "app config")
    for full in app.files():
        ext = os.path.splitext(full)[1].lower()
        if ext in endpoints.SKIP_EXT or ext == ".map":          # source maps repeat code and comments
            continue
        try:
            if os.path.getsize(full) > endpoints.MAX_FILE:
                continue
            with open(full, "rb") as fh:
                blob = fh.read()
        except OSError:
            continue
        if b"://" not in blob and b"googleapis.com/" not in blob:     # bucket hosts can appear without a scheme
            continue
        if blob[:4] == b"dex\n":
            blob = endpoints.dex_string_blob(blob)                # one string per line: no length-byte artefacts
        label = app.rel(full)
        for kind, rx in PATTERNS:
            for m in rx.finditer(blob):
                name = m.group(1).decode("ascii", "ignore").lower()
                if kind in ("s3", "gcs") and len(name) < 5:
                    continue                                     # `s3://doc`-style noise
                if _commented_out(blob, m.start()):
                    continue
                add(kind, name, label, m.group(2).decode() if kind == "azure" else None)
    project = cfg.get("project_id")
    return {"config": cfg, "backends": sorted(found.values(), key=lambda b: (b["kind"], b["name"])), "project_id": project}


def _mask(v: str) -> str:
    return v[:3] + "…" + v[-4:] if len(v) > 10 else "…"


def discovery_findings(d: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    cfg = d["config"]
    if cfg:
        shown = {k: (_mask(v) if k in ("api_key", "web_client_id", "app_id") else v) for k, v in cfg.items()}
        out.append(appfiles.finding(
            "INFO", "Firebase project configuration present",
            "These values ship in every client by design; security depends on server-side rules and API key "
            "restrictions, not on hiding them. Use `appsleuth cloud --check` to test the rules (opt-in).",
            evidence=", ".join(f"{k}={v}" for k, v in sorted(shown.items())), confidence="confirmed"))
    kinds = {"rtdb": "Firebase Realtime Database", "gcs": "Cloud Storage bucket", "s3": "Amazon S3 bucket",
             "azure": "Azure Blob storage account"}
    for kind, label in kinds.items():
        items = [b["name"] + (f"/{b['container']}" if b.get("container") else "") for b in d["backends"] if b["kind"] == kind]
        if items:
            out.append(appfiles.finding(
                "INFO", f"{len(items)} {label}(s) referenced", "Backends found in the app's code, assets or config.",
                evidence=", ".join(items[:8]) + (" ..." if len(items) > 8 else "")))
    return out


# ------------------------------------------------------------------------------ live checks

def _valid(kind: str, name: str) -> bool:
    if kind == "rtdb":
        return bool(RTDB_RE.match(name))
    if kind == "gcs":
        return bool(BUCKET_RE.match(name))
    if kind == "s3":
        return bool(S3_LABEL_RE.match(name))
    return False


def _body_has(body: bytes, *needles: bytes) -> bool:
    return any(n in body[:4096] for n in needles)


_GENERIC = {"com", "org", "net", "android", "app", "apps", "mobile", "prod", "release", "debug", "main", "the", "ios"}


def owner_tokens(package: Optional[str], project: Optional[str]) -> Set[str]:
    toks: Set[str] = set()
    for src in (package or "", project or ""):
        for t in re.split(r"[^a-z0-9]+", src.lower()):
            if len(t) >= 4 and t not in _GENERIC:
                toks.add(t)
    return toks


def _owned(name: str, tokens: Set[str]) -> bool:
    return any(t in name for t in tokens)


_RESERVED_BUCKET = (".appspot.com", ".firebasestorage.app")


def check_backend(b: Dict[str, Any], fetch: Callable, tokens: Optional[Set[str]] = None) -> Optional[Dict[str, Any]]:
    tokens = tokens or set()
    kind, name = b["kind"], b["name"]
    if not _valid(kind, name):
        return None
    where = f"{kind}:{name}"
    if kind == "rtdb":
        st, _h, body = fetch(f"https://{name}/.json?shallow=true", "GET")
        if st == 200:
            empty = body.strip() in (b"null", b"")
            return appfiles.finding(
                "HIGH" if not empty else "MEDIUM", "Firebase Realtime Database readable without authentication",
                "An unauthenticated request to the database root succeeded. Anyone can read "
                + ("the data" if not empty else "whatever is stored here (it is empty right now, but rules allow reads)")
                + ". Fix the security rules (`.read: false` by default). Response content was not stored.",
                evidence=f"{name}: HTTP 200" + (" (empty)" if empty else ""), location=where, confidence="confirmed")
        if st in (401, 403):
            return appfiles.finding("INFO", "Firebase Realtime Database denies anonymous reads",
                                    "Rules reject unauthenticated access to the root.", evidence=f"{name}: HTTP {st}",
                                    location=where, confidence="confirmed")
        if st in (404, 423):
            return appfiles.finding("INFO", "Firebase Realtime Database not active",
                                    "The instance does not exist or is deactivated.", evidence=f"{name}: HTTP {st}",
                                    location=where, confidence="confirmed")
        return appfiles.finding("INFO", "Firebase Realtime Database check inconclusive", f"Unexpected HTTP {st}.",
                                evidence=name, location=where)
    if kind == "gcs":
        st, _h, body = fetch(f"https://firebasestorage.googleapis.com/v0/b/{name}/o?maxResults=1", "GET")
        if st == 200:
            has = b'"items"' in body[:4096] or b'"prefixes"' in body[:4096]
            mine = _owned(name, tokens) or name.endswith(_RESERVED_BUCKET)
            return appfiles.finding(
                "HIGH" if has and mine else "MEDIUM", "Cloud Storage bucket listable without authentication",
                "An unauthenticated request listed objects in the bucket. Restrict `allow list`/`allow read` in the "
                "Storage rules. Object names were not stored."
                + ("" if mine else " The bucket name does not match this app, so it may belong to a third-party "
                   "SDK or CDN where public content is intentional; confirm who owns it."),
                evidence=f"{name}: HTTP 200" + ("" if has else " (no objects)"), location=where, confidence="confirmed")
        if st in (401, 403):
            return appfiles.finding("INFO", "Cloud Storage bucket denies anonymous listing", "Rules reject it.",
                                    evidence=f"{name}: HTTP {st}", location=where, confidence="confirmed")
        if st in (400, 404):
            if name.endswith(_RESERVED_BUCKET):
                return appfiles.finding(
                    "INFO", "Default Firebase Storage bucket not provisioned",
                    "Cloud Storage was never enabled for this project (or the bucket was removed). Names under "
                    "appspot.com / firebasestorage.app are reserved to the project owner, so this is not a takeover risk.",
                    evidence=f"{name}: HTTP {st}", location=where, confidence="confirmed")
            return appfiles.finding(
                "LOW" if _body_has(body, b"does not exist", b"Not Found", b"notFound") else "INFO",
                "Referenced Cloud Storage bucket not found",
                "Bucket names are global. If the app really uses this bucket and it was deleted, anyone can "
                "re-create it and serve the app's files (takeover). The name may also just be a string, so verify.",
                evidence=f"{name}: HTTP {st}", location=where, confidence="heuristic")
        return None
    if kind == "s3":
        st, _h, body = fetch(f"https://{name}.s3.amazonaws.com/?max-keys=1", "GET")
        if st == 200 and _body_has(body, b"<ListBucketResult"):
            mine = _owned(name, tokens)
            return appfiles.finding(
                "HIGH" if mine else "MEDIUM", "S3 bucket listable without authentication",
                "An unauthenticated request listed the bucket. Block public access and remove public ACL/policy "
                "grants. Object names were not stored."
                + ("" if mine else " The bucket name does not match this app, so it may belong to a third-party "
                   "SDK, ad network or CDN where public content is intentional; confirm who owns it."),
                evidence=f"{name}: HTTP 200", location=where, confidence="confirmed")
        if st == 404 and _body_has(body, b"NoSuchBucket"):
            return appfiles.finding(
                "MEDIUM", "Referenced S3 bucket does not exist (takeover risk)",
                "The app references a bucket name nobody owns. If this reference is live code, anyone can create "
                "the bucket and serve content to the app. (Commented-out code and source maps are skipped.)",
                evidence=f"{name}: NoSuchBucket", location=where, confidence="confirmed")
        if st in (403, 200, 301, 307):
            return appfiles.finding("INFO", "S3 bucket exists and is not publicly listable", "",
                                    evidence=f"{name}: HTTP {st}", location=where, confidence="confirmed")
        return None
    return None


def check_firestore(project: str, fetch: Callable) -> Optional[Dict[str, Any]]:
    if not PROJECT_RE.match(project or ""):
        return None
    st, _h, body = fetch(f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents:listCollectionIds",
                         "POST", b'{"pageSize":1}', headers={"Content-Type": "application/json"})
    where = f"firestore:{project}"
    if st == 200:
        return appfiles.finding(
            "HIGH", "Firestore readable without authentication",
            "An unauthenticated request listed collection ids. Tighten the Firestore security rules. "
            "Collection names were not stored.", evidence=f"{project}: HTTP 200", location=where, confidence="confirmed")
    if st in (401, 403):
        return appfiles.finding("INFO", "Firestore denies anonymous access", "Rules reject unauthenticated reads.",
                                evidence=f"{project}: HTTP {st}", location=where, confidence="confirmed")
    return None


def run(path: str, *, check: bool = False, fetch: Callable = netfetch.fetch) -> Dict[str, Any]:
    with appfiles.unpacked(path) as app:
        d = discover(app)
        findings = discovery_findings(d)
        meta: Dict[str, Any] = {"config": {k: (_mask(v) if k in ("api_key", "web_client_id", "app_id") else v)
                                           for k, v in d["config"].items()},
                                "backends": d["backends"], "checked": check, "requests": 0}
        if check:
            tokens = owner_tokens(app.package, d["project_id"])
            budget = MAX_REQUESTS
            targets = [b for b in d["backends"] if b["kind"] in ("rtdb", "gcs", "s3")]
            for b in targets:
                if budget <= 0:
                    findings.append(appfiles.finding("INFO", "Request budget reached",
                                                     f"Stopped after {MAX_REQUESTS} requests."))
                    break
                budget -= 1
                try:
                    f = check_backend(b, fetch, tokens)
                except OSError as e:
                    f = appfiles.finding("INFO", f"Could not reach {b['kind']}:{b['name']}", str(e)[:150])
                if f:
                    findings.append(f)
            if d["project_id"] and budget > 0:
                budget -= 1
                try:
                    f = check_firestore(d["project_id"], fetch)
                except OSError as e:
                    f = appfiles.finding("INFO", "Could not reach Firestore", str(e)[:150])
                if f:
                    findings.append(f)
            meta["requests"] = MAX_REQUESTS - budget
        else:
            if d["backends"] or d["config"]:
                findings.append(appfiles.finding(
                    "INFO", "Backend exposure not tested",
                    "Run with --check to ask each backend, read-only and unauthenticated, whether it is open. "
                    "Only do this for apps you are authorised to test."))
        return appfiles.new_result(app, "cloud", findings, meta)
