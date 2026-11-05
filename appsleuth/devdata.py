"""Pull an app's private data container from a device you own (the "getdata" feature).

iOS      jailbroken device over SSH:  /var/mobile/Containers/Data/Application/<UUID>/
Android  over adb, by the first method that works:
           root     `su -c tar` (rooted device / emulator)
           run-as   debuggable apps only
           backup   `adb backup` for apps with allowBackup=true on Android <= 11

Hostile-device assumptions: every name/path coming back is validated, the tar stream is
unpacked file-by-file by us (no links, devices or traversal), and size/count caps apply.
"""
import atexit
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zlib
from typing import Any, Dict, List, Optional

USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._:\-]{0,252}$")
BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
SERIAL_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,64}$")
IOS_DATA_ROOTS = ("/var/mobile/Containers/Data/Application/", "/private/var/mobile/Containers/Data/Application/")

DEFAULT_MAX_BYTES = 2 << 30
DEFAULT_MAX_FILES = 200_000


class PullError(RuntimeError):
    pass


def clean(text: Any) -> str:
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", str(text))


def expand_host(text: str) -> str:
    """9 -> 192.168.1.9 ; 0.5 -> 192.168.0.5 ; anything else unchanged."""
    text = text.strip()
    if re.fullmatch(r"\d{1,3}", text):
        parts = ["1", text]
    elif re.fullmatch(r"\d{1,3}\.\d{1,3}", text):
        parts = text.split(".")
    else:
        return text
    if all(int(x) <= 255 for x in parts):
        return "192.168." + ".".join(str(int(x)) for x in parts)
    return text


# --------------------------------------------------------------- safe extraction

def safe_extract_tar(tar_path: str, dest: str, *, rename=None, max_files: int = DEFAULT_MAX_FILES,
                     max_bytes: int = DEFAULT_MAX_BYTES) -> Dict[str, Any]:
    """Unpack regular files and directories only. Returns {'modes': {rel: mode}, 'skipped': n, ...}.
    `rename(name) -> name|None` can remap or drop members (used for Android backups)."""
    os.makedirs(dest, exist_ok=True)
    root = os.path.realpath(dest)
    modes: Dict[str, int] = {}
    skipped = files = total = 0
    with tarfile.open(tar_path) as t:
        for m in t:
            name = m.name.lstrip("./") if m.name.startswith("./") else m.name
            if rename:
                name = rename(name)
                if name is None:
                    continue
            if not name or name == ".":
                continue
            if os.path.isabs(name) or ".." in name.split("/"):
                raise PullError(f"unsafe path in archive: {clean(m.name)!r}")
            target = os.path.realpath(os.path.join(root, name))
            if not target.startswith(root + os.sep):
                raise PullError(f"archive entry escapes the output directory: {clean(m.name)!r}")
            if m.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            if not m.isreg():
                skipped += 1
                continue
            files += 1
            total += m.size
            if files > max_files or total > max_bytes:
                raise PullError("data container exceeds the size/file-count limit "
                                f"({max_files} files / {max_bytes >> 20} MB); use --max-mb to raise it")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = t.extractfile(m)
            if src is None:
                continue
            with open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            os.chmod(target, 0o600)
            modes[name] = m.mode & 0o7777
    return {"modes": modes, "skipped_links_or_special": skipped, "files": files, "bytes": total}


# --------------------------------------------------------------------------- iOS

class SSH:
    """One authenticated connection (ControlMaster) reused for every command, so the
    password is entered once and there is no flood of failed logins."""

    def __init__(self, host: str, port: int = 22, user: str = "root", key: Optional[str] = None,
                 password: Optional[str] = None):
        if not USER_RE.match(user) or not HOST_RE.match(host):
            raise PullError("invalid username or host")
        if not 0 < port < 65536:
            raise PullError("invalid port")
        if key and not os.path.isfile(key):
            raise PullError(f"SSH key not found: {key}")
        self.host, self.port, self.user, self.key, self.password = host, port, user, key, password
        self.sock_dir = tempfile.mkdtemp(prefix="appsleuth-", dir="/tmp")      # mode 0700
        self.sock = os.path.join(self.sock_dir, "s")

    def _base(self) -> List[str]:
        b = ["ssh", "-p", str(self.port), "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR"]
        if self.key:
            b += ["-i", self.key, "-o", "IdentitiesOnly=yes"]
        return b

    def open(self):
        cmd = self._base() + ["-o", "ControlMaster=yes", "-o", f"ControlPath={self.sock}",
                              "-o", "ControlPersist=10m", "-o", "NumberOfPasswordPrompts=1",
                              f"{self.user}@{self.host}", "-fN"]
        env, askpass = None, None
        if self.password:
            fd, askpass = tempfile.mkstemp(prefix="appsleuth_askpass_")
            os.write(fd, b'#!/bin/sh\nprintf "%s\\n" "$APPSLEUTH_PW"\n')
            os.close(fd)
            os.chmod(askpass, 0o700)
            env = dict(os.environ, APPSLEUTH_PW=self.password, SSH_ASKPASS=askpass, SSH_ASKPASS_REQUIRE="force")
        try:
            rc = subprocess.run(cmd, env=env).returncode
        finally:
            if askpass:
                os.unlink(askpass)
        if rc != 0:
            self.close()
            raise PullError(f"SSH login to {self.user}@{self.host}:{self.port} failed "
                            "(wrong password? try --user mobile on rootless jailbreaks, or --key)")
        atexit.register(self.close)

    def close(self):
        if os.path.isdir(self.sock_dir):
            subprocess.run(["ssh", "-O", "exit", "-o", f"ControlPath={self.sock}", f"{self.user}@{self.host}"],
                           capture_output=True)
            shutil.rmtree(self.sock_dir, ignore_errors=True)

    def _cmd(self) -> List[str]:
        return self._base() + ["-o", "ControlMaster=no", "-o", f"ControlPath={self.sock}",
                               f"{self.user}@{self.host}"]

    def run(self, command: str, binary: bool = False, check: bool = True):
        p = subprocess.run(self._cmd() + [command], capture_output=True)
        if check and p.returncode != 0:
            raise PullError(f"remote command failed: {clean(p.stderr.decode(errors='replace').strip())}")
        return p.stdout if binary else p.stdout.decode(errors="replace")

    def stream_to_file(self, command: str, path: str, max_bytes: int):
        with open(path, "wb") as fh:
            p = subprocess.Popen(self._cmd() + [command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            total = 0
            try:
                for chunk in iter(lambda: p.stdout.read(1 << 20), b""):
                    total += len(chunk)
                    if total > max_bytes:
                        p.kill()
                        raise PullError(f"container is larger than {max_bytes >> 20} MB; use --max-mb")
                    fh.write(chunk)
            finally:
                err = p.stderr.read().decode(errors="replace")
                p.wait()
            if p.returncode != 0:
                raise PullError(f"tar failed on device: {clean(err.strip())}")


def ios_list_containers(ssh: SSH, include_system: bool = False) -> List[Dict[str, Any]]:
    import plistlib
    listing = ssh.run("ls -d /var/mobile/Containers/Data/Application/*/ 2>/dev/null", check=False)
    mtimes: Dict[str, int] = {}
    for fmt in ("stat -c '%Y\t%n'", "stat -f '%m\t%N'"):
        out = ssh.run(f"{fmt} /var/mobile/Containers/Data/Application/*/ 2>/dev/null", check=False)
        if out.strip():
            for line in out.splitlines():
                t, _, p = line.partition("\t")
                if t.isdigit():
                    mtimes[p.rstrip("/")] = int(t)
            break
    apps = []
    for d in filter(None, listing.splitlines()):
        d = d.strip().rstrip("/")
        if not d.startswith(IOS_DATA_ROOTS) or "\n" in d or ".." in d.split("/"):
            continue
        try:
            raw = ssh.run("cat " + shlex.quote(d + "/.com.apple.mobile_container_manager.metadata.plist"),
                          binary=True)
            bid = str(plistlib.loads(raw).get("MCMMetadataIdentifier", ""))
        except Exception:
            continue
        if not BUNDLE_RE.match(bid):
            continue
        if not include_system and bid.startswith("com.apple.") and bid != "com.apple.TestFlight":
            continue
        apps.append({"bundle_id": bid, "container": d, "mtime": mtimes.get(d, 0)})
    apps.sort(key=lambda a: a["mtime"], reverse=True)
    return apps


def ios_pull(ssh: SSH, app: Dict[str, Any], out_dir: str, max_bytes: int = DEFAULT_MAX_BYTES) -> Dict[str, Any]:
    work = tempfile.mkdtemp(prefix="appsleuth_pull_")
    try:
        tar_path = os.path.join(work, "data.tar")
        ssh.stream_to_file(f"cd {shlex.quote(app['container'])} && tar -cf - .", tar_path, max_bytes)
        manifest = safe_extract_tar(tar_path, out_dir, max_bytes=max_bytes)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    manifest.update({"platform": "ios", "bundle_id": app["bundle_id"], "method": "ssh", "pulled_at": int(time.time())})
    return manifest


# ----------------------------------------------------------------------- Android

def _adb(args: List[str], serial: Optional[str] = None, **kw):
    cmd = ["adb"] + (["-s", serial] if serial else []) + args
    return subprocess.run(cmd, **kw)


def android_devices() -> List[str]:
    if not shutil.which("adb"):
        raise PullError("adb not found (install Android platform-tools)")
    out = subprocess.run(["adb", "devices"], capture_output=True, text=True).stdout
    return [l.split("\t")[0] for l in out.splitlines()[1:] if l.strip().endswith("\tdevice")]


def android_list_packages(serial: Optional[str]) -> List[str]:
    out = _adb(["shell", "pm", "list", "packages", "-3"], serial, capture_output=True, text=True).stdout
    return sorted(l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("package:")
                  and PKG_RE.match(l.split(":", 1)[1].strip()))


def _android_tar(serial, remote_cmd: str, tar_path: str, max_bytes: int):
    with open(tar_path, "wb") as fh:
        p = subprocess.Popen(["adb"] + (["-s", serial] if serial else []) + ["exec-out", remote_cmd],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        total = 0
        for chunk in iter(lambda: p.stdout.read(1 << 20), b""):
            total += len(chunk)
            if total > max_bytes:
                p.kill()
                raise PullError(f"data is larger than {max_bytes >> 20} MB; use --max-mb")
            fh.write(chunk)
        err = p.stderr.read().decode(errors="replace")
        p.wait()
    if p.returncode != 0 or os.path.getsize(tar_path) < 512:
        raise PullError(clean(err.strip()) or "empty archive")


def _is_root(serial) -> bool:
    r = _adb(["shell", "su", "-c", "id"], serial, capture_output=True, text=True, timeout=15)
    return "uid=0" in (r.stdout or "")


_AB_DIRS = {"sp": "shared_prefs", "db": "databases", "f": "files", "c": "cache", "r": "root", "ef": "external_files"}


def _parse_backup(ab_path: str, tar_path: str, max_bytes: int):
    with open(ab_path, "rb") as fh:
        if fh.readline() != b"ANDROID BACKUP\n":
            raise PullError("not an Android backup file")
        fh.readline()                                   # version
        compressed = fh.readline().strip() == b"1"
        if fh.readline().strip() != b"none":
            raise PullError("encrypted backups are not supported (set no backup password)")
        d = zlib.decompressobj() if compressed else None
        total = 0
        with open(tar_path, "wb") as out:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                data = d.decompress(chunk) if d else chunk
                total += len(data)
                if total > max_bytes:
                    raise PullError("backup expands beyond the size limit")
                out.write(data)


def android_pull(serial: Optional[str], pkg: str, out_dir: str, method: str = "auto",
                 max_bytes: int = DEFAULT_MAX_BYTES, log=print) -> Dict[str, Any]:
    if not PKG_RE.match(pkg):
        raise PullError("invalid package name")
    if serial and not SERIAL_RE.match(serial):
        raise PullError("invalid device serial")
    work = tempfile.mkdtemp(prefix="appsleuth_pull_")
    tar_path = os.path.join(work, "data.tar")
    errors, used = [], None
    try:
        order = ["root", "run-as", "backup"] if method == "auto" else [method]
        for m in order:
            try:
                if m == "root":
                    if not _is_root(serial):
                        raise PullError("device is not rooted (su not available)")
                    _android_tar(serial, f"su -c 'tar -cf - -C /data/data/{pkg} .'", tar_path, max_bytes)
                    rename = None
                elif m == "run-as":
                    _android_tar(serial, f"run-as {pkg} tar -cf - .", tar_path, max_bytes)
                    rename = None
                elif m == "backup":
                    log("[*] Confirm the backup on the device screen (leave the password empty)...")
                    ab = os.path.join(work, "app.ab")
                    _adb(["backup", "-f", ab, "-noapk", pkg], serial, timeout=180, capture_output=True)
                    if not os.path.isfile(ab) or os.path.getsize(ab) < 64:
                        raise PullError("backup produced no data (app disallows backup, or Android >= 12)")
                    _parse_backup(ab, tar_path, max_bytes)
                    prefix = f"apps/{pkg}/"

                    def rename(name, prefix=prefix):
                        if not name.startswith(prefix):
                            return None
                        rest = name[len(prefix):]
                        top, _, tail = rest.partition("/")
                        return f"{_AB_DIRS.get(top, top)}/{tail}".rstrip("/") if rest else None
                else:
                    raise PullError(f"unknown method {m}")
                used = m
                manifest = safe_extract_tar(tar_path, out_dir, rename=rename, max_bytes=max_bytes)
                break
            except (PullError, subprocess.TimeoutExpired, tarfile.TarError, zlib.error, OSError) as e:
                errors.append(f"{m}: {clean(e)}")
                if os.path.exists(tar_path):
                    os.unlink(tar_path)
        else:
            raise PullError(
                "could not read the app's data:\n  - " + "\n  - ".join(errors) +
                "\nAndroid blocks access to a non-debuggable app's private data unless the device is rooted "
                "(or an emulator/AVD without Play Store). Test builds can use run-as.")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    manifest.update({"platform": "android", "package": pkg, "method": used, "pulled_at": int(time.time())})
    return manifest
