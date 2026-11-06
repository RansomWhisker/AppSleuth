"""Small, careful HTTP helper for the opt-in network checks.

* never follows redirects (App Links / AASA verification requires none, and a hostile app
  must not be able to bounce us to an internal address)
* refuses hosts that resolve to private / loopback / link-local addresses
* caps response size and time, identifies itself, and never sends credentials
* injectable (`fetch=`) so every caller is testable without a network
"""
from __future__ import annotations

import ipaddress
import re
import socket
import urllib.error
import urllib.request
from typing import Dict, Optional, Tuple

USER_AGENT = "appsleuth-security-check (+https://github.com/RansomWhisker/AppSleuth)"
MAX_BODY = 1 << 20
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

Response = Tuple[int, Dict[str, str], bytes]       # status, headers (lower-case), body (<= MAX_BODY)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def is_public_host(host: str) -> bool:
    """True if `host` is a syntactically valid DNS name that resolves only to public addresses."""
    if not HOST_RE.match(host) or host.lower().endswith((".local", ".internal", ".localhost", ".lan", ".home")):
        return False
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return False
    return bool(infos)


def fetch(url: str, method: str = "GET", body: Optional[bytes] = None, timeout: float = 10.0,
          headers: Optional[Dict[str, str]] = None) -> Response:
    """HTTP(S) request; returns (status, headers, body). Raises OSError on network failure."""
    if not url.startswith("https://"):
        raise OSError("only https:// URLs are fetched")
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"User-Agent": USER_AGENT, "Accept": "application/json, */*", **(headers or {})})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        try:
            data = e.read(MAX_BODY)
        except Exception:
            data = b""
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, data
    except (urllib.error.URLError, socket.timeout, ValueError) as e:
        raise OSError(str(e))
