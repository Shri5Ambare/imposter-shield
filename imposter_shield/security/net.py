"""SSRF-safe URL validation.

Used wherever a user-supplied URL is later fetched server-side (suspect profile
URLs, evidence URLs, and worker image downloads). Blocks:
  - non-http(s) schemes (file://, gopher://, data:, etc.)
  - hostnames that resolve to loopback / private / link-local / reserved IPs
    (defeats `http://localhost:5432`, `http://169.254.169.254/` metadata, etc.)

Resolution is done with getaddrinfo so DNS names that point at internal ranges
are also caught — not just literal IPs.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from ..config import settings


class UnsafeURLError(ValueError):
    """Raised when a URL is not safe to fetch (bad scheme or private target)."""


_ALLOWED_SCHEMES = {"http", "https"}


def _ip_is_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def validate_public_url(raw: str) -> str:
    """Return the URL unchanged if safe to fetch; raise UnsafeURLError otherwise."""
    if settings.allow_private_network_urls:
        return raw  # explicit test/dev opt-out

    parsed = urlparse(raw)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeURLError(f"scheme '{parsed.scheme}' not allowed (http/https only)")
    host = parsed.hostname
    if not host:
        raise UnsafeURLError("URL has no host")

    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"could not resolve host '{host}': {exc}") from exc

    for info in infos:
        ip = info[4][0]            # sockaddr is the 5th element; its first item is the IP
        if _ip_is_blocked(ip):
            raise UnsafeURLError(f"host '{host}' resolves to blocked address {ip}")
    return raw


def is_public_url(raw: str) -> bool:
    try:
        validate_public_url(raw)
        return True
    except UnsafeURLError:
        return False
