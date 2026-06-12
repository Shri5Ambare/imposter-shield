"""Candidate discovery.

Finds *potential* impostors of a single protected identity. Scope discipline
matters here: we search for accounts impersonating the Source of Truth, not a
dragnet over unrelated people.

Preferred order:
  1. Official platform APIs / search endpoints (respect their ToS & rate limits).
  2. Search APIs (SerpApi, social-searcher) for handle permutations + name.
  3. Reverse-image search to find stolen profile photos.

Heavy/aggressive HTML scraping of authenticated or anti-bot-protected flows is
intentionally out of scope — it's brittle, often violates ToS, and isn't needed
to find public impersonation. Use the documented search surfaces.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field


@dataclass
class SourceOfTruth:
    name: str
    handles: dict           # {platform: handle}, e.g. {"instagram": "real_jane"}
    image_paths: list[str]
    canonical_bio: str
    image_phashes: list = field(default_factory=list)  # precomputed for fast match


@dataclass
class SuspectCandidate:
    platform: str
    url: str
    handle: str
    image_urls: list[str] = field(default_factory=list)
    bio: str = ""
    metadata: dict = field(default_factory=dict)
    discovered_via: str = ""


def handle_permutations(handle: str, *, max_out: int = 40) -> list[str]:
    """Common impersonation patterns: suffixes, separators, leet, doubled chars."""
    base = handle.lstrip("@")
    suffixes = ["", "_", ".", "official", "real", "_official", "1", "_backup", "hq", "team"]
    seps_variants = {base, base.replace("_", ""), base.replace(".", "")}
    leet = base.translate(str.maketrans({"o": "0", "i": "1", "l": "1", "e": "3", "a": "4"}))
    seps_variants.add(leet)

    out = set()
    for stem, suf in itertools.product(seps_variants, suffixes):
        out.add(f"{stem}{suf}")
        out.add(f"{suf}{stem}" if suf else stem)
    out.discard(base)  # the real handle is not a suspect
    return sorted(out)[:max_out]


def search_serpapi(query: str, api_key: str, *, platform_site: str | None = None) -> list[SuspectCandidate]:
    """Use SerpApi to find public profiles matching name/handle permutations."""
    from serpapi import GoogleSearch

    q = f'site:{platform_site} {query}' if platform_site else query
    search = GoogleSearch({"q": q, "api_key": api_key, "num": 20})
    results = search.get_dict().get("organic_results", [])
    out = []
    for r in results:
        link = r.get("link", "")
        if not link:
            continue
        out.append(SuspectCandidate(
            platform=platform_site or "web",
            url=link,
            handle=_handle_from_url(link),
            bio=r.get("snippet", ""),
            discovered_via=f"serpapi:{q}",
        ))
    return out


def reverse_image_search(image_path: str, api_key: str) -> list[SuspectCandidate]:
    """Find pages hosting a stolen profile photo (SerpApi Google Lens engine).

    In production you'd upload the image to object storage and pass its URL; this
    is the integration seam, kept thin on purpose."""
    from serpapi import GoogleSearch

    # Assumes image is reachable at a URL; replace with your storage URL.
    search = GoogleSearch({"engine": "google_lens", "url": image_path, "api_key": api_key})
    matches = search.get_dict().get("visual_matches", [])
    return [
        SuspectCandidate(
            platform="web", url=m.get("link", ""),
            handle=_handle_from_url(m.get("link", "")),
            image_urls=[m.get("thumbnail", "")],
            discovered_via="reverse_image",
        )
        for m in matches if m.get("link")
    ]


def _handle_from_url(url: str) -> str:
    from urllib.parse import urlparse
    path = urlparse(url).path.strip("/")
    return path.split("/")[0] if path else ""
