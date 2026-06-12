"""Image provenance: perceptual hashing + an optional invisible watermark.

Two independent ways to tell "this is my stolen photo":

1. **Perceptual hash (pHash)** — works on photos you posted *before* deploying
   this tool. We store the pHash of every Source-of-Truth image; a suspect image
   within a small Hamming distance is the same picture (even resized/recompressed).

2. **Invisible watermark (honeypot)** — for photos the user runs through this tool
   *before* posting. We embed a secret bit pattern in the image. Finding that
   pattern on an account proves the pixels came from the user. This is a
   demonstration using LSB steganography; for production use a frequency-domain
   (DCT/DWT) scheme that survives recompression — e.g. the `invisible-watermark`
   library.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np


# --------------------------- perceptual hash -------------------------------- #

@dataclass
class HashMatch:
    is_match: bool
    distance: int
    threshold: int


def phash(image_path: str):
    import imagehash
    from PIL import Image
    return imagehash.phash(Image.open(image_path))


def compare_phash(truth_hash, suspect_image_path: str, threshold: int = 8) -> HashMatch:
    """Hamming distance between a stored truth hash and a suspect image.
    ≤ threshold ⇒ same image. 8/64 bits is a conservative, low-false-positive cut."""
    d = truth_hash - phash(suspect_image_path)
    return HashMatch(is_match=d <= threshold, distance=int(d), threshold=threshold)


# ------------------------- invisible watermark ------------------------------ #
# Demonstration LSB scheme. Embeds a fixed-length secret tag in the blue channel.

_MAGIC = b"ISHLD\x00"   # marker so we can recognise our own payload


def embed_watermark(image_path: str, out_path: str, secret: bytes) -> str:
    """Embed ``_MAGIC + secret`` (padded to 32 bytes) into image LSBs."""
    from PIL import Image

    payload = _MAGIC + secret
    if len(payload) > 32:
        raise ValueError("secret too long (max 26 bytes)")
    payload = payload.ljust(32, b"\x00")
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))

    img = Image.open(image_path).convert("RGB")
    arr = np.array(img)
    flat = arr[:, :, 2].reshape(-1)  # blue channel
    if bits.size > flat.size:
        raise ValueError("image too small to hold watermark")
    flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits
    arr[:, :, 2] = flat.reshape(arr[:, :, 2].shape)
    Image.fromarray(arr).save(out_path)
    return out_path


def extract_watermark(image_path: str) -> bytes | None:
    """Return the embedded secret if our magic marker is present, else None."""
    from PIL import Image

    arr = np.array(Image.open(image_path).convert("RGB"))
    flat = arr[:, :, 2].reshape(-1)[: 32 * 8]
    payload = np.packbits(flat & 1).tobytes()
    if not payload.startswith(_MAGIC):
        return None
    return payload[len(_MAGIC):].rstrip(b"\x00")
