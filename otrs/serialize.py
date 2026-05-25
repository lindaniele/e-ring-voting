"""
Canonical wire encoding for OTRS objects.

We keep encoding/decoding in one place so the security-critical hash inputs
(H0, H1, H2 transcripts) are derived from a single canonical byte layout. All
length prefixes are 4-byte big-endian.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence

from otrs.group import POINT_BYTES, SCALAR_BYTES, Point, Scalar

LENGTH_PREFIX_BYTES = 4
MAX_RING_SIZE = 65535  # generous; the scheme itself has no protocol-level cap


def _u32(n: int) -> bytes:
    if n < 0 or n >> 32:
        raise ValueError(f"u32 out of range: {n}")
    return n.to_bytes(LENGTH_PREFIX_BYTES, "big")


def encode_ring(ring: Sequence[Point]) -> bytes:
    """Canonical encoding of an ordered ring of public keys."""
    if len(ring) > MAX_RING_SIZE:
        raise ValueError(f"ring too large (max {MAX_RING_SIZE})")
    parts = [_u32(len(ring))]
    parts.extend(pk.raw for pk in ring)
    return b"".join(parts)


def encode_points(points: Iterable[Point]) -> bytes:
    """Concatenate point encodings without a length prefix (caller-known length)."""
    return b"".join(p.raw for p in points)


def encode_signature(A1: Point, cN: Sequence[Scalar], zN: Sequence[Scalar]) -> bytes:
    """Serialize a signature: A1 || n || c_1..c_n || z_1..z_n."""
    if len(cN) != len(zN):
        raise ValueError("c and z arrays must have equal length")
    n = len(cN)
    parts = [A1.raw, _u32(n)]
    parts.extend(c.raw for c in cN)
    parts.extend(z.raw for z in zN)
    return b"".join(parts)


def decode_signature(blob: bytes) -> tuple[Point, List[Scalar], List[Scalar]]:
    """Parse a signature blob. Raises ValueError on malformed input."""
    if len(blob) < POINT_BYTES + LENGTH_PREFIX_BYTES:
        raise ValueError("signature blob too short")
    off = 0
    A1 = Point(blob[off : off + POINT_BYTES])
    off += POINT_BYTES
    n = int.from_bytes(blob[off : off + LENGTH_PREFIX_BYTES], "big")
    off += LENGTH_PREFIX_BYTES
    if n == 0 or n > MAX_RING_SIZE:
        raise ValueError(f"invalid ring size in signature: {n}")
    expected = POINT_BYTES + LENGTH_PREFIX_BYTES + 2 * n * SCALAR_BYTES
    if len(blob) != expected:
        raise ValueError(
            f"signature blob length mismatch: got {len(blob)}, expected {expected}"
        )
    cN = []
    for _ in range(n):
        cN.append(Scalar(blob[off : off + SCALAR_BYTES]))
        off += SCALAR_BYTES
    zN = []
    for _ in range(n):
        zN.append(Scalar(blob[off : off + SCALAR_BYTES]))
        off += SCALAR_BYTES
    return A1, cN, zN
