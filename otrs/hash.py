"""
RFC 9380 hash-to-curve and hash-to-scalar for Ristretto255.

Suite: ``ristretto255_XMD:SHA-512_R255MAP_RO_``.

``expand_message_xmd`` (RFC 9380 §5.3.1) is implemented from scratch — it's a
small, well-specified primitive — and composed with libsodium's
``crypto_core_ristretto255_from_hash`` to obtain the random-oracle variant of
the suite. Hash-to-scalar uses the same XMD expander followed by
``scalar_reduce`` (uniform over Z_q within 2^-256 statistical distance).

Domain-separation tags (DSTs) are caller-supplied — never reuse a DST across
unrelated protocols.
"""

from __future__ import annotations

import hashlib
from typing import Final

from otrs.group import Point, Scalar

SHA512_BLOCK: Final[int] = 128
SHA512_OUT: Final[int] = 64


def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    """
    RFC 9380 §5.3.1, expand_message_xmd with SHA-512.

    Produces ``len_in_bytes`` pseudorandom bytes from ``msg`` under the
    domain-separation tag ``dst``. If ``dst`` is longer than 255 bytes the
    spec mandates hashing it first under the prefix ``H2C-OVERSIZE-DST-``
    (§5.3.3); we implement that path too.
    """
    b_in_bytes = SHA512_OUT
    if len_in_bytes <= 0 or len_in_bytes > 65535:
        raise ValueError("len_in_bytes out of range")
    if len(dst) > 255:
        long_prefix = b"H2C-OVERSIZE-DST-"
        dst = hashlib.sha512(long_prefix + dst).digest()
    ell = (len_in_bytes + b_in_bytes - 1) // b_in_bytes
    if ell > 255:
        raise ValueError("expand_message_xmd: too many blocks requested")

    dst_prime = dst + len(dst).to_bytes(1, "big")
    z_pad = b"\x00" * SHA512_BLOCK
    l_i_b_str = len_in_bytes.to_bytes(2, "big")
    msg_prime = z_pad + msg + l_i_b_str + b"\x00" + dst_prime

    b0 = hashlib.sha512(msg_prime).digest()
    b1 = hashlib.sha512(b0 + b"\x01" + dst_prime).digest()
    out = bytearray(b1)
    bi_prev = b1
    for i in range(2, ell + 1):
        xored = bytes(a ^ b for a, b in zip(b0, bi_prev))
        bi = hashlib.sha512(xored + i.to_bytes(1, "big") + dst_prime).digest()
        out.extend(bi)
        bi_prev = bi
    return bytes(out[:len_in_bytes])


def hash_to_group(msg: bytes, dst: bytes) -> Point:
    """
    RFC 9380 hash_to_curve for ristretto255 (RO variant).

    The map composes 64 uniform bytes from ``expand_message_xmd`` with
    libsodium's ``ristretto255_from_hash``. The output distribution is within
    2^-126 of uniform on the prime-order group.
    """
    uniform = expand_message_xmd(msg, dst, 64)
    return Point.from_uniform_64(uniform)


def hash_to_scalar(msg: bytes, dst: bytes) -> Scalar:
    """
    Hash-to-scalar mod q (RFC 9380 §5.2 idiom).

    Uses XMD-SHA-512 to produce 64 bytes, then reduces mod q. Statistical
    distance from uniform on Z_q is below 2^-126, which is well below the
    128-bit security we target.
    """
    uniform = expand_message_xmd(msg, dst, 64)
    return Scalar.from_bytes_wide(uniform)
