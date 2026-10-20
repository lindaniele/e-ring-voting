"""
Schnorr proof of possession for ring public keys.

A voter registering ``pk = g^x`` proves knowledge of ``x`` by signing a
context string (election id, handle, ...). This is the "the voter signs
their registration with their own key" step of the original e-ring-voting
procedure. It stops a sponsor from registering a key it does not control,
for example somebody else's key or a point with no known discrete log that
would silently pad a ring with members nobody can sign for.

Proof: ``R = g^r``, ``c = H(R || pk || context)``, ``s = r + c·x``.
Encoding: ``R || s`` (64 bytes).
"""

from __future__ import annotations

from trs.group import ORDER, POINT_BYTES, Point, Scalar, base_mul
from trs.hash import hash_to_scalar
from trs.trs import PublicKey, SecretKey

DST_POP = b"FS07-TRS-v1-RISTRETTO255-XMD:SHA-512-POP"
POP_BYTES = 64


def _challenge(R: Point, pk: PublicKey, context: bytes) -> Scalar:
    return hash_to_scalar(R.raw + pk.point.raw + context, DST_POP)


def prove_possession(sk: SecretKey, pk: PublicKey, context: bytes) -> bytes:
    """Return a 64-byte proof that the holder of ``pk`` knows its secret."""
    r = Scalar.random()
    R = base_mul(r)
    s = r + _challenge(R, pk, context) * sk.x
    return R.raw + s.raw


def verify_possession(pk: PublicKey, context: bytes, proof: bytes) -> bool:
    """Check a proof produced by :func:`prove_possession` for ``context``."""
    if len(proof) != POP_BYTES:
        return False
    try:
        R = Point(proof[:POINT_BYTES])
    except ValueError:
        return False
    s = Scalar(proof[POINT_BYTES:])
    if s.to_int() >= ORDER:
        return False  # non-canonical scalar
    expected = R + pk.point.scalar_mul(_challenge(R, pk, context))
    return base_mul(s).raw == expected.raw
