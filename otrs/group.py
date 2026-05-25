"""
Ristretto255 group wrapper.

Ristretto255 is a prime-order group built on Curve25519 (Hamburg, 2015;
de Valence et al.). Order ``q = 2**252 + 27742317777372353535851937790883648493``.
All arithmetic is delegated to libsodium via pynacl, which is the audited
implementation we depend on.

We expose four types of operation:

* scalar arithmetic mod ``q``                  (add, sub, mul, invert, reduce)
* point arithmetic on the prime-order group    (add, sub, scalar-mul, base-mul)
* serialization                                (32 bytes per scalar, 32 per point)
* sampling                                     (uniform scalars from os.urandom)

This module deliberately raises ``ValueError`` for invalid encodings rather
than returning sentinel values, so callers cannot silently operate on garbage.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

from otrs._libsodium import (
    POINT_BYTES as _POINT_BYTES,
    SCALAR_BYTES as _SCALAR_BYTES,
    crypto_core_ristretto255_add,
    crypto_core_ristretto255_from_hash,
    crypto_core_ristretto255_is_valid_point,
    crypto_core_ristretto255_scalar_add,
    crypto_core_ristretto255_scalar_invert,
    crypto_core_ristretto255_scalar_mul,
    crypto_core_ristretto255_scalar_reduce,
    crypto_core_ristretto255_scalar_sub,
    crypto_core_ristretto255_sub,
    crypto_scalarmult_ristretto255,
    crypto_scalarmult_ristretto255_base,
)

POINT_BYTES: Final[int] = _POINT_BYTES        # 32
SCALAR_BYTES: Final[int] = _SCALAR_BYTES      # 32

# Group order q. Public; included so library users can reason about modular
# arithmetic without round-tripping through libsodium.
ORDER: Final[int] = 2**252 + 27742317777372353535851937790883648493


# --------------------------------------------------------------------------- #
# Scalars                                                                     #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Scalar:
    """An integer mod q, stored canonically as 32 little-endian bytes."""

    raw: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.raw, (bytes, bytearray)):
            raise TypeError("Scalar.raw must be bytes")
        if len(self.raw) != SCALAR_BYTES:
            raise ValueError(f"Scalar must be {SCALAR_BYTES} bytes, got {len(self.raw)}")

    @classmethod
    def from_int(cls, x: int) -> "Scalar":
        return cls((x % ORDER).to_bytes(SCALAR_BYTES, "little"))

    @classmethod
    def from_bytes_wide(cls, b: bytes) -> "Scalar":
        """Reduce 64 uniform bytes mod q (RFC 9380 hash-to-field building block)."""
        if len(b) != 64:
            raise ValueError(f"from_bytes_wide expects 64 bytes, got {len(b)}")
        return cls(crypto_core_ristretto255_scalar_reduce(b))

    @classmethod
    def random(cls) -> "Scalar":
        # Pull 64 bytes from the OS CSPRNG and reduce — uniform over Z_q.
        return cls.from_bytes_wide(os.urandom(64))

    def to_int(self) -> int:
        return int.from_bytes(self.raw, "little")

    def __add__(self, other: "Scalar") -> "Scalar":
        return Scalar(crypto_core_ristretto255_scalar_add(self.raw, other.raw))

    def __sub__(self, other: "Scalar") -> "Scalar":
        return Scalar(crypto_core_ristretto255_scalar_sub(self.raw, other.raw))

    def __mul__(self, other: "Scalar") -> "Scalar":
        return Scalar(crypto_core_ristretto255_scalar_mul(self.raw, other.raw))

    def __neg__(self) -> "Scalar":
        return Scalar.from_int(0) - self

    def invert(self) -> "Scalar":
        if self.to_int() == 0:
            raise ZeroDivisionError("Scalar inversion of zero")
        return Scalar(crypto_core_ristretto255_scalar_invert(self.raw))

    def is_zero(self) -> bool:
        return self.to_int() == 0


# --------------------------------------------------------------------------- #
# Points                                                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Point:
    """A Ristretto255 group element, canonically 32 bytes."""

    raw: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.raw, (bytes, bytearray)):
            raise TypeError("Point.raw must be bytes")
        if len(self.raw) != POINT_BYTES:
            raise ValueError(f"Point must be {POINT_BYTES} bytes, got {len(self.raw)}")
        if not crypto_core_ristretto255_is_valid_point(self.raw):
            raise ValueError("Bytes do not encode a valid Ristretto255 point")

    @classmethod
    def base(cls) -> "Point":
        """The canonical Ristretto255 generator G."""
        # G = scalarmult_base(1).
        one = Scalar.from_int(1)
        return cls(crypto_scalarmult_ristretto255_base(one.raw))

    @classmethod
    def from_uniform_64(cls, b: bytes) -> "Point":
        """Map 64 uniform bytes to a point. Used by RFC 9380 hash-to-curve."""
        if len(b) != 64:
            raise ValueError(f"from_uniform_64 expects 64 bytes, got {len(b)}")
        return cls(crypto_core_ristretto255_from_hash(b))

    def __add__(self, other: "Point") -> "Point":
        return Point(crypto_core_ristretto255_add(self.raw, other.raw))

    def __sub__(self, other: "Point") -> "Point":
        return Point(crypto_core_ristretto255_sub(self.raw, other.raw))

    def scalar_mul(self, s: Scalar) -> "Point":
        if s.is_zero():
            # libsodium rejects scalar=0 in crypto_scalarmult_ristretto255.
            # We define 0·P = identity by convention. Represent identity as
            # P − P, which libsodium emits as the canonical all-zero encoding.
            return self - self
        return Point(crypto_scalarmult_ristretto255(s.raw, self.raw))


def base_mul(s: Scalar) -> Point:
    """Compute s·G where G is the Ristretto255 generator."""
    if s.is_zero():
        g = Point.base()
        return g - g
    return Point(crypto_scalarmult_ristretto255_base(s.raw))
