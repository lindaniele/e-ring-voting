"""
Direct cffi ABI binding for libsodium's Ristretto255 surface.

Ubuntu 24.04's ``python3-nacl`` (PyNaCl 1.5.0-4build1) was built against a
libsodium that did not export Ristretto255 bindings, so we go around it and
talk to ``libsodium.so.23`` directly via cffi in ABI mode (no compiler needed).
The cdef list below is copied verbatim from libsodium's ``crypto_core_ristretto255.h``
and ``crypto_scalarmult_ristretto255.h`` headers.

This module deliberately mirrors the names that PyNaCl would have exposed
(``crypto_core_ristretto255_*`` and friends) so the rest of the package
imports it as a drop-in replacement.

Constants (BYTES, SCALARBYTES, etc.) are taken from the standard:
all are 32 except ``hashbytes`` and ``nonreducedscalarbytes`` which are 64.
"""

from __future__ import annotations

from cffi import FFI

_ffi = FFI()
_ffi.cdef(
    """
    int sodium_init(void);

    /* sizes */
    size_t crypto_core_ristretto255_bytes(void);
    size_t crypto_core_ristretto255_scalarbytes(void);
    size_t crypto_core_ristretto255_hashbytes(void);
    size_t crypto_core_ristretto255_nonreducedscalarbytes(void);
    size_t crypto_scalarmult_ristretto255_bytes(void);
    size_t crypto_scalarmult_ristretto255_scalarbytes(void);

    /* group ops */
    int crypto_core_ristretto255_is_valid_point(const unsigned char *p);
    int crypto_core_ristretto255_from_hash(unsigned char *p,
                                           const unsigned char *r);
    int crypto_core_ristretto255_add(unsigned char *r,
                                     const unsigned char *p,
                                     const unsigned char *q);
    int crypto_core_ristretto255_sub(unsigned char *r,
                                     const unsigned char *p,
                                     const unsigned char *q);

    /* scalar ops */
    void crypto_core_ristretto255_scalar_random(unsigned char *r);
    void crypto_core_ristretto255_scalar_reduce(unsigned char *r,
                                                const unsigned char *s);
    void crypto_core_ristretto255_scalar_add(unsigned char *z,
                                             const unsigned char *x,
                                             const unsigned char *y);
    void crypto_core_ristretto255_scalar_sub(unsigned char *z,
                                             const unsigned char *x,
                                             const unsigned char *y);
    void crypto_core_ristretto255_scalar_mul(unsigned char *z,
                                             const unsigned char *x,
                                             const unsigned char *y);
    int  crypto_core_ristretto255_scalar_invert(unsigned char *recip,
                                                const unsigned char *s);

    /* scalar multiplication */
    int crypto_scalarmult_ristretto255(unsigned char *q,
                                       const unsigned char *n,
                                       const unsigned char *p);
    int crypto_scalarmult_ristretto255_base(unsigned char *q,
                                            const unsigned char *n);
    """
)

# Load the system libsodium. We pin to soname 23 to fail loudly if it changes
# (binary-incompatible bumps would require an updated cdef).
_lib = _ffi.dlopen("libsodium.so.23")

if _lib.sodium_init() < 0:
    # -1 is the "already initialised" return on libsodium ≥ 1.0.18 paths that
    # were called by another loader. We tolerate >= 0; explicit guard kept
    # in case future libsodium versions tighten the contract.
    raise RuntimeError("sodium_init failed")

POINT_BYTES = _lib.crypto_core_ristretto255_bytes()
SCALAR_BYTES = _lib.crypto_core_ristretto255_scalarbytes()
HASH_BYTES = _lib.crypto_core_ristretto255_hashbytes()
NONREDUCED_SCALAR_BYTES = _lib.crypto_core_ristretto255_nonreducedscalarbytes()

assert POINT_BYTES == 32 and SCALAR_BYTES == 32 and HASH_BYTES == 64


def _new(n: int) -> "ffi.CData":
    return _ffi.new(f"unsigned char[{n}]")


def _to_bytes(buf: "ffi.CData", n: int) -> bytes:
    return bytes(_ffi.buffer(buf, n))


# --------------------------------------------------------------------------- #
# Public API mirroring PyNaCl's naming                                        #
# --------------------------------------------------------------------------- #


def crypto_core_ristretto255_is_valid_point(p: bytes) -> bool:
    if len(p) != POINT_BYTES:
        return False
    return _lib.crypto_core_ristretto255_is_valid_point(p) == 1


def crypto_core_ristretto255_from_hash(h: bytes) -> bytes:
    if len(h) != HASH_BYTES:
        raise ValueError(f"hash must be {HASH_BYTES} bytes, got {len(h)}")
    out = _new(POINT_BYTES)
    rc = _lib.crypto_core_ristretto255_from_hash(out, h)
    if rc != 0:
        raise RuntimeError("crypto_core_ristretto255_from_hash failed")
    return _to_bytes(out, POINT_BYTES)


def _check_point(name: str, p: bytes) -> None:
    if len(p) != POINT_BYTES:
        raise ValueError(f"{name}: point must be {POINT_BYTES} bytes")


def _check_scalar(name: str, s: bytes) -> None:
    if len(s) != SCALAR_BYTES:
        raise ValueError(f"{name}: scalar must be {SCALAR_BYTES} bytes")


def crypto_core_ristretto255_add(p: bytes, q: bytes) -> bytes:
    _check_point("add", p)
    _check_point("add", q)
    out = _new(POINT_BYTES)
    rc = _lib.crypto_core_ristretto255_add(out, p, q)
    if rc != 0:
        raise ValueError("ristretto255 add rejected inputs")
    return _to_bytes(out, POINT_BYTES)


def crypto_core_ristretto255_sub(p: bytes, q: bytes) -> bytes:
    _check_point("sub", p)
    _check_point("sub", q)
    out = _new(POINT_BYTES)
    rc = _lib.crypto_core_ristretto255_sub(out, p, q)
    if rc != 0:
        raise ValueError("ristretto255 sub rejected inputs")
    return _to_bytes(out, POINT_BYTES)


def crypto_core_ristretto255_scalar_add(x: bytes, y: bytes) -> bytes:
    _check_scalar("scalar_add", x)
    _check_scalar("scalar_add", y)
    out = _new(SCALAR_BYTES)
    _lib.crypto_core_ristretto255_scalar_add(out, x, y)
    return _to_bytes(out, SCALAR_BYTES)


def crypto_core_ristretto255_scalar_sub(x: bytes, y: bytes) -> bytes:
    _check_scalar("scalar_sub", x)
    _check_scalar("scalar_sub", y)
    out = _new(SCALAR_BYTES)
    _lib.crypto_core_ristretto255_scalar_sub(out, x, y)
    return _to_bytes(out, SCALAR_BYTES)


def crypto_core_ristretto255_scalar_mul(x: bytes, y: bytes) -> bytes:
    _check_scalar("scalar_mul", x)
    _check_scalar("scalar_mul", y)
    out = _new(SCALAR_BYTES)
    _lib.crypto_core_ristretto255_scalar_mul(out, x, y)
    return _to_bytes(out, SCALAR_BYTES)


def crypto_core_ristretto255_scalar_invert(s: bytes) -> bytes:
    _check_scalar("scalar_invert", s)
    out = _new(SCALAR_BYTES)
    rc = _lib.crypto_core_ristretto255_scalar_invert(out, s)
    if rc != 0:
        raise ZeroDivisionError("scalar inversion failed (zero scalar)")
    return _to_bytes(out, SCALAR_BYTES)


def crypto_core_ristretto255_scalar_reduce(s: bytes) -> bytes:
    if len(s) != NONREDUCED_SCALAR_BYTES:
        raise ValueError(
            f"scalar_reduce expects {NONREDUCED_SCALAR_BYTES} bytes, "
            f"got {len(s)}"
        )
    out = _new(SCALAR_BYTES)
    _lib.crypto_core_ristretto255_scalar_reduce(out, s)
    return _to_bytes(out, SCALAR_BYTES)


def crypto_scalarmult_ristretto255(n: bytes, p: bytes) -> bytes:
    _check_scalar("scalarmult", n)
    _check_point("scalarmult", p)
    out = _new(POINT_BYTES)
    rc = _lib.crypto_scalarmult_ristretto255(out, n, p)
    if rc != 0:
        # libsodium returns -1 for n=0 or P of small order. We surface this so
        # group.py can substitute identity for n=0 explicitly.
        raise ValueError("scalarmult rejected (zero scalar or small-order point)")
    return _to_bytes(out, POINT_BYTES)


def crypto_scalarmult_ristretto255_base(n: bytes) -> bytes:
    _check_scalar("scalarmult_base", n)
    out = _new(POINT_BYTES)
    rc = _lib.crypto_scalarmult_ristretto255_base(out, n)
    if rc != 0:
        raise ValueError("scalarmult_base rejected (zero scalar)")
    return _to_bytes(out, POINT_BYTES)
