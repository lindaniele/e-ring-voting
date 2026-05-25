"""
otrs — one-time traceable ring signatures.

Reference implementation of Scafuro & Zhang's one-time traceable ring signature
scheme, instantiated over the Ristretto255 prime-order group with RFC 9380
hash-to-curve. Intended as a research artifact, not for production deployment
without further review.
"""

from otrs.otrs import (
    KeyPair,
    PublicKey,
    SecretKey,
    Signature,
    TraceResult,
    keygen,
    sign,
    trace,
    verify,
)

__all__ = [
    "KeyPair",
    "PublicKey",
    "SecretKey",
    "Signature",
    "TraceResult",
    "keygen",
    "sign",
    "trace",
    "verify",
]

__version__ = "0.1.0"
