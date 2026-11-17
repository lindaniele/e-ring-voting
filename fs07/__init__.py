"""
fs07 — Fujisaki & Suzuki's traceable ring signature (PKC 2007).

Instantiated over Ristretto255 with RFC 9380 hash-to-curve. This is the
scheme the 2021–22 prototype implemented (``legacy/cryptography/ring.py``),
with its bugs fixed. The voting design no longer uses it: it signs with the
one-time scheme in :mod:`otrs`. It is kept as the point of comparison for
the benchmarks and the paper (reusable keys and short signatures, but
security from DDH, which a quantum computer breaks retroactively).

Research artifact, not for production use.
"""

from fs07.scheme import (
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

__version__ = "0.5.0"
