"""
trs — traceable ring signatures.

Implementation of Fujisaki & Suzuki's traceable ring signature (PKC 2007),
instantiated over the Ristretto255 prime-order group with RFC 9380
hash-to-curve, plus a Schnorr proof of possession used at voter
registration. Intended as a research artifact, not for production
deployment without further review.
"""

from trs.pop import prove_possession, verify_possession
from trs.trs import (
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
    "prove_possession",
    "sign",
    "trace",
    "verify",
    "verify_possession",
]

__version__ = "0.5.0"
