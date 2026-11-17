"""
otrs — one-time traceable ring signatures.

An implementation of the scheme of Alessandra Scafuro and Bihan Zhang,
*One-time Traceable Ring Signatures*, ESORICS 2021 (IACR ePrint 2021/1054;
a text copy is in ``docs/references/``). It uses nothing but a hash
function: keys are Naor bit-commitment keys in equivocal mode, a signature
opens the signer's commitments with one seed of each pair, and a second
signature by the same key reveals the other seed of some pair, which
identifies the key. No discrete logarithms are involved, so the scheme is
believed to resist quantum adversaries (the proofs in [SZ21] are in the
classical random-oracle model).

Every honest key must sign **once**. That is the whole design constraint,
and in e-ring-voting it is also the rule: one key, one poll, one message.

Research artifact; pure Python, not constant-time, not reviewed.
"""

from otrs.primitives import OTRS128, OTRS256, Params, params_for
from otrs.scheme import (
    KeyPair,
    Openings,
    PublicKey,
    Ring,
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
    "OTRS128",
    "OTRS256",
    "Openings",
    "Params",
    "PublicKey",
    "Ring",
    "SecretKey",
    "Signature",
    "TraceResult",
    "keygen",
    "params_for",
    "sign",
    "trace",
    "verify",
]

__version__ = "1.0.0"
