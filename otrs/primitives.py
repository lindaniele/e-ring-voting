"""
Parameters and hash functions of the one-time traceable ring signature.

Scafuro and Zhang [SZ21] build the scheme from two random oracles,

* ``G : {0,1}^λ → {0,1}^{3λ}``, the pseudorandom generator of Naor's bit
  commitment, and
* ``H : {0,1}^* → {0,1}^λ``, which turns the commitments into the target
  string ``z``.

Both are instantiated here with SHAKE256 under distinct domain-separation
prefixes (the paper's implementation uses SHAKE128 in Go). The prefixes
also carry ``λ``, so the 128- and 256-bit parameter sets never share an
oracle.

Three further derivations are ours and do not appear in the paper:

* ``ring_digest`` compresses the ring (``N`` keys of ``3λ²`` bits each)
  into ``2λ`` bits before it enters ``H``;
* ``secret_seeds`` expands a short master secret into the ``2λ`` seeds of
  a key, so a key file holds ``λ/4`` bytes instead of ``λ²/4``;
* ``signing_stream`` derives the signer's randomness from the master
  secret and the full signing input. Deterministic signing matters more
  here than for ordinary signatures: a one-time key that re-signs the
  *same* message with fresh randomness produces a second, distinct
  signature and is traced (see :mod:`otrs.scheme`).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict

DST_PREFIX = b"SZ21-OTRS-SHAKE256-v1/"


@dataclass(frozen=True)
class Params:
    """A parameter set: the security parameter ``λ`` in bits."""

    lam: int
    ident: int  # one byte, written in front of every encoded key and signature

    @property
    def seed_bytes(self) -> int:
        """Length of a PRG seed, of the target ``z`` and of each ``x_i``."""
        return self.lam // 8

    @property
    def row_bytes(self) -> int:
        """Length of one public-key row ``pk_{i,j}`` (``3λ`` bits)."""
        return 3 * self.lam // 8

    @property
    def rows(self) -> int:
        """Rows per key: one Naor commitment key per bit of ``z``."""
        return self.lam

    @property
    def master_bytes(self) -> int:
        return 2 * self.lam // 8

    @property
    def key_bytes(self) -> int:
        """Encoded public key: ident, 32-byte label, ``λ`` rows."""
        return 1 + LABEL_BYTES + self.rows * self.row_bytes

    def sig_bytes(self, n: int) -> int:
        """Encoded signature for a ring of ``n``: ``n·λ·(λ+1)`` bits + 5."""
        return 1 + 4 + n * (self.seed_bytes + self.rows * self.seed_bytes)

    def dst(self, name: str) -> bytes:
        return DST_PREFIX + f"L{self.lam}/{name}/".encode()


LABEL_BYTES = 32

OTRS128 = Params(lam=128, ident=0x01)
OTRS256 = Params(lam=256, ident=0x02)

PARAMS_BY_IDENT: Dict[int, Params] = {p.ident: p for p in (OTRS128, OTRS256)}
PARAMS_BY_LAMBDA: Dict[int, Params] = {p.lam: p for p in (OTRS128, OTRS256)}


def params_for(lam: int) -> Params:
    try:
        return PARAMS_BY_LAMBDA[lam]
    except KeyError:
        raise ValueError(f"unsupported security parameter: {lam}") from None


def _u32(n: int) -> bytes:
    if n < 0 or n >> 32:
        raise ValueError(f"u32 out of range: {n}")
    return n.to_bytes(4, "big")


# --------------------------------------------------------------------------- #
# The two random oracles of the paper                                          #
# --------------------------------------------------------------------------- #

_G_STATE: Dict[int, "hashlib._Hash"] = {}


def _g_state(params: Params):
    st = _G_STATE.get(params.lam)
    if st is None:
        st = hashlib.shake_256(params.dst("G"))
        _G_STATE[params.lam] = st
    return st


def G(params: Params, seed: bytes) -> bytes:
    """The PRG ``G : {0,1}^λ → {0,1}^{3λ}``."""
    h = _g_state(params).copy()
    h.update(seed)
    return h.digest(params.row_bytes)


def G_concat(params: Params, seeds) -> bytes:
    """``G(s_1) || G(s_2) || ...`` for an iterable of seeds."""
    base = _g_state(params)
    out = []
    n = params.row_bytes
    for s in seeds:
        h = base.copy()
        h.update(s)
        out.append(h.digest(n))
    return b"".join(out)


def H(
    params: Params,
    context: bytes,
    ring_digest_: bytes,
    message: bytes,
    commitments: bytes,
) -> bytes:
    """The target ``z = H(R, m, c_1, ..., c_N)``, extended with a context."""
    h = hashlib.shake_256(params.dst("H"))
    h.update(_u32(len(context)))
    h.update(context)
    h.update(ring_digest_)
    h.update(_u32(len(message)))
    h.update(message)
    h.update(commitments)
    return h.digest(params.seed_bytes)


# --------------------------------------------------------------------------- #
# Derivations added by this implementation                                     #
# --------------------------------------------------------------------------- #


def ring_digest(params: Params, encoded_keys) -> bytes:
    """A ``2λ``-bit digest of the ordered ring."""
    keys = list(encoded_keys)
    h = hashlib.shake_256(params.dst("ring"))
    h.update(_u32(len(keys)))
    for k in keys:
        h.update(k)
    return h.digest(2 * params.seed_bytes)


def secret_seeds(params: Params, label: bytes, master: bytes) -> bytes:
    """The ``2λ`` seeds ``s^0_1, s^1_1, ..., s^0_λ, s^1_λ``, concatenated."""
    h = hashlib.shake_256(params.dst("sk"))
    h.update(label)
    h.update(master)
    return h.digest(2 * params.rows * params.seed_bytes)


def signing_stream(
    params: Params,
    master: bytes,
    label: bytes,
    context: bytes,
    ring_digest_: bytes,
    message: bytes,
    length: int,
) -> bytes:
    """The signer's random strings ``x_i`` and seeds ``r_{i,j}``, derived."""
    h = hashlib.shake_256(params.dst("sign"))
    h.update(master)
    h.update(label)
    h.update(_u32(len(context)))
    h.update(context)
    h.update(ring_digest_)
    h.update(_u32(len(message)))
    h.update(message)
    return h.digest(length)
