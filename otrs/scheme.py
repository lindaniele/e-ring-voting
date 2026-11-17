"""
One-time traceable ring signature of Scafuro and Zhang (ESORICS 2021),
scheme ``Σ_OTS`` of their Fig. 1.

Notation follows the paper. ``λ`` is the security parameter, ``N`` the
ring size, ``G`` and ``H`` the two random oracles of
:mod:`otrs.primitives`.

Key generation
    Pick ``2λ`` seeds ``s^0_j, s^1_j`` and publish the rows
    ``pk_j = G(s^0_j) ⊕ G(s^1_j)``, ``j = 1..λ``. Each row is the first
    message of Naor's bit commitment computed in *equivocal mode*: whoever
    knows ``s^0_j`` and ``s^1_j`` can open the commitment ``G(s^0_j)`` to
    either bit.

Signing (signer at position ``l``)
    For every other member ``i`` pick a random ``x_i ∈ {0,1}^λ`` and commit
    to it bit by bit, ``c_{i,j} = G(r_{i,j}) ⊕ x_i[j]·pk_{i,j}``. For the
    signer commit to ``c_{l,j} = G(s^0_{l,j})``. Compute the target
    ``z = H(R, m, c_1..c_N)``, set ``x*_l = z ⊕ ⊕_{i≠l} x_i`` and open the
    signer's commitments to ``x*_l`` by revealing ``s^{x*_l[j]}_{l,j}``.
    The signature is every ``x_i`` and every opening seed ``r_{i,j}``:
    ``N·λ·(λ+1)`` bits.

Verification
    Recompute every ``c_{i,j}`` from ``(x_i[j], r_{i,j})``, recompute ``z``
    and check ``z = ⊕_i x_i``.

Trace
    Two signatures over the same ring are traced to member ``i`` if, for
    some row ``j``, ``G(α_{i,j}) ⊕ G(β_{i,j}) = pk_{i,j}``: together they
    reveal both seeds of one of ``i``'s rows. Any two distinct signatures
    made with the same key do this with probability ``1 − 2^{-λ}``, *even
    on the same message*, because their targets differ.

What this module adds to Fig. 1
-------------------------------
1. **Rows must be non-zero.** If ``pk_{i,j} = 0`` the commitment
   ``G(r) ⊕ x·pk_{i,j}`` equals ``G(r)`` for both bits, so the row opens
   either way *with the same seed*. A key whose rows are all zero signs any
   number of times, with fresh seeds each time, and is never traced. Fig. 1
   checks that ring keys are distinct and well-sized but not this; every
   key accepted here is checked (``test_otrs.py::TestZeroRow``). For a
   non-zero row, opening it both ways needs two seeds, and finding two
   such pairs for one row is a 4-XOR problem on ``3λ`` bits, about
   ``2^λ`` work by Wagner's algorithm. This is what the ``3λ`` stretch
   buys.
2. **A public label inside the key** (32 bytes). It is hashed into the ring
   like the rest of the key and lets an application bind a one-time key to
   the single use it was made for (here: one poll and one registration
   handle, or one transfer round). It does not touch the security argument
   of [SZ21]: it is public data that every party sees in the ring.
3. **Deterministic signing**, see :func:`otrs.primitives.signing_stream`.
   Signing the same input twice returns the same bytes; a copy is not a
   second signature.
4. **Trace returns every traced member**, not just one: a signature made by
   a coalition can open rows of several keys.
5. **Openings are reusable.** Verification computes ``G(r_{i,j})`` for
   every opening seed; :meth:`Ring.check` returns them as an
   :class:`Openings` object so that tracing a new signature against the
   ones already recorded costs XORs, not hashes.

Security (from [SZ21], classical ROM): one-time anonymity, public
traceability (``N`` keys cannot produce ``N + 1`` distinct signatures
without a trace) and one-time exculpability (an honest key used once
cannot be traced). All three hold only if every honest key signs **at most
once, ever**. This is pure Python and not constant-time.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from functools import cached_property
from typing import List, Optional, Sequence, Tuple

from otrs.primitives import (
    LABEL_BYTES,
    OTRS128,
    PARAMS_BY_IDENT,
    G,
    G_concat,
    H,
    Params,
    ring_digest,
    secret_seeds,
    signing_stream,
)


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _bits(x: bytes, lam: int) -> str:
    """``x`` as a string of ``λ`` characters '0'/'1', most significant first."""
    return format(int.from_bytes(x, "big"), f"0{lam}b")


# --------------------------------------------------------------------------- #
# Keys                                                                         #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PublicKey:
    """``λ`` rows of ``3λ`` bits plus a 32-byte public label."""

    params: Params
    label: bytes
    rows: Tuple[bytes, ...]

    @cached_property
    def encoded(self) -> bytes:
        return bytes([self.params.ident]) + self.label + b"".join(self.rows)

    def to_bytes(self) -> bytes:
        return self.encoded

    @cached_property
    def fingerprint(self) -> bytes:
        """SHA-256 of the encoding: a short, stable identifier for the key."""
        return hashlib.sha256(self.encoded).digest()

    def problems(self) -> List[str]:
        """Why this key must not enter a ring (empty if it may)."""
        p = self.params
        out: List[str] = []
        if len(self.label) != LABEL_BYTES:
            out.append("label must be 32 bytes")
        if len(self.rows) != p.rows:
            out.append(f"key must have {p.rows} rows")
        zero = bytes(p.row_bytes)
        for j, row in enumerate(self.rows):
            if len(row) != p.row_bytes:
                out.append(f"row {j} has the wrong length")
            elif row == zero:
                out.append(f"row {j} is zero (it would open to both bits)")
        return out

    @classmethod
    def from_bytes(cls, blob: bytes) -> "PublicKey":
        if not blob:
            raise ValueError("empty public key")
        params = PARAMS_BY_IDENT.get(blob[0])
        if params is None:
            raise ValueError(f"unknown parameter set {blob[0]}")
        if len(blob) != params.key_bytes:
            raise ValueError(
                f"public key must be {params.key_bytes} bytes, got {len(blob)}"
            )
        label = blob[1:1 + LABEL_BYTES]
        rb = params.row_bytes
        body = blob[1 + LABEL_BYTES:]
        rows = tuple(body[k * rb:(k + 1) * rb] for k in range(params.rows))
        pk = cls(params=params, label=label, rows=rows)
        issues = pk.problems()
        if issues:
            raise ValueError("invalid public key: " + "; ".join(issues))
        return pk


@dataclass(frozen=True)
class SecretKey:
    """A master secret; the ``2λ`` seeds are derived from it and the label."""

    params: Params
    label: bytes
    master: bytes

    @cached_property
    def seeds(self) -> bytes:
        return secret_seeds(self.params, self.label, self.master)

    def seed(self, j: int, bit: int) -> bytes:
        sb = self.params.seed_bytes
        k = 2 * j + bit
        return self.seeds[k * sb:(k + 1) * sb]

    def public_key(self) -> PublicKey:
        p = self.params
        rows = []
        for j in range(p.rows):
            row = _xor(G(p, self.seed(j, 0)), G(p, self.seed(j, 1)))
            if row == bytes(p.row_bytes):
                raise ValueError("degenerate key (zero row): use another master secret")
            rows.append(row)
        return PublicKey(params=p, label=self.label, rows=tuple(rows))

    def to_bytes(self) -> bytes:
        return bytes([self.params.ident]) + self.label + self.master

    @classmethod
    def from_bytes(cls, blob: bytes) -> "SecretKey":
        if not blob:
            raise ValueError("empty secret key")
        params = PARAMS_BY_IDENT.get(blob[0])
        if params is None:
            raise ValueError(f"unknown parameter set {blob[0]}")
        if len(blob) != 1 + LABEL_BYTES + params.master_bytes:
            raise ValueError("secret key has the wrong length")
        return cls(
            params=params,
            label=blob[1:1 + LABEL_BYTES],
            master=blob[1 + LABEL_BYTES:],
        )


@dataclass(frozen=True)
class KeyPair:
    sk: SecretKey
    pk: PublicKey


def keygen(
    label: bytes = bytes(LABEL_BYTES),
    *,
    params: Params = OTRS128,
    master: Optional[bytes] = None,
) -> KeyPair:
    """A fresh one-time key. Use it for **one** signature."""
    if len(label) != LABEL_BYTES:
        raise ValueError("label must be 32 bytes")
    if master is None:
        master = os.urandom(params.master_bytes)
    if len(master) != params.master_bytes:
        raise ValueError(f"master secret must be {params.master_bytes} bytes")
    sk = SecretKey(params=params, label=label, master=master)
    return KeyPair(sk=sk, pk=sk.public_key())


# --------------------------------------------------------------------------- #
# Signatures                                                                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Signature:
    """``x_i`` for every member and the ``λ`` opening seeds of every member."""

    params: Params
    xs: Tuple[bytes, ...]
    seeds: bytes  # member-major: r_{1,1} .. r_{1,λ}, r_{2,1}, ..

    @property
    def ring_size(self) -> int:
        return len(self.xs)

    def seed(self, i: int, j: int) -> bytes:
        sb = self.params.seed_bytes
        k = i * self.params.rows + j
        return self.seeds[k * sb:(k + 1) * sb]

    @cached_property
    def encoded(self) -> bytes:
        p = self.params
        per = p.rows * p.seed_bytes
        parts = [bytes([p.ident]), len(self.xs).to_bytes(4, "big")]
        for i, x in enumerate(self.xs):
            parts.append(x)
            parts.append(self.seeds[i * per:(i + 1) * per])
        return b"".join(parts)

    def to_bytes(self) -> bytes:
        return self.encoded

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Signature":
        if len(blob) < 5:
            raise ValueError("signature too short")
        params = PARAMS_BY_IDENT.get(blob[0])
        if params is None:
            raise ValueError(f"unknown parameter set {blob[0]}")
        n = int.from_bytes(blob[1:5], "big")
        if n < 1:
            raise ValueError("signature for an empty ring")
        if len(blob) != params.sig_bytes(n):
            raise ValueError(
                f"signature length {len(blob)} != {params.sig_bytes(n)} for N={n}"
            )
        sb = params.seed_bytes
        per = params.rows * sb
        xs, seeds = [], []
        off = 5
        for _ in range(n):
            xs.append(blob[off:off + sb])
            off += sb
            seeds.append(blob[off:off + per])
            off += per
        return cls(params=params, xs=tuple(xs), seeds=b"".join(seeds))


@dataclass(frozen=True)
class Openings:
    """``G(r_{i,j})`` for every opening seed of a signature, as one integer."""

    value: int


@dataclass(frozen=True)
class TraceResult:
    """
    * ``"identical"``: the same signature twice (a copy, not a second use);
    * ``"traced"``: ``culprits`` (0-based positions) each had both seeds of
      some row revealed by the pair, i.e. their key signed twice;
    * ``"independent"``: no key was traced.
    """

    status: str
    culprits: Tuple[int, ...] = ()
    culprit_pks: Tuple[PublicKey, ...] = ()


# --------------------------------------------------------------------------- #
# Ring                                                                         #
# --------------------------------------------------------------------------- #


class Ring:
    """
    An ordered ring with everything that depends only on its keys
    precomputed: the ring digest that enters ``H`` and the concatenation of
    all rows used by verification and trace.
    """

    def __init__(self, keys: Sequence[PublicKey], *, _check_keys: bool = True) -> None:
        keys = tuple(keys)
        if not keys:
            raise ValueError("ring must contain at least one key")
        params = keys[0].params
        if any(k.params != params for k in keys):
            raise ValueError("ring mixes parameter sets")
        if _check_keys:
            for k in keys:
                issues = k.problems()
                if issues:
                    raise ValueError("invalid key in ring: " + "; ".join(issues))
        position = {k.fingerprint: i for i, k in enumerate(keys)}
        if len(position) != len(keys):
            raise ValueError("ring contains duplicate keys")
        self.keys = keys
        self.params = params
        self.digest = ring_digest(params, (k.encoded for k in keys))
        cat = b"".join(row for k in keys for row in k.rows)
        self._pcat = int.from_bytes(cat, "big")
        self._cat_len = len(cat)
        self._position = position
        rb = params.row_bytes
        self._one = b"\xff" * rb
        self._zero = bytes(rb)

    def __len__(self) -> int:
        return len(self.keys)

    def position(self, pk: PublicKey) -> int:
        try:
            return self._position[pk.fingerprint]
        except KeyError:
            raise ValueError("key is not a member of the ring") from None

    # ----- internals ------------------------------------------------------ #
    def _mask(self, xs: Sequence[bytes]) -> int:
        lam, one, zero = self.params.lam, self._one, self._zero
        return int.from_bytes(
            b"".join(one if b == "1" else zero for x in xs for b in _bits(x, lam)),
            "big",
        )

    def _openings(self, seeds: bytes) -> int:
        sb = self.params.seed_bytes
        count = len(seeds) // sb
        return int.from_bytes(
            G_concat(self.params, (seeds[k * sb:(k + 1) * sb] for k in range(count))),
            "big",
        )

    def _commitments(self, xs: Sequence[bytes], openings: int) -> bytes:
        return (openings ^ (self._mask(xs) & self._pcat)).to_bytes(self._cat_len, "big")

    # ----- sign / verify -------------------------------------------------- #
    def sign(
        self,
        kp: KeyPair,
        message: bytes,
        context: bytes = b"",
        *,
        randomized: bool = False,
    ) -> Signature:
        """
        ``RSign`` with the signer found by key. The randomness is derived
        from the secret and the input, so signing twice returns the same
        signature. ``randomized=True`` draws it from the OS instead, as a
        careless wallet would: a second call then yields a *different*
        signature, and the key is traced even if the message is the same.
        """
        p = self.params
        if kp.pk.params != p:
            raise ValueError("key and ring use different parameter sets")
        l = self.position(kp.pk)
        n, lam, sb = len(self.keys), p.rows, p.seed_bytes
        per = lam * sb
        length = (n - 1) * (sb + per)
        if randomized:
            stream = os.urandom(length)
        else:
            stream = signing_stream(
                p, kp.sk.master, kp.sk.label, context, self.digest, message, length
            )
        xs: List[bytes] = []
        seeds: List[bytes] = []
        off = 0
        for i in range(n):
            if i == l:
                # c_{l,j} = G(s^0_{l,j}): equivocal commitments, opened later.
                xs.append(bytes(sb))
                seeds.append(b"".join(kp.sk.seed(j, 0) for j in range(lam)))
                continue
            xs.append(stream[off:off + sb])
            off += sb
            seeds.append(stream[off:off + per])
            off += per
        commitments = self._commitments(xs, self._openings(b"".join(seeds)))
        z = H(p, context, self.digest, message, commitments)
        acc = int.from_bytes(z, "big")
        for i, x in enumerate(xs):
            if i != l:
                acc ^= int.from_bytes(x, "big")
        x_star = acc.to_bytes(sb, "big")
        xs[l] = x_star
        seeds[l] = b"".join(
            kp.sk.seed(j, int(bit)) for j, bit in enumerate(_bits(x_star, lam))
        )
        return Signature(params=p, xs=tuple(xs), seeds=b"".join(seeds))

    def check(
        self, sig: Signature, message: bytes, context: bytes = b""
    ) -> Optional[Openings]:
        """Verify ``sig``; return its openings if valid, ``None`` otherwise."""
        p = self.params
        if sig.params != p or len(sig.xs) != len(self.keys):
            return None
        if len(sig.seeds) != len(self.keys) * p.rows * p.seed_bytes:
            return None
        if any(len(x) != p.seed_bytes for x in sig.xs):
            return None
        openings = self._openings(sig.seeds)
        commitments = self._commitments(sig.xs, openings)
        z = H(p, context, self.digest, message, commitments)
        acc = 0
        for x in sig.xs:
            acc ^= int.from_bytes(x, "big")
        if not hmac.compare_digest(acc.to_bytes(p.seed_bytes, "big"), z):
            return None
        return Openings(openings)

    def verify(self, sig: Signature, message: bytes, context: bytes = b"") -> bool:
        return self.check(sig, message, context) is not None

    # ----- trace ----------------------------------------------------------- #
    def openings(self, sig: Signature) -> Openings:
        """The openings of ``sig`` without verifying it."""
        return Openings(self._openings(sig.seeds))

    def culprits(self, a: Openings, b: Openings) -> List[int]:
        """Positions ``i`` with a row where ``G(α) ⊕ G(β) = pk_{i,j}``."""
        diff = (a.value ^ b.value ^ self._pcat).to_bytes(self._cat_len, "big")
        rb = self.params.row_bytes
        per_member = self.params.rows * rb
        zero = self._zero
        found: List[int] = []
        pos = diff.find(zero)
        while pos != -1:
            if pos % rb == 0:
                member = pos // per_member
                found.append(member)
                pos = diff.find(zero, (member + 1) * per_member)
            else:
                pos = diff.find(zero, pos + 1)
        return found

    def trace(self, sig1: Signature, sig2: Signature) -> TraceResult:
        """[SZ21] Trace. Both signatures are assumed to verify on this ring."""
        if sig1.to_bytes() == sig2.to_bytes():
            return TraceResult(status="identical")
        found = self.culprits(self.openings(sig1), self.openings(sig2))
        if not found:
            return TraceResult(status="independent")
        return TraceResult(
            status="traced",
            culprits=tuple(found),
            culprit_pks=tuple(self.keys[i] for i in found),
        )


# --------------------------------------------------------------------------- #
# Paper-style functional interface                                             #
# --------------------------------------------------------------------------- #


def sign(
    kp: KeyPair, ring: Sequence[PublicKey], message: bytes, context: bytes = b""
) -> Signature:
    """``RSign(R, sk, m)``."""
    return Ring(ring).sign(kp, message, context)


def verify(
    ring: Sequence[PublicKey], message: bytes, sig: Signature, context: bytes = b""
) -> bool:
    """``RVer(R, σ, m)``."""
    return Ring(ring).verify(sig, message, context)


def trace(ring: Sequence[PublicKey], sig1: Signature, sig2: Signature) -> TraceResult:
    """``Trace(R, m1, σ1, m2, σ2)``; the messages play no role."""
    return Ring(ring).trace(sig1, sig2)
