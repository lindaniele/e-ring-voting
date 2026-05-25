"""
One-time traceable ring signature (Scafuro & Zhang, 2021), instantiated over
Ristretto255 with RFC 9380 hash-to-curve.

The scheme provides:

* **Anonymity inside the ring.** A signature on behalf of a ring
  ``{pk_1, ..., pk_n}`` reveals nothing about which member produced it,
  assuming DDH is hard in the underlying group and the hash functions behave
  as random oracles.
* **One-time traceability.** Two signatures by the same ring member on the
  same ``issue`` are linkable: the ``trace`` algorithm identifies the
  responsible public key without ever revealing the signer's identity from a
  single signature. The intended use is e-voting, where ``issue`` is the
  election identifier and one signature per voter is the rule.

Public domain-separation tags below pin the protocol version. Any change to
the algebraic structure must change the tag prefix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from otrs.group import ORDER, Point, Scalar, base_mul
from otrs.hash import hash_to_group, hash_to_scalar
from otrs.serialize import (
    decode_signature,
    encode_points,
    encode_ring,
    encode_signature,
)

# Version-bound domain-separation tags. Bump on any algebraic change.
DST_H0 = b"OTRS-v1-RISTRETTO255-XMD:SHA-512-H0"
DST_H1 = b"OTRS-v1-RISTRETTO255-XMD:SHA-512-H1"
DST_H2 = b"OTRS-v1-RISTRETTO255-XMD:SHA-512-H2"


# --------------------------------------------------------------------------- #
# Types                                                                        #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SecretKey:
    """A signer's private scalar x."""

    x: Scalar


@dataclass(frozen=True)
class PublicKey:
    """A signer's public point g^x."""

    point: Point

    def to_bytes(self) -> bytes:
        return self.point.raw

    @classmethod
    def from_bytes(cls, b: bytes) -> "PublicKey":
        return cls(Point(b))


@dataclass(frozen=True)
class KeyPair:
    sk: SecretKey
    pk: PublicKey


@dataclass(frozen=True)
class Signature:
    """A_1 and the (c_j, z_j) response pairs for j = 1..n."""

    A1: Point
    c: List[Scalar]
    z: List[Scalar]

    def to_bytes(self) -> bytes:
        return encode_signature(self.A1, self.c, self.z)

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Signature":
        A1, c, z = decode_signature(blob)
        return cls(A1=A1, c=c, z=z)


@dataclass(frozen=True)
class TraceResult:
    """
    Outcome of comparing two signatures on the same (issue, ring):

    * ``status == "double-sign"``: the same signer produced both signatures
      on distinct messages. ``culprit_index`` and ``culprit_pk`` identify them.
    * ``status == "linked"``: both signatures share every column, i.e. the
      same signer produced both on the same message (a literal replay).
    * ``status == "independent"``: no column collides; the signers differ.
    """

    status: str  # "double-sign" | "linked" | "independent"
    culprit_index: int | None = None
    culprit_pk: PublicKey | None = None


# --------------------------------------------------------------------------- #
# Key generation                                                              #
# --------------------------------------------------------------------------- #


def keygen() -> KeyPair:
    """Sample a uniform secret scalar x ≠ 0 and compute pk = g^x."""
    while True:
        x = Scalar.random()
        if not x.is_zero():
            break
    pk = PublicKey(base_mul(x))
    return KeyPair(SecretKey(x), pk)


# --------------------------------------------------------------------------- #
# Internal helpers                                                            #
# --------------------------------------------------------------------------- #


def _check_ring(ring: Sequence[PublicKey]) -> None:
    n = len(ring)
    if n < 1:
        raise ValueError("ring must contain at least one public key")
    if n >= ORDER:
        # Positions live in {1,..,n} ⊂ Z_q*. Practically unreachable but defended.
        raise ValueError("ring size exceeds group order")
    seen = set()
    for pk in ring:
        if pk.point.raw in seen:
            raise ValueError("ring contains duplicate public keys")
        seen.add(pk.point.raw)


def _ring_bytes(ring: Sequence[PublicKey]) -> bytes:
    return encode_ring([pk.point for pk in ring])


def _find_position(ring: Sequence[PublicKey], pk: PublicKey) -> int:
    """Return the 1-indexed position of ``pk`` in ``ring``, or raise."""
    for idx, member in enumerate(ring, start=1):
        if member.point.raw == pk.point.raw:
            return idx
    raise ValueError("signer's public key is not in the supplied ring")


def _challenge(
    issue: bytes,
    ring_bytes: bytes,
    A0: Point,
    A1: Point,
    a_list: Sequence[Point],
    b_list: Sequence[Point],
) -> Scalar:
    """H2 transcript: issue || ring || A0 || A1 || a_1..a_n || b_1..b_n."""
    transcript = b"".join(
        [
            issue,
            ring_bytes,
            A0.raw,
            A1.raw,
            encode_points(a_list),
            encode_points(b_list),
        ]
    )
    return hash_to_scalar(transcript, DST_H2)


# --------------------------------------------------------------------------- #
# Sign                                                                        #
# --------------------------------------------------------------------------- #


def sign(
    sk: SecretKey,
    pk: PublicKey,
    issue: bytes,
    message: bytes,
    ring: Sequence[PublicKey],
) -> Signature:
    """
    Produce a ring signature on ``message`` under ``issue``.

    The signer's own public key must appear in ``ring`` (we look it up rather
    than trust a caller-supplied index, to remove a bug surface). All other
    ring members may be arbitrary public keys; their secrets are unknown.

    The ``issue`` argument is the per-election tag from the paper: tracing
    works across signatures sharing the same ``(issue, ring)``.
    """
    _check_ring(ring)
    position = _find_position(ring, pk)
    n = len(ring)

    ring_bytes = _ring_bytes(ring)
    h = hash_to_group(issue + ring_bytes, DST_H0)
    A0 = hash_to_group(issue + ring_bytes + message, DST_H1)

    # The trace tag: σ_i = h^{x_i}. Deterministic in (issue, ring, signer).
    sigma_i = h.scalar_mul(sk.x)

    # A_1 = (σ_i − A_0) · (1/position)  in the prime-order group.
    inv_pos = Scalar.from_int(position).invert()
    A1 = (sigma_i - A0).scalar_mul(inv_pos)

    # σ_j for j ≠ position is computed via the same recurrence:
    #   σ_j = A_0 + j · A_1.
    sigmas: List[Point] = []
    for j in range(1, n + 1):
        if j == position:
            sigmas.append(sigma_i)
        else:
            sigmas.append(A0 + A1.scalar_mul(Scalar.from_int(j)))

    a_list: List[Point] = [None] * n  # type: ignore[list-item]
    b_list: List[Point] = [None] * n  # type: ignore[list-item]
    c_list: List[Scalar] = [Scalar.from_int(0)] * n
    z_list: List[Scalar] = [Scalar.from_int(0)] * n

    # Random "ephemeral" witness for the signer's slot.
    w = Scalar.random()
    a_list[position - 1] = base_mul(w)
    b_list[position - 1] = h.scalar_mul(w)

    # Simulate the proofs for every other slot.
    for j in range(1, n + 1):
        if j == position:
            continue
        c_j = Scalar.random()
        z_j = Scalar.random()
        c_list[j - 1] = c_j
        z_list[j - 1] = z_j
        # a_j = g^{z_j} + pk_j · c_j  ;  b_j = h^{z_j} + σ_j · c_j
        a_list[j - 1] = base_mul(z_j) + ring[j - 1].point.scalar_mul(c_j)
        b_list[j - 1] = h.scalar_mul(z_j) + sigmas[j - 1].scalar_mul(c_j)

    c_total = _challenge(issue, ring_bytes, A0, A1, a_list, b_list)

    # c_i = c_total - Σ_{j ≠ i} c_j  (mod q)
    sum_other = Scalar.from_int(0)
    for j in range(1, n + 1):
        if j == position:
            continue
        sum_other = sum_other + c_list[j - 1]
    c_i = c_total - sum_other
    c_list[position - 1] = c_i

    # z_i = w - c_i · x_i  (mod q)
    z_list[position - 1] = w - (c_i * sk.x)

    return Signature(A1=A1, c=c_list, z=z_list)


# --------------------------------------------------------------------------- #
# Verify                                                                      #
# --------------------------------------------------------------------------- #


def verify(
    sig: Signature,
    issue: bytes,
    message: bytes,
    ring: Sequence[PublicKey],
) -> bool:
    """Return ``True`` iff ``sig`` is a valid OTRS signature."""
    _check_ring(ring)
    n = len(ring)
    if len(sig.c) != n or len(sig.z) != n:
        return False

    ring_bytes = _ring_bytes(ring)
    h = hash_to_group(issue + ring_bytes, DST_H0)
    A0 = hash_to_group(issue + ring_bytes + message, DST_H1)

    # Reconstruct (σ_j, a_j, b_j) and check the global challenge equation.
    a_list: List[Point] = []
    b_list: List[Point] = []
    for j in range(1, n + 1):
        sigma_j = A0 + sig.A1.scalar_mul(Scalar.from_int(j))
        a_j = base_mul(sig.z[j - 1]) + ring[j - 1].point.scalar_mul(sig.c[j - 1])
        b_j = h.scalar_mul(sig.z[j - 1]) + sigma_j.scalar_mul(sig.c[j - 1])
        a_list.append(a_j)
        b_list.append(b_j)

    expected = _challenge(issue, ring_bytes, A0, sig.A1, a_list, b_list)
    got = Scalar.from_int(0)
    for c_j in sig.c:
        got = got + c_j
    return got.raw == expected.raw  # canonical encoding → constant-time-ish equality


# --------------------------------------------------------------------------- #
# Trace                                                                       #
# --------------------------------------------------------------------------- #


def _sigma_columns(
    A1: Point, A0: Point, n: int
) -> List[Point]:
    return [A0 + A1.scalar_mul(Scalar.from_int(j)) for j in range(1, n + 1)]


def trace(
    issue: bytes,
    ring: Sequence[PublicKey],
    m1: bytes,
    sig1: Signature,
    m2: bytes,
    sig2: Signature,
) -> TraceResult:
    """
    Compare two signatures on the same ``(issue, ring)`` and classify them.

    Tracing assumes ``verify`` returned ``True`` on both inputs — we don't
    re-verify here so that callers can choose to amortise that cost — but the
    result on unverified inputs is undefined.

    .. note::
       For the degenerate ring of size ``n = 1``, the "all columns match" and
       "exactly one column matches" cases coincide; the function returns
       ``status="linked"`` even for distinct messages by the lone signer.
       Anonymity is undefined for ``n = 1`` regardless, so callers should
       require ``n ≥ 2`` for any realistic voting use.
    """
    _check_ring(ring)
    n = len(ring)
    ring_bytes = _ring_bytes(ring)

    A0_1 = hash_to_group(issue + ring_bytes + m1, DST_H1)
    A0_2 = hash_to_group(issue + ring_bytes + m2, DST_H1)

    col1 = _sigma_columns(sig1.A1, A0_1, n)
    col2 = _sigma_columns(sig2.A1, A0_2, n)

    matches = [j for j in range(n) if col1[j].raw == col2[j].raw]

    if len(matches) == n:
        return TraceResult(status="linked")
    if len(matches) == 1:
        idx = matches[0]
        return TraceResult(
            status="double-sign",
            culprit_index=idx + 1,  # 1-indexed for paper-consistency
            culprit_pk=ring[idx],
        )
    return TraceResult(status="independent")
