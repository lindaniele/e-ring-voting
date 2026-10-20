"""
Grouping signed messages by signer, following the FS07 trace rule.

Every signature under a tag ``(issue, ring)`` carries one *column* per ring
position, ``σ_j = A0 + j·A1``; column ``j`` equals ``h^{x_j}`` exactly when
the signer sits at position ``j``. Two signatures by the same signer
therefore share a column, and two signatures by different signers share
none (except with negligible probability). FS07 then distinguishes:

* same message, every column shared → **linked**: one signer, one message.
  A copy of a ballot replayed from the public log is the typical case. It
  counts once and the signer stays anonymous.
* different messages, a column shared → **double-sign**: the shared
  column's position is the signer. Both messages are void and the key is
  exposed.

:class:`TagBook` keeps the messages of one tag indexed by column, so a
validator can decide on arrival whether a message is new, a replay, or the
evidence that exposes a double-signer, and an auditor can classify the
whole book at the end. A component of messages connected by shared
columns is one signer; the signer's position is only *known* if that
signer double-signed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from trs import PublicKey, Signature
from trs.group import Scalar
from trs.hash import hash_to_group
from trs.serialize import encode_ring
from trs.trs import DST_H1

# Admission outcomes of TagBook.admit().
FRESH = "fresh"              # first message from this signer
EVIDENCE = "double-sign"     # second, different message: exposes the signer
REPLAY = "replay"            # same signer, same message as before
SATURATED = "saturated"      # signer already exposed; nothing more to learn


def sigma_columns(
    issue: bytes, ring_bytes: bytes, message: bytes, sig: Signature
) -> List[bytes]:
    """The trace columns σ_1..σ_n of ``sig`` (encoded points)."""
    A0 = hash_to_group(issue + ring_bytes + message, DST_H1)
    return [
        (A0 + sig.A1.scalar_mul(Scalar.from_int(j))).raw
        for j in range(1, len(sig.c) + 1)
    ]


@dataclass(frozen=True)
class Classification:
    """Outcome of classifying a :class:`TagBook` (indices are book order)."""

    accepted: List[int]       # one item per honest signer
    linked: List[int]         # further copies of an accepted item
    rejected: List[int]       # every item of a double-signer
    culprits: List[int]       # 0-based ring positions of double-signers


@dataclass
class TagBook:
    """Signed messages under one tag ``(issue, ring)``, indexed by column."""

    issue: bytes
    ring: List[PublicKey]
    ring_bytes: bytes = b""
    messages: List[bytes] = field(default_factory=list)
    refs: List[object] = field(default_factory=list)
    _buckets: Dict[Tuple[int, bytes], List[int]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.ring_bytes:
            self.ring_bytes = encode_ring([pk.point for pk in self.ring])

    def copy(self) -> "TagBook":
        return TagBook(
            issue=self.issue,
            ring=self.ring,
            ring_bytes=self.ring_bytes,
            messages=list(self.messages),
            refs=list(self.refs),
            _buckets={k: list(v) for k, v in self._buckets.items()},
        )

    def __len__(self) -> int:
        return len(self.messages)

    def _same_signer(self, cols: Sequence[bytes]) -> List[int]:
        found: set[int] = set()
        for j, col in enumerate(cols):
            found.update(self._buckets.get((j, col), ()))
        return sorted(found)

    def admit(self, message: bytes, sig: Signature, ref: object = None) -> str:
        """
        Record ``(message, sig)`` unless it adds nothing; return the outcome.

        The signature must already have been verified against this tag.
        Replays and messages from an already exposed signer are *not*
        recorded, which bounds every signer to at most two entries.
        """
        cols = sigma_columns(self.issue, self.ring_bytes, message, sig)
        earlier = self._same_signer(cols)
        if any(self.messages[i] == message for i in earlier):
            return REPLAY
        if len(earlier) >= 2:
            return SATURATED
        self._record(message, cols, ref)
        return EVIDENCE if earlier else FRESH

    def _record(self, message: bytes, cols: Sequence[bytes], ref: object) -> None:
        idx = len(self.messages)
        self.messages.append(message)
        self.refs.append(ref)
        for j, col in enumerate(cols):
            self._buckets.setdefault((j, col), []).append(idx)

    def classify(self) -> Classification:
        """Split the recorded messages into honest signers and double-signers."""
        parent = list(range(len(self.messages)))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        for members in self._buckets.values():
            for other in members[1:]:
                parent[find(other)] = find(members[0])

        components: Dict[int, List[int]] = {}
        for i in range(len(self.messages)):
            components.setdefault(find(i), []).append(i)

        accepted: List[int] = []
        linked: List[int] = []
        rejected: List[int] = []
        for members in components.values():
            if len({self.messages[i] for i in members}) == 1:
                accepted.append(members[0])
                linked.extend(members[1:])
            else:
                rejected.extend(members)
        # A column shared by different messages is a double-signer's tag.
        culprits = {
            j
            for (j, _), bucket in self._buckets.items()
            if len({self.messages[i] for i in bucket}) > 1
        }
        return Classification(
            accepted=sorted(accepted),
            linked=sorted(linked),
            rejected=sorted(rejected),
            culprits=sorted(culprits),
        )


def classify_messages(
    issue: bytes,
    ring: Sequence[PublicKey],
    items: Sequence[Tuple[bytes, Signature]],
) -> Classification:
    """
    Classify a list of already verified ``(message, signature)`` pairs.

    Unlike :meth:`TagBook.admit`, nothing is dropped: replays land in
    ``linked`` and a double-signer's extra messages in ``rejected``, so the
    returned indices refer to ``items`` one-to-one.
    """
    book = TagBook(issue=issue, ring=list(ring))
    for message, sig in items:
        book._record(message, sigma_columns(book.issue, book.ring_bytes, message, sig), None)
    return book.classify()
