"""
Classifying the messages signed inside one group, by OTRS trace.

Scafuro–Zhang trace two *distinct* signatures made with the same key,
whatever they sign and under whatever context. Inside a group of a round
that gives three cases:

* a byte-identical copy of a recorded signature is a **replay**: anybody
  can copy a ballot off the chain, and a copy is not a second use of the
  key. It is refused and blames nobody. (Honest signing is deterministic,
  so a voter who re-sends its ballot also produces a copy.)
* a signature that traces against a recorded one is **evidence**: the
  keys it traces to signed twice. Every message involved is void and the
  keys are the group's *culprits*.
* anything else is one use of one key: it counts.

FS07, the scheme the 2021–22 prototype used, distinguishes a fourth case:
two signatures by one key on the *same* message are only "linked" and the
signer stays anonymous. Here there is no such case. Signing the same
ballot twice with fresh randomness exposes the key like any double vote.

:class:`TagBook` keeps every recorded signature's openings (``G(r)`` of
every seed, computed anyway by verification), so admitting a signature
costs one big-integer XOR per recorded signature and no hashing.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set, Tuple

from otrs import Openings, Ring, Signature

# Admission outcomes of TagBook.admit().
FRESH = "fresh"            # first use of a key: recorded, counts
EVIDENCE = "evidence"      # second use of some key: recorded, exposes it
REPLAY = "replay"          # byte-identical copy of a recorded signature
SATURATED = "saturated"    # traces only keys already exposed: nothing to learn
EXHAUSTED = "exhausted"    # would be the (N+1)-th untraced signature of N keys


@dataclass(frozen=True)
class Classification:
    """Outcome of classifying a group's messages (indices in input order)."""

    accepted: List[int]       # untraced: one use of one key each
    rejected: List[int]       # involved in a trace
    culprits: List[int]       # ring positions of the keys traced
    copies: List[int] = field(default_factory=list)  # duplicates of an earlier item


@dataclass
class TagBook:
    """The signed messages of one group in one round."""

    ring: Ring
    messages: List[bytes] = field(default_factory=list)
    refs: List[object] = field(default_factory=list)
    openings: List[Openings] = field(default_factory=list)
    digests: Set[bytes] = field(default_factory=set)
    traced: Set[int] = field(default_factory=set)     # record indices
    culprits: Set[int] = field(default_factory=set)   # ring positions

    def copy(self) -> "TagBook":
        return TagBook(
            ring=self.ring,
            messages=list(self.messages),
            refs=list(self.refs),
            openings=list(self.openings),
            digests=set(self.digests),
            traced=set(self.traced),
            culprits=set(self.culprits),
        )

    def __len__(self) -> int:
        return len(self.messages)

    def untraced(self) -> int:
        return len(self.messages) - len(self.traced)

    def admit(
        self,
        message: bytes,
        sig: Signature,
        openings: Openings,
        ref: object = None,
    ) -> str:
        """
        Record a verified ``(message, sig)`` unless it adds nothing.

        ``openings`` must be what :meth:`otrs.Ring.check` returned for
        ``sig`` on this book's ring. Refused outcomes leave the book
        unchanged. A group of ``N`` keys therefore holds at most ``N``
        untraced signatures and at most ``N`` pieces of evidence.
        """
        digest = hashlib.sha256(sig.to_bytes()).digest()
        if digest in self.digests:
            return REPLAY
        hits: List[int] = []
        traced_keys: Set[int] = set()
        for idx, other in enumerate(self.openings):
            found = self.ring.culprits(openings, other)
            if found:
                hits.append(idx)
                traced_keys.update(found)
        if hits and traced_keys <= self.culprits:
            return SATURATED
        if not hits and self.untraced() >= len(self.ring):
            # Public traceability says this cannot happen with honest keys.
            return EXHAUSTED
        idx = len(self.messages)
        self.messages.append(message)
        self.refs.append(ref)
        self.openings.append(openings)
        self.digests.add(digest)
        if hits:
            self.traced.update(hits)
            self.traced.add(idx)
            self.culprits.update(traced_keys)
            return EVIDENCE
        return FRESH

    def classify(self) -> Classification:
        rejected = sorted(self.traced)
        accepted = [i for i in range(len(self.messages)) if i not in self.traced]
        return Classification(
            accepted=accepted, rejected=rejected, culprits=sorted(self.culprits)
        )


def classify_messages(
    ring: Ring,
    items: Sequence[Tuple[bytes, Signature]],
    openings: Optional[Sequence[Openings]] = None,
) -> Classification:
    """
    Classify already verified ``(message, signature)`` pairs of one group.

    Unlike :meth:`TagBook.admit` nothing is dropped: copies land in
    ``copies`` and every signature involved in a trace in ``rejected``, so
    indices refer to ``items`` one to one.
    """
    if openings is None:
        openings = [ring.openings(sig) for _, sig in items]
    first: dict[bytes, int] = {}
    copies: List[int] = []
    distinct: List[int] = []
    for i, (_, sig) in enumerate(items):
        d = hashlib.sha256(sig.to_bytes()).digest()
        if d in first:
            copies.append(i)
        else:
            first[d] = i
            distinct.append(i)
    traced: Set[int] = set()
    culprits: Set[int] = set()
    for a_pos, a in enumerate(distinct):
        for b in distinct[a_pos + 1:]:
            found = ring.culprits(openings[a], openings[b])
            if found:
                traced.update((a, b))
                culprits.update(found)
    # A copy shares the fate of the signature it copies.
    for c in copies:
        if first[hashlib.sha256(items[c][1].to_bytes()).digest()] in traced:
            traced.add(c)
    copies = [c for c in copies if c not in traced]
    return Classification(
        accepted=[i for i in distinct if i not in traced],
        rejected=sorted(traced),
        culprits=sorted(culprits),
        copies=copies,
    )
