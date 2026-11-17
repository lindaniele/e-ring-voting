"""Classification of a group's messages with the OTRS trace (voting/tally.py)."""

from __future__ import annotations

import pytest

from otrs import Ring, keygen
from voting.tally import (
    EVIDENCE,
    EXHAUSTED,
    FRESH,
    REPLAY,
    SATURATED,
    TagBook,
    classify_messages,
)

CTX = b"poll/round-0"


@pytest.fixture
def group():
    kps = [keygen() for _ in range(5)]
    return kps, Ring([kp.pk for kp in kps])


def signed(ring, kp, msg, **kw):
    return msg, ring.sign(kp, msg, CTX, **kw)


def admit(book, ring, kp, msg, **kw):
    m, sig = signed(ring, kp, msg, **kw)
    return book.admit(m, sig, ring.check(sig, m, CTX))


class TestClassify:
    def test_honest_signers_all_accepted(self, group):
        kps, ring = group
        v = classify_messages(ring, [signed(ring, kp, b"yes") for kp in kps])
        assert v.accepted == [0, 1, 2, 3, 4] and v.rejected == [] and v.culprits == []

    def test_copies_frame_nobody(self, group):
        kps, ring = group
        a, b = signed(ring, kps[2], b"yes"), signed(ring, kps[3], b"no")
        v = classify_messages(ring, [a, b, a, b])
        assert v.accepted == [0, 1] and v.copies == [2, 3]
        assert v.rejected == [] and v.culprits == []

    def test_double_vote_exposes_the_key(self, group):
        kps, ring = group
        items = [signed(ring, kps[1], b"yes"), signed(ring, kps[1], b"no"),
                 signed(ring, kps[4], b"no")]
        v = classify_messages(ring, items)
        assert v.accepted == [2] and v.rejected == [0, 1] and v.culprits == [1]

    def test_same_message_twice_is_a_double_vote(self, group):
        kps, ring = group
        items = [signed(ring, kps[0], b"yes", randomized=True),
                 signed(ring, kps[0], b"yes", randomized=True)]
        v = classify_messages(ring, items)
        assert v.rejected == [0, 1] and v.culprits == [0]

    def test_copy_of_a_traced_signature_is_void_too(self, group):
        kps, ring = group
        y, n = signed(ring, kps[0], b"yes"), signed(ring, kps[0], b"no")
        v = classify_messages(ring, [y, y, n])
        assert v.rejected == [0, 1, 2] and v.copies == [] and v.culprits == [0]


class TestTagBookAdmission:
    def test_outcomes(self, group):
        kps, ring = group
        book = TagBook(ring=ring)
        assert admit(book, ring, kps[0], b"a") == FRESH
        assert admit(book, ring, kps[0], b"a") == REPLAY        # deterministic copy
        assert admit(book, ring, kps[0], b"b") == EVIDENCE
        assert admit(book, ring, kps[0], b"c") == SATURATED
        assert admit(book, ring, kps[1], b"c") == FRESH
        assert len(book) == 3
        v = book.classify()
        assert v.culprits == [0] and v.accepted == [2] and v.rejected == [0, 1]

    def test_never_more_untraced_signatures_than_keys(self, group):
        kps, ring = group
        book = TagBook(ring=ring)
        for kp in kps:
            assert admit(book, ring, kp, b"yes") == FRESH
        # A sixth untraced signature from five keys would contradict public
        # traceability; a real one is evidence against some key instead.
        assert admit(book, ring, kps[3], b"no") == EVIDENCE
        assert book.untraced() == 4

    def test_exhausted_guard(self, group):
        kps, ring = group
        book = TagBook(ring=ring)
        for kp in kps:
            admit(book, ring, kp, b"yes")
        # Simulate the impossible case with a signature from another ring
        # member set that happens not to trace (a foreign, fresh key).
        other = [keygen() for _ in range(5)]
        foreign = Ring([kp.pk for kp in other])
        m, sig = b"yes", foreign.sign(other[0], b"yes", CTX)
        assert book.admit(m, sig, foreign.check(sig, m, CTX)) == EXHAUSTED

    def test_copy_is_independent(self, group):
        kps, ring = group
        book = TagBook(ring=ring)
        admit(book, ring, kps[0], b"a")
        clone = book.copy()
        admit(clone, ring, kps[1], b"a")
        assert len(book) == 1 and len(clone) == 2
