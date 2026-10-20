"""FS07 classification of signed messages (voting/tally.py)."""

from __future__ import annotations

import pytest

from trs import keygen, sign
from voting.tally import (
    EVIDENCE,
    FRESH,
    REPLAY,
    SATURATED,
    TagBook,
    classify_messages,
)

ISSUE = b"poll"


@pytest.fixture
def ring():
    kps = [keygen() for _ in range(5)]
    return kps, [kp.pk for kp in kps]


def signed(kp, ring, msg):
    return msg, sign(kp.sk, kp.pk, ISSUE, msg, ring)


class TestClassify:
    def test_honest_signers_all_accepted(self, ring):
        kps, pks = ring
        items = [signed(kp, pks, b"yes") for kp in kps]
        v = classify_messages(ISSUE, pks, items)
        assert v.accepted == [0, 1, 2, 3, 4] and v.rejected == [] and v.culprits == []

    def test_replays_of_two_voters_do_not_frame_anyone(self, ring):
        # Regression for the old bucketing: copies of two honest ballots with
        # different choices voided both and accused ring position 1.
        kps, pks = ring
        a, b = signed(kps[2], pks, b"yes"), signed(kps[3], pks, b"no")
        v = classify_messages(ISSUE, pks, [a, b, a, b])
        assert v.accepted == [0, 1]
        assert v.linked == [2, 3]
        assert v.rejected == [] and v.culprits == []

    def test_double_sign_exposes_the_position(self, ring):
        kps, pks = ring
        items = [signed(kps[1], pks, b"yes"), signed(kps[1], pks, b"no"),
                 signed(kps[4], pks, b"no")]
        v = classify_messages(ISSUE, pks, items)
        assert v.accepted == [2]
        assert v.rejected == [0, 1]
        assert v.culprits == [1]

    def test_replay_plus_double_sign(self, ring):
        kps, pks = ring
        y = signed(kps[0], pks, b"yes")
        n = signed(kps[0], pks, b"no")
        v = classify_messages(ISSUE, pks, [y, y, n])
        assert v.rejected == [0, 1, 2] and v.culprits == [0]

    def test_singleton_ring(self):
        kp = keygen()
        pks = [kp.pk]
        v = classify_messages(ISSUE, pks, [signed(kp, pks, b"a"), signed(kp, pks, b"b")])
        assert v.culprits == [0]
        v = classify_messages(ISSUE, pks, [signed(kp, pks, b"a"), signed(kp, pks, b"a")])
        assert v.accepted == [0] and v.linked == [1]


class TestTagBookAdmission:
    def test_outcomes(self, ring):
        kps, pks = ring
        book = TagBook(issue=ISSUE, ring=pks)
        assert book.admit(*signed(kps[0], pks, b"a")) == FRESH
        assert book.admit(*signed(kps[0], pks, b"a")) == REPLAY
        assert book.admit(*signed(kps[0], pks, b"b")) == EVIDENCE
        assert book.admit(*signed(kps[0], pks, b"c")) == SATURATED
        assert book.admit(*signed(kps[1], pks, b"c")) == FRESH
        assert len(book) == 3
        v = book.classify()
        assert v.culprits == [0] and v.accepted == [2]

    def test_copy_is_independent(self, ring):
        kps, pks = ring
        book = TagBook(issue=ISSUE, ring=pks)
        book.admit(*signed(kps[0], pks, b"a"))
        clone = book.copy()
        clone.admit(*signed(kps[1], pks, b"a"))
        assert len(book) == 1 and len(clone) == 2
