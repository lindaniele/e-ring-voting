"""End-to-end integration tests for the voting system."""

from __future__ import annotations

import time
from base64 import b64decode, b64encode
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from voting import auditor as auditor_mod
from voting import manager as mgr
from voting import voter as vt
from voting.records import (
    Ballot,
    ElectionSetup,
    RecordError,
    RingPublication,
    TallyPublication,
    VoterRegistration,
    parse_payload,
)


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture
def now():
    return int(time.time())


@pytest.fixture
def cohort():
    """Trivial 1-of-1 cohort — the v0.2 single-manager model."""
    return mgr.generate_cohort(n=1, threshold=1)


@pytest.fixture
def log_path(tmp_path):
    return tmp_path / "election.jsonl"


def _open_election(
    log_path, cohort, *, options=("yes", "no"), now: int, title="Test"
):
    return mgr.setup_election(
        log_path=log_path,
        cohort=cohort,
        title=title,
        description="demo",
        options=list(options),
        registration_close=now - 120,
        voting_open=now - 60,
        voting_close=now + 86400,
    )


def _register_n_voters(log_path, cohort, n: int):
    voters = [vt.new_keypair() for _ in range(n)]
    for i, kp in enumerate(voters):
        mgr.register_voter(
            log_path=log_path,
            cohort=cohort,
            voter_pk=kp.pk.point.raw,
            voter_handle=f"voter-{i}",
        )
    return voters


# --------------------------------------------------------------------------- #
# Happy path                                                                  #
# --------------------------------------------------------------------------- #


class TestHappyPath:
    def test_full_election_audits_correctly(self, log_path, cohort, now):
        _open_election(log_path, cohort, now=now)
        voters = _register_n_voters(log_path, cohort, 5)
        mgr.publish_ring(log_path=log_path, cohort=cohort)
        ctx = vt.load_voting_context(log_path)

        for kp, choice in zip(voters[:3], ["yes", "yes", "no"]):
            b = vt.cast_ballot(voter=kp, context=ctx, choice=choice)
            mgr.publish_ballot(log_path=log_path, cohort=cohort, ballot=b)
        mgr.close_voting(log_path=log_path, cohort=cohort)

        report = auditor_mod.audit(log_path=log_path)
        assert report.tally == {"yes": 2, "no": 1}
        assert report.rejected_ballot_indices == []
        assert report.double_sign_culprits == []
        assert len(report.accepted_ballot_indices) == 3

    def test_manager_can_publish_tally(self, log_path, cohort, now):
        _open_election(log_path, cohort, now=now)
        voters = _register_n_voters(log_path, cohort, 4)
        mgr.publish_ring(log_path=log_path, cohort=cohort)
        ctx = vt.load_voting_context(log_path)
        for kp in voters[:2]:
            b = vt.cast_ballot(voter=kp, context=ctx, choice="yes")
            mgr.publish_ballot(log_path=log_path, cohort=cohort, ballot=b)
        mgr.close_voting(log_path=log_path, cohort=cohort)
        rep = auditor_mod.audit(log_path=log_path)
        mgr.publish_tally(
            log_path=log_path, cohort=cohort,
            tally=auditor_mod.build_tally_record(rep),
        )
        rep2 = auditor_mod.audit(log_path=log_path)
        assert rep2.claimed_tally is not None
        assert rep2.tally_matches_claim()


# --------------------------------------------------------------------------- #
# Double-sign                                                                 #
# --------------------------------------------------------------------------- #


class TestDoubleSign:
    def test_double_sign_excludes_both_ballots(self, log_path, cohort, now):
        _open_election(log_path, cohort, now=now, options=("a", "b"))
        voters = _register_n_voters(log_path, cohort, 5)
        mgr.publish_ring(log_path=log_path, cohort=cohort)
        ctx = vt.load_voting_context(log_path)
        for choice in ["a", "b"]:
            b = vt.cast_ballot(voter=voters[0], context=ctx, choice=choice)
            mgr.publish_ballot(log_path=log_path, cohort=cohort, ballot=b)
        b = vt.cast_ballot(voter=voters[1], context=ctx, choice="a")
        mgr.publish_ballot(log_path=log_path, cohort=cohort, ballot=b)
        mgr.close_voting(log_path=log_path, cohort=cohort)

        report = auditor_mod.audit(log_path=log_path)
        assert report.tally == {"a": 1, "b": 0}
        assert len(report.rejected_ballot_indices) == 2
        assert all(r == "double-sign" for _, r in report.rejected_ballot_indices)
        assert len(report.double_sign_culprits) == 1
        assert report.double_sign_culprits[0].point.raw == voters[0].pk.point.raw

    def test_linked_same_message_counts_once(self, log_path, cohort, now):
        _open_election(log_path, cohort, now=now)
        voters = _register_n_voters(log_path, cohort, 3)
        mgr.publish_ring(log_path=log_path, cohort=cohort)
        ctx = vt.load_voting_context(log_path)
        for _ in range(2):
            b = vt.cast_ballot(voter=voters[0], context=ctx, choice="yes")
            mgr.publish_ballot(log_path=log_path, cohort=cohort, ballot=b)
        mgr.close_voting(log_path=log_path, cohort=cohort)
        report = auditor_mod.audit(log_path=log_path)
        assert report.tally == {"yes": 1, "no": 0}
        assert report.double_sign_culprits == []


# --------------------------------------------------------------------------- #
# Adversarial                                                                 #
# --------------------------------------------------------------------------- #


class TestAdversaries:
    def test_voter_outside_ring_cannot_sign_passing_ballot(
        self, log_path, cohort, now
    ):
        _open_election(log_path, cohort, now=now)
        _register_n_voters(log_path, cohort, 3)
        mgr.publish_ring(log_path=log_path, cohort=cohort)
        ctx = vt.load_voting_context(log_path)

        outsider = vt.new_keypair()
        with pytest.raises(ValueError, match="not a member of the published ring"):
            vt.cast_ballot(voter=outsider, context=ctx, choice="yes")

    def test_invalid_choice_rejected_at_cast(self, log_path, cohort, now):
        _open_election(log_path, cohort, now=now)
        voters = _register_n_voters(log_path, cohort, 2)
        mgr.publish_ring(log_path=log_path, cohort=cohort)
        ctx = vt.load_voting_context(log_path)
        with pytest.raises(ValueError, match="not in election options"):
            vt.cast_ballot(voter=voters[0], context=ctx, choice="banana")

    def test_audit_rejects_tampered_ballot_signature(self, log_path, cohort, now):
        _open_election(log_path, cohort, now=now)
        voters = _register_n_voters(log_path, cohort, 3)
        mgr.publish_ring(log_path=log_path, cohort=cohort)
        ctx = vt.load_voting_context(log_path)
        good_ballot = vt.cast_ballot(voter=voters[0], context=ctx, choice="yes")
        raw = bytearray(b64decode(good_ballot.otrs_sig_b64))
        raw[10] ^= 0xFF
        tampered = Ballot(choice="yes", otrs_sig_b64=b64encode(bytes(raw)).decode())
        mgr.publish_ballot(log_path=log_path, cohort=cohort, ballot=tampered)
        mgr.close_voting(log_path=log_path, cohort=cohort)
        with pytest.raises(auditor_mod.AuditError):
            auditor_mod.audit(log_path=log_path)

    def test_audit_rejects_extra_record_after_tally(self, log_path, cohort, now):
        _open_election(log_path, cohort, now=now)
        voters = _register_n_voters(log_path, cohort, 2)
        mgr.publish_ring(log_path=log_path, cohort=cohort)
        ctx = vt.load_voting_context(log_path)
        b = vt.cast_ballot(voter=voters[0], context=ctx, choice="yes")
        mgr.publish_ballot(log_path=log_path, cohort=cohort, ballot=b)
        mgr.close_voting(log_path=log_path, cohort=cohort)
        rep = auditor_mod.audit(log_path=log_path)
        mgr.publish_tally(
            log_path=log_path, cohort=cohort,
            tally=auditor_mod.build_tally_record(rep),
        )
        # Manually stuff an extra tally entry.
        from voting.log import BulletinBoard
        BulletinBoard(log_path).append(
            TallyPublication(tally={"yes": 999, "no": 0}).to_payload(),
            cohort.sks[: cohort.threshold],
            cohort.as_publisher_cohort(),
        )
        with pytest.raises(auditor_mod.AuditError, match="extra record after"):
            auditor_mod.audit(log_path=log_path)

    def test_audit_rejects_log_signed_by_wrong_cohort(self, log_path, cohort, now):
        """
        If someone tampered with the cohort_pks in the setup record, the
        auditor would derive a different cohort and the signatures would
        fail to verify under it. We simulate by replacing the log's setup
        with a forged one whose cohort_pks_b64 are wrong.
        """
        _open_election(log_path, cohort, now=now)
        _register_n_voters(log_path, cohort, 2)
        # Manually corrupt the cohort pks claim in entry 0.
        # The forged setup would have different bytes and so the entry's
        # publisher sig would no longer match. Easiest demonstration: just
        # change a byte in entry 0's payload (which contains cohort_pks_b64)
        # on disk and re-run audit.
        lines = log_path.read_text().splitlines()
        # Flip one byte in the first line's payload field — base64 char.
        ln = lines[0]
        # find `"payload":"..."` and corrupt it slightly
        head, _, rest = ln.partition('"payload":"')
        payload_b64, _, tail = rest.partition('"')
        # Change a single char of the base64.
        bad_payload = payload_b64[:5] + ("A" if payload_b64[5] != "A" else "B") + payload_b64[6:]
        lines[0] = head + '"payload":"' + bad_payload + '"' + tail
        log_path.write_text("\n".join(lines) + "\n")
        with pytest.raises(auditor_mod.AuditError):
            auditor_mod.audit(log_path=log_path)
