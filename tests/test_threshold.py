"""Threshold cohort + witness federation tests (v0.3)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from voting import auditor as auditor_mod
from voting import manager as mgr
from voting import voter as vt
from voting import witness as wit
from voting.log import (
    BulletinBoard,
    Entry,
    LogError,
    PublisherCohort,
    commit_pending,
    cosign_pending,
    propose_entry,
)


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture
def now():
    return int(time.time())


def make_cohort(n: int, t: int):
    return mgr.generate_cohort(n=n, threshold=t)


def open_election(
    log_path: Path, cohort, *, now: int, options=("yes", "no"),
    witness_pks=(), witness_threshold=0,
):
    return mgr.setup_election(
        log_path=log_path,
        cohort=cohort,
        title="Test",
        description="",
        options=list(options),
        registration_close=now - 120,
        voting_open=now - 60,
        voting_close=now + 86400,
        witness_pks=list(witness_pks),
        witness_threshold=witness_threshold,
    )


def register_n(log_path, cohort, n):
    voters = [vt.new_keypair() for _ in range(n)]
    for i, kp in enumerate(voters):
        mgr.register_voter(
            log_path=log_path,
            cohort=cohort,
            voter_pk=kp.pk.point.raw,
            voter_handle=f"v{i}",
        )
    return voters


# --------------------------------------------------------------------------- #
# Threshold append                                                            #
# --------------------------------------------------------------------------- #


class TestThresholdAppend:
    def test_2_of_3_happy_path(self, tmp_path, now):
        log_path = tmp_path / "log.jsonl"
        cohort = make_cohort(3, 2)
        open_election(log_path, cohort, now=now)
        # Setup itself appended with threshold=2 signers; verify under the cohort.
        BulletinBoard(log_path).verify(cohort.as_publisher_cohort())

    def test_log_rejects_below_threshold(self, tmp_path, now):
        log_path = tmp_path / "log.jsonl"
        cohort = make_cohort(3, 2)
        open_election(log_path, cohort, now=now)
        log = BulletinBoard(log_path)
        # Direct .append with only 1 signer should raise.
        with pytest.raises(LogError, match="need at least 2"):
            log.append(
                b"payload",
                signers=[cohort.sks[0]],
                cohort=cohort.as_publisher_cohort(),
            )

    def test_log_rejects_duplicate_signer(self, tmp_path, now):
        log_path = tmp_path / "log.jsonl"
        cohort = make_cohort(3, 2)
        open_election(log_path, cohort, now=now)
        log = BulletinBoard(log_path)
        # Same member twice — must be rejected (not "two distinct sigs").
        with pytest.raises(LogError, match="duplicate signer index"):
            log.append(
                b"payload",
                signers=[(0, cohort.sks[0][1]), (0, cohort.sks[0][1])],
                cohort=cohort.as_publisher_cohort(),
            )

    def test_log_rejects_wrong_member_sk(self, tmp_path, now):
        log_path = tmp_path / "log.jsonl"
        cohort = make_cohort(3, 2)
        open_election(log_path, cohort, now=now)
        log = BulletinBoard(log_path)
        # Member 0 signs but claims to be member 1.
        wrong = [(1, cohort.sks[0][1]), (2, cohort.sks[2][1])]
        with pytest.raises(LogError, match="does not verify"):
            log.append(b"x", signers=wrong, cohort=cohort.as_publisher_cohort())

    def test_audit_rejects_log_under_higher_threshold(self, tmp_path, now):
        # Build the log under threshold=1, then try to verify under threshold=2.
        log_path = tmp_path / "log.jsonl"
        relaxed = make_cohort(3, 1)
        open_election(log_path, relaxed, now=now)
        register_n(log_path, relaxed, 2)
        # Now verify under a *stricter* cohort. Should fail.
        strict = PublisherCohort(pks=[s.public_key() for _, s in relaxed.sks], threshold=2)
        with pytest.raises(LogError, match="distinct cohort signers"):
            BulletinBoard(log_path).verify(strict)


# --------------------------------------------------------------------------- #
# Asynchronous co-signing                                                     #
# --------------------------------------------------------------------------- #


class TestPendingCosign:
    def test_pending_round_trip(self, tmp_path, now):
        log_path = tmp_path / "log.jsonl"
        cohort = make_cohort(3, 2)
        open_election(log_path, cohort, now=now)
        # Propose a new arbitrary entry, two cohort members co-sign,
        # then commit.
        pub = cohort.as_publisher_cohort()
        propose_entry(log_path, b"deferred-payload")
        cosign_pending(log_path, 0, cohort.sks[0][1], pub)
        cosign_pending(log_path, 1, cohort.sks[1][1], pub)
        entry = commit_pending(log_path, pub)
        assert entry.payload == b"deferred-payload"
        assert len(entry.publisher_sigs) == 2
        BulletinBoard(log_path).verify(pub)

    def test_pending_refuses_commit_below_threshold(self, tmp_path, now):
        log_path = tmp_path / "log.jsonl"
        cohort = make_cohort(3, 2)
        open_election(log_path, cohort, now=now)
        pub = cohort.as_publisher_cohort()
        propose_entry(log_path, b"x")
        cosign_pending(log_path, 0, cohort.sks[0][1], pub)
        with pytest.raises(LogError, match="need ≥ 2"):
            commit_pending(log_path, pub)

    def test_pending_refuses_double_signature(self, tmp_path, now):
        log_path = tmp_path / "log.jsonl"
        cohort = make_cohort(3, 2)
        open_election(log_path, cohort, now=now)
        pub = cohort.as_publisher_cohort()
        propose_entry(log_path, b"x")
        cosign_pending(log_path, 0, cohort.sks[0][1], pub)
        with pytest.raises(LogError, match="already signed"):
            cosign_pending(log_path, 0, cohort.sks[0][1], pub)


# --------------------------------------------------------------------------- #
# Witness federation                                                          #
# --------------------------------------------------------------------------- #


class TestWitnesses:
    def _build_election_with_witnesses(self, tmp_path, now, n_witness=3, k=2):
        log_path = tmp_path / "log.jsonl"
        cohort = make_cohort(3, 2)
        w_sks = [ed25519.Ed25519PrivateKey.generate() for _ in range(n_witness)]
        w_pks = [s.public_key() for s in w_sks]
        open_election(
            log_path, cohort, now=now,
            witness_pks=w_pks, witness_threshold=k,
        )
        voters = register_n(log_path, cohort, 3)
        mgr.publish_ring(log_path=log_path, cohort=cohort)
        ctx = vt.load_voting_context(log_path)
        for kp, choice in zip(voters, ["yes", "yes", "no"]):
            b = vt.cast_ballot(voter=kp, context=ctx, choice=choice)
            mgr.publish_ballot(log_path=log_path, cohort=cohort, ballot=b)
        mgr.close_voting(log_path=log_path, cohort=cohort)
        return log_path, cohort, w_sks, w_pks

    def test_threshold_witnesses_satisfied(self, tmp_path, now):
        log_path, cohort, w_sks, w_pks = self._build_election_with_witnesses(
            tmp_path, now, n_witness=3, k=2
        )
        pub = cohort.as_publisher_cohort()
        for i in [0, 1]:
            wit.emit_checkpoint(
                log_path=log_path, cohort=pub, witness_sk=w_sks[i], witness_index=i
            )
        rep = auditor_mod.audit(log_path=log_path)
        assert rep.witness_count == 2
        assert rep.witness_cosigned_index is not None
        assert rep.tally == {"yes": 2, "no": 1}

    def test_threshold_witnesses_not_met_fails_audit(self, tmp_path, now):
        log_path, cohort, w_sks, w_pks = self._build_election_with_witnesses(
            tmp_path, now, n_witness=3, k=2
        )
        pub = cohort.as_publisher_cohort()
        # Only one witness checkpoints — threshold is 2 → audit must fail.
        wit.emit_checkpoint(
            log_path=log_path, cohort=pub, witness_sk=w_sks[0], witness_index=0
        )
        with pytest.raises(auditor_mod.AuditError, match="co-signed by"):
            auditor_mod.audit(log_path=log_path)

    def test_equivocation_detected(self, tmp_path, now):
        """
        If two witnesses sign the *same* log_index with *different* head
        hashes, the auditor must surface this as equivocation evidence.
        We simulate it by writing two checkpoints with different
        ``head_hash`` values directly into the sidecar.
        """
        log_path, cohort, w_sks, w_pks = self._build_election_with_witnesses(
            tmp_path, now, n_witness=3, k=2
        )
        pub = cohort.as_publisher_cohort()
        cp0 = wit.emit_checkpoint(
            log_path=log_path, cohort=pub, witness_sk=w_sks[0], witness_index=0
        )

        # Manually forge an "honest" checkpoint by witness 1 over a *different*
        # head hash, signing it under witness 1's real key (this models the
        # situation where witness 1 was shown a divergent log).
        bogus_hash = b"\x42" * 32
        forged = wit.Checkpoint(
            log_index=cp0.log_index,
            head_hash=bogus_hash,
            witness_index=1,
            sig=b"",  # filled below
        )
        forged_sig = w_sks[1].sign(forged.signing_preimage())
        forged = wit.Checkpoint(
            log_index=forged.log_index,
            head_hash=forged.head_hash,
            witness_index=forged.witness_index,
            sig=forged_sig,
        )
        wit_path = wit._checkpoints_path(log_path)
        with wit_path.open("a") as f:
            f.write(forged.to_json_line() + "\n")

        with pytest.raises(auditor_mod.AuditError, match="EQUIVOCATION"):
            auditor_mod.audit(log_path=log_path)

    def test_forged_witness_sig_rejected(self, tmp_path, now):
        # A checkpoint whose signature is structurally well-formed but does
        # not verify under the claimed witness key must fail audit.
        log_path, cohort, w_sks, w_pks = self._build_election_with_witnesses(
            tmp_path, now, n_witness=3, k=1
        )
        # Witness 0 signs a checkpoint *for a different (head) log* — i.e.
        # the sig is over a different preimage, so it won't verify against
        # the actual head_hash field.
        log_entries = BulletinBoard(log_path).read_all()
        head = log_entries[-1]
        # Sig over WRONG head hash:
        bogus = wit.Checkpoint(
            log_index=head.index,
            head_hash=head.hash(),  # the claim
            witness_index=0,
            sig=w_sks[0].sign(  # signature over a DIFFERENT preimage
                wit.Checkpoint(
                    log_index=head.index,
                    head_hash=b"\x00" * 32,
                    witness_index=0,
                    sig=b"",
                ).signing_preimage()
            ),
        )
        wit_path = wit._checkpoints_path(log_path)
        with wit_path.open("a") as f:
            f.write(bogus.to_json_line() + "\n")
        with pytest.raises(auditor_mod.AuditError, match="invalid signature"):
            auditor_mod.audit(log_path=log_path)
