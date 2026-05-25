"""
Public-auditor API (v0.3).

Anyone with the bulletin board, the publisher cohort's public keys, and
(optionally) the witness federation's public keys can audit. The auditor
performs five kinds of check, in order:

1. **Log integrity.** The chain hashes, indices, threshold-many cohort
   signatures, and timestamps are well-formed (delegated to
   :meth:`BulletinBoard.verify`).
2. **State machine.** Records appear in the legal order
   ``Setup → Registration* → Ring → Ballot* → Closed → Tally?``.
3. **Per-record validity.** OTRS signatures verify against the published
   ring; the ring exactly matches the multiset of attested registrations;
   ballot choices are in the option set.
4. **Witness federation (optional).** If the setup declares witnesses,
   their checkpoints are verified; any equivocation evidence is fatal;
   the configured ``witness_threshold`` must be met at some index.
5. **Tally.** Compute the canonical tally from the ballots (handling
   double-signs via OTRS trace) and, if a :class:`TallyPublication` is
   present, compare it against the manager cohort's claim.
"""

from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from otrs import PublicKey, Signature, verify
from otrs.group import Scalar
from otrs.hash import hash_to_group
from otrs.otrs import DST_H1
from otrs.serialize import encode_ring
from voting.log import BulletinBoard, LogError, PublisherCohort, pk_from_raw
from voting.records import (
    Ballot,
    ElectionSetup,
    RecordError,
    RingPublication,
    TallyPublication,
    VoterRegistration,
    VotingClosed,
    parse_payload,
)


def _parse_payload_or_audit_error(payload: bytes, entry_index: int):
    """Wrap RecordError so the auditor surfaces a single error type."""
    try:
        return parse_payload(payload)
    except RecordError as exc:
        raise AuditError(f"entry {entry_index}: malformed record ({exc})") from exc
from voting.witness import (
    Checkpoint,
    latest_cosigned_index,
    read_checkpoints,
    verify_checkpoints,
)


class AuditError(Exception):
    """Raised by :func:`audit` on the first detected inconsistency."""


# --------------------------------------------------------------------------- #
# Report                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AuditReport:
    setup: ElectionSetup
    ring: List[PublicKey]
    tally: Dict[str, int]
    accepted_ballot_indices: List[int]
    rejected_ballot_indices: List[Tuple[int, str]] = field(default_factory=list)
    double_sign_culprits: List[PublicKey] = field(default_factory=list)
    claimed_tally: TallyPublication | None = None
    witness_cosigned_index: int | None = None  # latest log index with ≥k witnesses
    witness_count: int = 0  # number of valid checkpoints

    def tally_matches_claim(self) -> bool:
        if self.claimed_tally is None:
            return True
        return self.tally == self.claimed_tally.tally


# --------------------------------------------------------------------------- #
# Internals                                                                    #
# --------------------------------------------------------------------------- #


def _sigma_columns_from_sig(
    sig: Signature, message: bytes, election_id_bytes: bytes, ring_bytes: bytes
) -> List[bytes]:
    A0 = hash_to_group(election_id_bytes + ring_bytes + message, DST_H1)
    n = len(sig.c)
    return [(A0 + sig.A1.scalar_mul(Scalar.from_int(j))).raw for j in range(1, n + 1)]


def _build_cohort_from_setup(setup: ElectionSetup) -> PublisherCohort:
    pks = [pk_from_raw(b64decode(s)) for s in setup.cohort_pks_b64]
    return PublisherCohort(pks=pks, threshold=setup.threshold)


# --------------------------------------------------------------------------- #
# audit()                                                                      #
# --------------------------------------------------------------------------- #


def audit(*, log_path: Path) -> AuditReport:
    """
    Audit a bulletin board end-to-end.

    The cohort identity and witness identity are read from the
    :class:`ElectionSetup` genesis record. This means the only out-of-band
    trust the auditor needs is the channel by which they received that
    record — in practice, the cohort's keys would be published in a
    well-known repository / DNS entry / printed-on-a-poster.
    """
    log = BulletinBoard(log_path)
    entries = log.read_all()
    if not entries:
        raise AuditError("log is empty")

    # ----- 0. Genesis: bootstrap cohort identity from the log itself ----- #
    head_rec = _parse_payload_or_audit_error(entries[0].payload, entries[0].index)
    if not isinstance(head_rec, ElectionSetup):
        raise AuditError("first entry must be ElectionSetup")
    head_rec.validate()
    setup = head_rec
    cohort = _build_cohort_from_setup(setup)
    witness_pks = [pk_from_raw(b64decode(s)) for s in setup.witness_pks_b64]

    # ----- 1. log integrity ---------------------------------------------- #
    try:
        log.verify(cohort)
    except LogError as exc:
        raise AuditError(f"log integrity failed: {exc}") from exc

    # ----- 2 + 3. state machine + per-record validity -------------------- #
    state = "registration"  # entry 0 was Setup; from entry 1 onward expect Registration*
    registrations: List[VoterRegistration] = []
    ring_pks: List[PublicKey] | None = None
    ring_bytes: bytes | None = None
    ballots: List[Tuple[int, Ballot, Signature, bytes]] = []
    closed_seen = False
    claimed_tally: TallyPublication | None = None

    for entry in entries[1:]:
        rec = _parse_payload_or_audit_error(entry.payload, entry.index)

        if state == "registration":
            if isinstance(rec, VoterRegistration):
                pk_raw_v = b64decode(rec.voter_pk_b64)
                if len(pk_raw_v) != 32:
                    raise AuditError(
                        f"entry {entry.index}: voter_pk_b64 must be 32 bytes"
                    )
                try:
                    PublicKey.from_bytes(pk_raw_v)
                except ValueError as exc:
                    raise AuditError(
                        f"entry {entry.index}: voter_pk is not on the group"
                    ) from exc
                registrations.append(rec)
                continue
            if isinstance(rec, RingPublication):
                ring_raw = [b64decode(s) for s in rec.ring_b64]
                attested = {b64decode(r.voter_pk_b64) for r in registrations}
                if set(ring_raw) != attested:
                    raise AuditError(
                        f"entry {entry.index}: ring does not equal attested registrations"
                    )
                if len(ring_raw) != len(set(ring_raw)):
                    raise AuditError(
                        f"entry {entry.index}: ring contains duplicates"
                    )
                ring_pks = [PublicKey.from_bytes(p) for p in ring_raw]
                ring_bytes = encode_ring([pk.point for pk in ring_pks])
                state = "voting"
                continue
            raise AuditError(
                f"entry {entry.index}: unexpected {type(rec).__name__} in registration"
            )

        if state == "voting":
            if isinstance(rec, Ballot):
                if rec.choice not in setup.options:
                    raise AuditError(
                        f"entry {entry.index}: choice {rec.choice!r} not in options"
                    )
                if entry.timestamp < setup.voting_open:
                    raise AuditError(
                        f"entry {entry.index}: ballot timestamp before voting_open"
                    )
                if entry.timestamp > setup.voting_close:
                    raise AuditError(
                        f"entry {entry.index}: ballot timestamp after voting_close"
                    )
                try:
                    sig = Signature.from_bytes(b64decode(rec.otrs_sig_b64))
                except (ValueError, Exception) as exc:  # noqa: BLE001
                    raise AuditError(
                        f"entry {entry.index}: malformed OTRS signature"
                    ) from exc
                assert ring_pks is not None
                msg = Ballot.message_for(rec.choice)
                if not verify(sig, bytes.fromhex(setup.election_id), msg, ring_pks):
                    raise AuditError(
                        f"entry {entry.index}: OTRS signature does not verify"
                    )
                ballots.append((entry.index, rec, sig, msg))
                continue
            if isinstance(rec, VotingClosed):
                closed_seen = True
                state = "closed"
                continue
            raise AuditError(
                f"entry {entry.index}: unexpected {type(rec).__name__} in voting"
            )

        if state == "closed":
            if isinstance(rec, TallyPublication):
                claimed_tally = rec
                state = "done"
                continue
            raise AuditError(
                f"entry {entry.index}: unexpected {type(rec).__name__} after closed"
            )

        if state == "done":
            raise AuditError(
                f"entry {entry.index}: extra record after TallyPublication"
            )

    if ring_pks is None or ring_bytes is None:
        raise AuditError("log did not reach voting phase")

    # ----- 4. witness federation (optional) ------------------------------ #
    witness_cosigned: int | None = None
    valid_checkpoints: List[Checkpoint] = []
    if witness_pks:
        try:
            valid_checkpoints = verify_checkpoints(
                log_path=log_path,
                witness_pks=witness_pks,
                witness_threshold=setup.witness_threshold,
            )
        except LogError as exc:
            raise AuditError(f"witness federation: {exc}") from exc
        witness_cosigned = latest_cosigned_index(
            valid_checkpoints, setup.witness_threshold
        )
        if setup.witness_threshold > 0 and witness_cosigned is None:
            raise AuditError(
                f"no log index has been co-signed by ≥ {setup.witness_threshold} witnesses"
            )

    # ----- 5. tally ------------------------------------------------------ #
    election_id_bytes = bytes.fromhex(setup.election_id)
    buckets: Dict[Tuple[int, bytes], List[int]] = {}
    cols_per_ballot: Dict[int, List[bytes]] = {}
    for bi, (entry_idx, rec, sig, msg) in enumerate(ballots):
        cols = _sigma_columns_from_sig(sig, msg, election_id_bytes, ring_bytes)
        cols_per_ballot[bi] = cols
        for j, sj in enumerate(cols, start=1):
            buckets.setdefault((j, sj), []).append(bi)

    signer_of_ballot: Dict[int, int] = {}
    for bi in range(len(ballots)):
        my_cols = cols_per_ballot[bi]
        collision_positions = [
            j
            for j, sj in enumerate(my_cols, start=1)
            if len(buckets[(j, sj)]) >= 2
        ]
        if not collision_positions:
            signer_of_ballot[bi] = -bi - 1  # unique synthetic id
        else:
            signer_of_ballot[bi] = collision_positions[0]

    by_signer: Dict[int, List[int]] = {}
    for bi, signer in signer_of_ballot.items():
        by_signer.setdefault(signer, []).append(bi)

    tally: Dict[str, int] = {opt: 0 for opt in setup.options}
    accepted: List[int] = []
    rejected: List[Tuple[int, str]] = []
    double_signers: List[PublicKey] = []
    for signer, bis in by_signer.items():
        choices = {ballots[bi][1].choice for bi in bis}
        if len(choices) == 1:
            tally[next(iter(choices))] += 1
            accepted.append(ballots[bis[0]][0])
        else:
            for bi in bis:
                rejected.append((ballots[bi][0], "double-sign"))
            if signer >= 1:
                double_signers.append(ring_pks[signer - 1])

    return AuditReport(
        setup=setup,
        ring=ring_pks,
        tally=tally,
        accepted_ballot_indices=sorted(accepted),
        rejected_ballot_indices=sorted(rejected),
        double_sign_culprits=double_signers,
        claimed_tally=claimed_tally,
        witness_cosigned_index=witness_cosigned,
        witness_count=len(valid_checkpoints),
    )


def build_tally_record(report: AuditReport) -> TallyPublication:
    return TallyPublication(
        tally=dict(report.tally),
        double_sign_culprits_b64=[
            b64encode(pk.point.raw).decode() for pk in report.double_sign_culprits
        ],
    )
