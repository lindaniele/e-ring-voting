"""
Election manager / publisher cohort API.

In v0.3 the "manager" is a *cohort* of N Ed25519 publishers, any t of which
must co-sign every bulletin-board entry. The single-publisher model of v0.2
is the degenerate case N=1, t=1.

The functions in this module fall into three groups:

* **Cohort key management.** Generate, save and load Ed25519 keypairs.
* **Synchronous publishing.** :func:`setup_election`, :func:`register_voter`,
  :func:`publish_ring`, :func:`publish_ballot`, :func:`close_voting`,
  :func:`publish_tally`. Each takes a list of ``(member_index, sk)`` pairs
  and writes the entry atomically. Useful for tests and small deployments
  where the cohort members trust each other to pool keys.
* **Asynchronous publishing.** Use :func:`propose_record`,
  :func:`cosign_record`, :func:`commit_record` from :mod:`voting.log`
  (via this module's re-exports) when the cohort members live in different
  processes/machines and must sign on their own schedule.
"""

from __future__ import annotations

import hashlib
import time
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from voting.log import (
    BulletinBoard,
    PublisherCohort,
    commit_pending,
    cosign_pending,
    pk_raw,
    propose_entry,
)
from voting.records import (
    Ballot,
    ElectionSetup,
    RingPublication,
    TallyPublication,
    VoterRegistration,
    VotingClosed,
    parse_payload,
)


# --------------------------------------------------------------------------- #
# Cohort helpers                                                              #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CohortSpec:
    """A locally-held cohort: pks plus the sk for the members we control."""

    pks: List[ed25519.Ed25519PublicKey]
    threshold: int
    sks: List[Tuple[int, ed25519.Ed25519PrivateKey]]

    def as_publisher_cohort(self) -> PublisherCohort:
        return PublisherCohort(pks=list(self.pks), threshold=self.threshold)


def generate_cohort(n: int, threshold: int) -> CohortSpec:
    """Generate a fresh cohort of size ``n`` with the given threshold."""
    if not (1 <= threshold <= n):
        raise ValueError(f"threshold {threshold} not in [1, {n}]")
    sks = [ed25519.Ed25519PrivateKey.generate() for _ in range(n)]
    pks = [sk.public_key() for sk in sks]
    return CohortSpec(
        pks=pks,
        threshold=threshold,
        sks=[(i, sk) for i, sk in enumerate(sks)],
    )


def cohort_pks_b64(cohort: PublisherCohort) -> List[str]:
    return [b64encode(pk_raw(pk)).decode() for pk in cohort.pks]


def derive_election_id(
    cohort: PublisherCohort, title: str, created_at: int
) -> str:
    """A reasonable default election_id: hash of (cohort head pk, title, time)."""
    h = hashlib.sha256()
    h.update(pk_raw(cohort.pks[0]))
    h.update(title.encode("utf-8"))
    h.update(created_at.to_bytes(8, "big"))
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# setup                                                                       #
# --------------------------------------------------------------------------- #


def setup_election(
    *,
    log_path: Path,
    cohort: CohortSpec,
    title: str,
    description: str,
    options: Sequence[str],
    registration_close: int,
    voting_open: int,
    voting_close: int,
    witness_pks: Sequence[ed25519.Ed25519PublicKey] = (),
    witness_threshold: int = 0,
    election_id: str | None = None,
) -> ElectionSetup:
    """Publish the genesis :class:`ElectionSetup` record."""
    log = BulletinBoard(log_path)
    if log.read_all():
        raise ValueError("log already initialised; refusing to overwrite")
    pub = cohort.as_publisher_cohort()
    created_at = int(time.time())
    eid = election_id or derive_election_id(pub, title, created_at)
    setup = ElectionSetup(
        election_id=eid,
        title=title,
        description=description,
        options=list(options),
        registration_close=registration_close,
        voting_open=voting_open,
        voting_close=voting_close,
        cohort_pks_b64=cohort_pks_b64(pub),
        threshold=cohort.threshold,
        witness_pks_b64=[b64encode(pk_raw(p)).decode() for p in witness_pks],
        witness_threshold=witness_threshold,
    )
    setup.validate()
    log.append(setup.to_payload(), cohort.sks[: cohort.threshold], pub)
    return setup


# --------------------------------------------------------------------------- #
# Voter registration                                                          #
# --------------------------------------------------------------------------- #


def register_voter(
    *,
    log_path: Path,
    cohort: CohortSpec,
    voter_pk: bytes,
    voter_handle: str,
) -> VoterRegistration:
    """Publish a :class:`VoterRegistration` entry, co-signed by the cohort."""
    log = BulletinBoard(log_path)
    pub = cohort.as_publisher_cohort()
    _current_setup(log)
    _ensure_no_ring_yet(log)
    if len(voter_pk) != 32:
        raise ValueError("voter_pk must be 32 bytes (Ristretto255)")
    reg = VoterRegistration(
        voter_pk_b64=b64encode(voter_pk).decode(),
        voter_handle=voter_handle,
    )
    log.append(reg.to_payload(), cohort.sks[: cohort.threshold], pub)
    return reg


# --------------------------------------------------------------------------- #
# Ring publication                                                            #
# --------------------------------------------------------------------------- #


def publish_ring(*, log_path: Path, cohort: CohortSpec) -> RingPublication:
    log = BulletinBoard(log_path)
    pub = cohort.as_publisher_cohort()
    _ensure_no_ring_yet(log)
    seen: set[str] = set()
    pks: List[str] = []
    for entry in log.read_all():
        rec = parse_payload(entry.payload)
        if isinstance(rec, VoterRegistration):
            if rec.voter_pk_b64 in seen:
                continue
            seen.add(rec.voter_pk_b64)
            pks.append(rec.voter_pk_b64)
    if len(pks) < 2:
        raise ValueError(
            f"need at least 2 registered voters to publish a ring, have {len(pks)}"
        )
    from base64 import b64decode
    pks.sort(key=lambda s: b64decode(s))
    ring = RingPublication(ring_b64=pks)
    log.append(ring.to_payload(), cohort.sks[: cohort.threshold], pub)
    return ring


# --------------------------------------------------------------------------- #
# Ballot acceptance / close / tally                                           #
# --------------------------------------------------------------------------- #


def publish_ballot(
    *, log_path: Path, cohort: CohortSpec, ballot: Ballot
) -> None:
    log = BulletinBoard(log_path)
    pub = cohort.as_publisher_cohort()
    _ensure_voting_open_not_closed(log)
    log.append(ballot.to_payload(), cohort.sks[: cohort.threshold], pub)


def close_voting(*, log_path: Path, cohort: CohortSpec) -> None:
    log = BulletinBoard(log_path)
    pub = cohort.as_publisher_cohort()
    _ensure_voting_open_not_closed(log)
    log.append(VotingClosed().to_payload(), cohort.sks[: cohort.threshold], pub)


def publish_tally(
    *, log_path: Path, cohort: CohortSpec, tally: TallyPublication
) -> None:
    log = BulletinBoard(log_path)
    pub = cohort.as_publisher_cohort()
    _ensure_closed_no_tally(log)
    log.append(tally.to_payload(), cohort.sks[: cohort.threshold], pub)


# --------------------------------------------------------------------------- #
# Asynchronous publishing helpers (re-exports)                                #
# --------------------------------------------------------------------------- #


# Re-export the async helpers so cohort-member processes can import them
# from ``voting.manager`` together with the typed records.
__all__ = [
    "CohortSpec",
    "PublisherCohort",
    "generate_cohort",
    "cohort_pks_b64",
    "derive_election_id",
    "setup_election",
    "register_voter",
    "publish_ring",
    "publish_ballot",
    "close_voting",
    "publish_tally",
    "propose_entry",
    "cosign_pending",
    "commit_pending",
]


# --------------------------------------------------------------------------- #
# Internal state-machine helpers                                              #
# --------------------------------------------------------------------------- #


def _current_setup(log: BulletinBoard) -> ElectionSetup:
    entries = log.read_all()
    if not entries:
        raise ValueError("log is empty; run setup_election first")
    head = parse_payload(entries[0].payload)
    if not isinstance(head, ElectionSetup):
        raise ValueError("first entry is not an ElectionSetup")
    return head


def _ensure_no_ring_yet(log: BulletinBoard) -> None:
    for entry in log.read_all():
        rec = parse_payload(entry.payload)
        if isinstance(rec, RingPublication):
            raise ValueError("registration phase is closed: ring already published")


def _ensure_voting_open_not_closed(log: BulletinBoard) -> None:
    ring_seen = False
    for entry in log.read_all():
        rec = parse_payload(entry.payload)
        if isinstance(rec, RingPublication):
            ring_seen = True
        if isinstance(rec, VotingClosed):
            raise ValueError("voting is already closed")
    if not ring_seen:
        raise ValueError("voting has not opened (no RingPublication yet)")


def _ensure_closed_no_tally(log: BulletinBoard) -> None:
    closed = False
    for entry in log.read_all():
        rec = parse_payload(entry.payload)
        if isinstance(rec, VotingClosed):
            closed = True
        if isinstance(rec, TallyPublication):
            raise ValueError("tally already published")
    if not closed:
        raise ValueError("voting is not yet closed")
