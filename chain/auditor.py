"""
Public auditor for the PoW chain.

Loading a chain through :class:`chain.node.Node` already enforces:

* block PoW + linkage,
* per-tx signature + nonce + balance + state-machine rules,
* per-ballot OTRS verification against the published ring,
* poll lifecycle (Setup -> Registration -> Ring -> Ballot -> Closed -> Tally).

So by the time we get here, the *integrity* of the chain is established.
What's left for the auditor is the tally: aggregate ballots, run the
trace algorithm to detect double-signs, and compare the recomputed tally
against any on-chain claim.

The tally algorithm is the same one used by ``voting.auditor`` — we
bucket every (column-index, sigma-value) pair across all ballots and any
two ballots that share a bucket either come from the same signer (linked
or double-sign) or are by chance a column collision (probability bounded
by ``binom(B, 2) * 2^-252`` for ring size ``n`` and ``B`` ballots, which
is below 2^-200 for any conceivable election).
"""

from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from chain.node import Node
from chain.state import ChainParams, DEFAULT_PARAMS, PollState
from otrs import PublicKey, Signature
from otrs.group import Scalar
from otrs.hash import hash_to_group
from otrs.otrs import DST_H1
from voting.records import ElectionSetup, TallyPublication


class ChainAuditError(Exception):
    """Raised when the chain itself fails to load or replay."""


# --------------------------------------------------------------------------- #
# Reports                                                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PollAuditReport:
    election_id: str
    setup: ElectionSetup
    ring: List[PublicKey]
    phase: str
    tally: Dict[str, int]
    accepted_ballot_heights: List[int]
    rejected_ballot_heights: List[Tuple[int, str]] = field(default_factory=list)
    double_sign_culprits: List[PublicKey] = field(default_factory=list)
    claimed_tally: Optional[TallyPublication] = None

    def tally_matches_claim(self) -> bool:
        if self.claimed_tally is None:
            return True
        return self.tally == self.claimed_tally.tally


@dataclass(frozen=True)
class ChainAuditReport:
    chain_height: int
    chain_weight: int
    polls: List[PollAuditReport]


# --------------------------------------------------------------------------- #
# Internals                                                                    #
# --------------------------------------------------------------------------- #


def _sigma_columns(
    sig: Signature, message: bytes, election_id_bytes: bytes, ring_bytes: bytes
) -> List[bytes]:
    A0 = hash_to_group(election_id_bytes + ring_bytes + message, DST_H1)
    n = len(sig.c)
    return [(A0 + sig.A1.scalar_mul(Scalar.from_int(j))).raw for j in range(1, n + 1)]


def _audit_poll(poll: PollState) -> PollAuditReport:
    if poll.ring_pks is None or poll.ring_bytes is None:
        # Poll never reached voting phase — empty tally, empty ring.
        return PollAuditReport(
            election_id=poll.election_id,
            setup=poll.setup,
            ring=[],
            phase=poll.phase,
            tally={opt: 0 for opt in poll.setup.options},
            accepted_ballot_heights=[],
            claimed_tally=poll.claimed_tally,
        )

    election_id_bytes = bytes.fromhex(poll.setup.election_id)
    buckets: Dict[Tuple[int, bytes], List[int]] = {}
    cols_per_ballot: Dict[int, List[bytes]] = {}
    for bi, (height, choice, sig, msg) in enumerate(poll.ballots):
        cols = _sigma_columns(sig, msg, election_id_bytes, poll.ring_bytes)
        cols_per_ballot[bi] = cols
        for j, sj in enumerate(cols, start=1):
            buckets.setdefault((j, sj), []).append(bi)

    signer_of_ballot: Dict[int, int] = {}
    for bi in range(len(poll.ballots)):
        my_cols = cols_per_ballot[bi]
        collisions = [
            j for j, sj in enumerate(my_cols, start=1) if len(buckets[(j, sj)]) >= 2
        ]
        if not collisions:
            signer_of_ballot[bi] = -bi - 1
        else:
            signer_of_ballot[bi] = collisions[0]

    by_signer: Dict[int, List[int]] = {}
    for bi, s in signer_of_ballot.items():
        by_signer.setdefault(s, []).append(bi)

    tally: Dict[str, int] = {opt: 0 for opt in poll.setup.options}
    accepted: List[int] = []
    rejected: List[Tuple[int, str]] = []
    double_signers: List[PublicKey] = []
    for signer, bis in by_signer.items():
        choices = {poll.ballots[bi][1] for bi in bis}
        if len(choices) == 1:
            tally[next(iter(choices))] += 1
            accepted.append(poll.ballots[bis[0]][0])
        else:
            for bi in bis:
                rejected.append((poll.ballots[bi][0], "double-sign"))
            if signer >= 1:
                double_signers.append(poll.ring_pks[signer - 1])

    return PollAuditReport(
        election_id=poll.election_id,
        setup=poll.setup,
        ring=list(poll.ring_pks),
        phase=poll.phase,
        tally=tally,
        accepted_ballot_heights=sorted(accepted),
        rejected_ballot_heights=sorted(rejected),
        double_sign_culprits=double_signers,
        claimed_tally=poll.claimed_tally,
    )


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #


def audit_chain(
    chain_path: Path, *, params: ChainParams = DEFAULT_PARAMS
) -> ChainAuditReport:
    """
    Replay the chain file end-to-end and produce per-poll audit reports.

    Any chain-level inconsistency (PoW, signatures, state machine) raises
    inside :class:`chain.node.Node.load`. By the time this returns, every
    ballot in every poll has been individually OTRS-verified.
    """
    try:
        node = Node.load(chain_path, params=params)
    except Exception as exc:  # noqa: BLE001
        raise ChainAuditError(f"chain replay failed: {exc}") from exc

    reports = [_audit_poll(poll) for poll in node.state.polls.values()]
    reports.sort(key=lambda r: r.election_id)
    return ChainAuditReport(
        chain_height=node.height,
        chain_weight=node.state.cum_weight,
        polls=reports,
    )


def build_tally_record(report: PollAuditReport) -> TallyPublication:
    return TallyPublication(
        tally=dict(report.tally),
        double_sign_culprits_b64=[
            b64encode(pk.point.raw).decode() for pk in report.double_sign_culprits
        ],
    )
