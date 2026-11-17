"""
Public auditor for the PoW chain.

Loading a chain through :class:`chain.node.Node` replays every rule from
genesis:

* block PoW at the prescribed difficulty, linkage, coinbase amounts,
* per-tx signatures, nonces, balances, deposits and key labels,
* every ballot and key transfer verified against its group,
* the poll lifecycle (freeze, regrouping, tally, slashing, refunds), which
  the chain computes itself at the deadlines.

So the audit *is* the replay: there is no claimed tally to compare against,
because no party publishes one. This module only turns the replayed state
into a report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from chain.node import Node
from chain.state import ChainParams, DEFAULT_PARAMS, PollState
from voting.records import ElectionSetup


class ChainAuditError(Exception):
    """Raised when the chain itself fails to load or replay."""


@dataclass(frozen=True)
class PollAuditReport:
    election_id: str
    setup: ElectionSetup
    phase: str
    registered: int
    group_sizes: List[List[int]]              # per round, per group
    tally: Optional[Dict[str, int]]           # None until the poll closes
    culprits: List[Tuple[int, str, str]] = field(default_factory=list)
    slashed: int = 0
    refunded: int = 0
    transfers: List[int] = field(default_factory=list)


@dataclass(frozen=True)
class ChainAuditReport:
    chain_height: int
    chain_weight: int
    burned: int
    polls: List[PollAuditReport]


def audit_poll(poll: PollState) -> PollAuditReport:
    result = poll.result
    return PollAuditReport(
        election_id=poll.election_id,
        setup=poll.setup,
        phase=poll.phase,
        registered=len(poll.registrations),
        group_sizes=[[len(g) for g in rnd.groups] for rnd in poll.rounds],
        tally=dict(result.tally) if result else None,
        culprits=list(result.culprits) if result else [],
        slashed=result.slashed if result else 0,
        refunded=result.refunded if result else 0,
        transfers=list(result.transfers) if result else [],
    )


def audit_chain(
    chain_path: Path, *, params: ChainParams = DEFAULT_PARAMS
) -> ChainAuditReport:
    """Replay the chain file end-to-end and produce per-poll reports."""
    try:
        node = Node.load(chain_path, params=params)
    except Exception as exc:  # noqa: BLE001
        raise ChainAuditError(f"chain replay failed: {exc}") from exc
    reports = sorted(
        (audit_poll(poll) for poll in node.state.polls.values()),
        key=lambda r: r.election_id,
    )
    return ChainAuditReport(
        chain_height=node.height,
        chain_weight=node.state.cum_weight,
        burned=node.state.burned,
        polls=reports,
    )
