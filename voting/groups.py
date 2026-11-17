"""
Fixed-size voter groups and round tags.

A one-time traceable ring signature costs O(n) in time and size (about
2 KB per member at λ = 128), so a single ring of every voter does not
scale: a ring of 1000 makes every ballot 2 MB. The original e-ring-voting procedure fixed a
*group size* in the poll announcement and let voters sign inside their
group. That raises the question this module answers: **who decides which
voters share a group?** If the organiser did, it could surround a target
voter with keys it controls and shrink the target's anonymity set to one.

So nobody decides. Members are ordered by ``SHA-256(label || beacon || pk)``
and cut into consecutive groups, where ``beacon`` is a value fixed only
*after* the member list is final (on the chain: the hash of the block
preceding the one that freezes the list). The organiser registers keys
before the beacon exists, so it cannot steer a key next to a target; the
residual bias is the miner's (it can withhold a block whose hash it
dislikes, at the price of the block reward).

Every group has at least ``group_size`` members (when there are that many
voters at all): ``n`` members make ``g = n // group_size`` groups and the
``n mod g`` leftovers are spread one per group.
"""

from __future__ import annotations

import hashlib
from typing import List, Sequence

GROUP_DST = b"e-ring-voting-groups-v1"


def issue_for(election_id: str, round_: int) -> bytes:
    """The tag of a round: the election id, suffixed after round 0."""
    eid = bytes.fromhex(election_id)
    if round_ == 0:
        return eid
    return eid + b"/round" + round_.to_bytes(4, "big")


def signing_context(election_id: str, round_: int) -> bytes:
    """The OTRS context string of a round, hashed into every signature."""
    return b"e-ring-voting/v1/" + issue_for(election_id, round_)


def assign_groups(
    members: Sequence[bytes], group_size: int, beacon: bytes, label: bytes
) -> List[List[bytes]]:
    """
    Partition ``members`` (key identifiers: the chain passes OTRS key
    fingerprints) into groups.

    ``label`` binds the assignment to one poll and round (use
    :func:`issue_for`). Each returned group is sorted by identifier, which
    is the canonical ring order. ``group_size == 0`` yields a single group.
    """
    if len(set(members)) != len(members):
        raise ValueError("duplicate members")
    if not members:
        return []
    if group_size <= 0 or len(members) < 2 * group_size:
        return [sorted(members)]
    order = sorted(
        members,
        key=lambda pk: hashlib.sha256(GROUP_DST + label + beacon + pk).digest(),
    )
    g = len(members) // group_size
    base, extra = divmod(len(members), g)
    groups: List[List[bytes]] = []
    pos = 0
    for i in range(g):
        size = base + (1 if i < extra else 0)
        groups.append(sorted(order[pos:pos + size]))
        pos += size
    return groups
