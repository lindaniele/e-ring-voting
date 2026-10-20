"""
Voter-side helpers: build the transactions a voter or sponsor submits.

Groups only exist once the chain has frozen a round, and the freeze happens
at the start of the first block past the deadline. To vote in that very
block, pass the poll as it will look to that block's transactions:
``state_for_next_block(node.state, timestamp).polls[election_id]``.
"""

from __future__ import annotations

from base64 import b64encode
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from chain.state import PollState
from chain.transactions import (
    Transaction,
    make_ballot,
    make_key_transfer,
    make_register_voter,
)
from trs import KeyPair, PublicKey, prove_possession, sign
from voting.groups import issue_for
from voting.records import Ballot, KeyTransfer, VoterRegistration


def registration_tx(
    *,
    sponsor_pk_raw: bytes,
    sponsor_sk: ed25519.Ed25519PrivateKey,
    election_id: str,
    voter: KeyPair,
    handle: str,
    fee: int,
    deposit: int,
    nonce: int,
) -> Transaction:
    """Registration of ``voter`` with its proof of possession, paid by the sponsor."""
    pop = prove_possession(
        voter.sk, voter.pk, VoterRegistration.pop_context(election_id, handle)
    )
    record = VoterRegistration(
        voter_pk_b64=b64encode(voter.pk.point.raw).decode(),
        voter_handle=handle,
        pop_sig_b64=b64encode(pop).decode(),
    )
    return make_register_voter(
        sponsor_pk_raw, election_id, record.to_payload(),
        fee=fee, deposit=deposit, nonce=nonce, sk=sponsor_sk,
    )


def locate(poll: PollState, pk: PublicKey) -> Tuple[int, int]:
    """``(round, group)`` of ``pk`` in the poll's current round."""
    if poll.phase != "voting":
        raise ValueError(f"poll is not open for voting (phase {poll.phase!r})")
    r = poll.current_round
    for g, members in enumerate(poll.rounds[r].groups):
        if any(m.point.raw == pk.point.raw for m in members):
            return r, g
    raise ValueError(f"key is not a member of any group of round {r}")


def ballot_tx(poll: PollState, voter: KeyPair, choice: str) -> Transaction:
    """Sign a ballot for ``choice`` inside the voter's current group."""
    r, g = locate(poll, voter.pk)
    sig = sign(
        voter.sk, voter.pk, issue_for(poll.election_id, r),
        Ballot.message_for(choice), poll.rounds[r].groups[g],
    )
    record = Ballot(
        choice=choice,
        trs_sig_b64=b64encode(sig.to_bytes()).decode(),
        round=r,
        group=g,
    )
    return make_ballot(poll.election_id, record.to_payload())


def key_transfer_tx(poll: PollState, voter: KeyPair, new_pk: PublicKey) -> Transaction:
    """Spend the voter's current-round right on ``new_pk`` for the next round."""
    r, g = locate(poll, voter.pk)
    new_raw = new_pk.point.raw
    sig = sign(
        voter.sk, voter.pk, issue_for(poll.election_id, r),
        KeyTransfer.message_for(new_raw), poll.rounds[r].groups[g],
    )
    record = KeyTransfer(
        new_pk_b64=b64encode(new_raw).decode(),
        trs_sig_b64=b64encode(sig.to_bytes()).decode(),
        round=r,
        group=g,
    )
    return make_key_transfer(poll.election_id, record.to_payload())
