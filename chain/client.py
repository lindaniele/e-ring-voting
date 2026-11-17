"""
Voter-side helpers: make keys and build the transactions a voter or a
sponsor submits.

A one-time key is made for exactly one use, and its label says which:
:func:`voter_key` for a registration (poll and handle), :func:`transfer_key`
for a key that enters a later round by transfer. Signing is deterministic,
so re-sending a ballot re-sends the same bytes, which the chain treats as a
harmless copy.

Groups only exist once the chain has frozen a round, and the freeze happens
at the start of the first block past the deadline. To vote in that very
block, pass the poll as it will look to that block's transactions:
``state_for_next_block(node.state, timestamp).polls[election_id]``.
"""

from __future__ import annotations

from base64 import b64encode
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from chain.state import PollState
from chain.transactions import (
    Transaction,
    make_ballot,
    make_key_transfer,
    make_register_voter,
)
from otrs import KeyPair, PublicKey, keygen, params_for
from voting.groups import signing_context
from voting.records import Ballot, KeyTransfer, VoterRegistration


def voter_key(
    election_id: str, handle: str, *, security: int = 128,
    master: Optional[bytes] = None,
) -> KeyPair:
    """A fresh key for registering ``handle`` in poll ``election_id``."""
    return keygen(
        VoterRegistration.key_label(election_id, handle),
        params=params_for(security), master=master,
    )


def transfer_key(
    election_id: str, round_: int, *, security: int = 128,
    master: Optional[bytes] = None,
) -> KeyPair:
    """A fresh key to receive a voting right in round ``round_``."""
    return keygen(
        KeyTransfer.key_label(election_id, round_),
        params=params_for(security), master=master,
    )


def registration_tx(
    *,
    sponsor_pk_raw: bytes,
    sponsor_sk: ed25519.Ed25519PrivateKey,
    election_id: str,
    voter_pk: PublicKey,
    handle: str,
    fee: int,
    deposit: int,
    nonce: int,
) -> Transaction:
    """Registration of ``voter_pk`` under ``handle``, paid by the sponsor."""
    record = VoterRegistration(
        voter_pk_b64=b64encode(voter_pk.to_bytes()).decode(),
        voter_handle=handle,
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
    for g, ring in enumerate(poll.rounds[r].groups):
        try:
            ring.position(pk)
            return r, g
        except ValueError:
            continue
    raise ValueError(f"key is not a member of any group of round {r}")


def ballot_tx(
    poll: PollState, voter: KeyPair, choice: str, *, randomized: bool = False
) -> Transaction:
    """
    Sign a ballot for ``choice`` inside the voter's current group.

    ``randomized=True`` imitates a wallet that does not sign
    deterministically; sending two such ballots traces the key.
    """
    r, g = locate(poll, voter.pk)
    sig = poll.rounds[r].groups[g].sign(
        voter, Ballot.message_for(choice), signing_context(poll.election_id, r),
        randomized=randomized,
    )
    record = Ballot(
        choice=choice, sig_b64=b64encode(sig.to_bytes()).decode(), round=r, group=g,
    )
    return make_ballot(poll.election_id, record.to_payload())


def key_transfer_tx(poll: PollState, voter: KeyPair, new_pk: PublicKey) -> Transaction:
    """Spend the voter's current-round right on ``new_pk`` for the next round."""
    r, g = locate(poll, voter.pk)
    raw = new_pk.to_bytes()
    sig = poll.rounds[r].groups[g].sign(
        voter, KeyTransfer.message_for(raw), signing_context(poll.election_id, r),
    )
    record = KeyTransfer(
        new_pk_b64=b64encode(raw).decode(),
        sig_b64=b64encode(sig.to_bytes()).decode(),
        round=r,
        group=g,
    )
    return make_key_transfer(poll.election_id, record.to_payload())
