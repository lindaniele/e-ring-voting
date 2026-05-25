"""
Chain state: account ledger + per-poll election state machine.

The state is the result of folding a sequence of blocks. Applying a block
either succeeds and mutates the state in place, or raises
:class:`StateError` and leaves the state untouched (apply on a snapshot
if you need rewind semantics — see :func:`State.copy`).

Block-level rules
-----------------
* The first transaction MUST be a coinbase. No further coinbases.
* PoW must verify, prev_hash must match the tip, height = tip.height + 1,
  timestamp > parent.timestamp.
* The coinbase amount must equal ``block_reward + sum(fees)`` of all
  fee-bearing transactions in the block.

Transaction-level rules
-----------------------
* Transfers: signed by sender, nonce matches account, sufficient balance.
* Voting transactions wrap the ``voting.records`` types and enforce the
  same state machine on a per-poll basis. Poll creator is the only
  identity that may publish the ring / close / tally for their own poll.
* Ballots are unsigned at the chain layer — anonymity preserved. The
  OTRS signature inside the payload is what proves validity.
"""

from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401  (re-export shape)

from chain.block import Block, block_weight, is_genesis, verify_pow
from chain.transactions import (
    SIGNED_KINDS,
    Transaction,
    TxKind,
    verify_tx_sig,
)
from otrs import PublicKey, Signature, verify as otrs_verify
from otrs.group import Scalar
from otrs.hash import hash_to_group
from otrs.otrs import DST_H1
from otrs.serialize import encode_ring
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


class StateError(Exception):
    """Raised on block or transaction validation failure."""


# --------------------------------------------------------------------------- #
# Protocol parameters                                                          #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ChainParams:
    block_reward: int = 50
    setup_fee: int = 5
    registration_fee: int = 1
    ring_fee: int = 1
    close_fee: int = 1
    tally_fee: int = 1
    target_block_seconds: int = 60
    difficulty_adjust_window: int = 11
    difficulty_min: int = 1
    difficulty_max: int = 32


DEFAULT_PARAMS = ChainParams()


# --------------------------------------------------------------------------- #
# Account ledger                                                               #
# --------------------------------------------------------------------------- #


@dataclass
class Account:
    balance: int = 0
    nonce: int = 0  # number of txs sent — next tx must have nonce == this


@dataclass
class PollState:
    election_id: str
    creator_pk_b64: str
    setup: ElectionSetup
    phase: str  # "registration" | "voting" | "closed" | "tallied"
    registrations: List[VoterRegistration] = field(default_factory=list)
    ring_pks: Optional[List[PublicKey]] = None
    ring_bytes: Optional[bytes] = None
    # (block_height, choice, sig, message_bytes) per accepted ballot:
    ballots: List[Tuple[int, str, Signature, bytes]] = field(default_factory=list)
    claimed_tally: Optional[TallyPublication] = None


@dataclass
class State:
    accounts: Dict[str, Account] = field(default_factory=dict)
    polls: Dict[str, PollState] = field(default_factory=dict)
    height: int = -1
    tip_hash: bytes = b""
    last_timestamp: int = 0
    cum_weight: int = 0  # sum of 2^difficulty across all applied blocks

    # ----- account helpers ----------------------------------------------- #
    def _account(self, pk_b64: str) -> Account:
        if pk_b64 not in self.accounts:
            self.accounts[pk_b64] = Account()
        return self.accounts[pk_b64]

    def balance(self, pk_b64: str) -> int:
        return self._account(pk_b64).balance

    def nonce(self, pk_b64: str) -> int:
        return self._account(pk_b64).nonce

    def credit(self, pk_b64: str, amount: int) -> None:
        if amount < 0:
            raise StateError(f"cannot credit negative amount: {amount}")
        self._account(pk_b64).balance += amount

    def debit(self, pk_b64: str, amount: int) -> None:
        if amount < 0:
            raise StateError(f"cannot debit negative amount: {amount}")
        acc = self._account(pk_b64)
        if acc.balance < amount:
            raise StateError(
                f"insufficient balance for {pk_b64[:12]}…: {acc.balance} < {amount}"
            )
        acc.balance -= amount

    def consume_nonce(self, pk_b64: str, expected: int) -> None:
        acc = self._account(pk_b64)
        if acc.nonce != expected:
            raise StateError(
                f"nonce mismatch for {pk_b64[:12]}…: expected {acc.nonce}, got {expected}"
            )
        acc.nonce += 1

    def copy(self) -> "State":
        """Deep-ish copy: accounts and polls are duplicated; raw bytes shared."""
        new = State(
            height=self.height,
            tip_hash=self.tip_hash,
            last_timestamp=self.last_timestamp,
            cum_weight=self.cum_weight,
        )
        new.accounts = {k: Account(balance=v.balance, nonce=v.nonce) for k, v in self.accounts.items()}
        new.polls = {
            k: PollState(
                election_id=v.election_id,
                creator_pk_b64=v.creator_pk_b64,
                setup=v.setup,
                phase=v.phase,
                registrations=list(v.registrations),
                ring_pks=list(v.ring_pks) if v.ring_pks is not None else None,
                ring_bytes=v.ring_bytes,
                ballots=list(v.ballots),
                claimed_tally=v.claimed_tally,
            )
            for k, v in self.polls.items()
        }
        return new


# --------------------------------------------------------------------------- #
# Per-kind validators                                                          #
# --------------------------------------------------------------------------- #


def _apply_coinbase(state: State, tx: Transaction, *, block_height: int) -> int:
    body = tx.body
    try:
        miner_b64 = str(body["miner_pk_b64"])
        amount = int(body["amount"])
        height = int(body["height"])
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed coinbase: {exc}") from exc
    if height != block_height:
        raise StateError(
            f"coinbase height field {height} != block height {block_height}"
        )
    if amount < 0:
        raise StateError("coinbase amount must be non-negative")
    state.credit(miner_b64, amount)
    return amount  # for the block-level reward check


def _apply_transfer(state: State, tx: Transaction) -> int:
    body = tx.body
    try:
        sender_b64 = str(body["sender_pk_b64"])
        recipients = list(body["recipients"])
        fee = int(body["fee"])
        nonce = int(body["nonce"])
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed transfer: {exc}") from exc
    if fee < 0:
        raise StateError("fee must be non-negative")
    sender_raw = b64decode(sender_b64)
    if not verify_tx_sig(tx, sender_raw):
        raise StateError("transfer signature invalid")
    total = fee
    parsed: List[Tuple[str, int]] = []
    for r in recipients:
        amt = int(r["amount"])
        if amt < 0:
            raise StateError("transfer amount must be non-negative")
        total += amt
        parsed.append((str(r["pk_b64"]), amt))
    state.consume_nonce(sender_b64, nonce)
    state.debit(sender_b64, total)
    for pk_b64, amt in parsed:
        state.credit(pk_b64, amt)
    return fee


def _consume_fee_and_nonce(
    state: State, tx: Transaction, signer_field: str, fee: int, nonce: int
) -> Tuple[str, bytes]:
    signer_b64 = str(tx.body[signer_field])
    signer_raw = b64decode(signer_b64)
    if not verify_tx_sig(tx, signer_raw):
        raise StateError(f"signature invalid for {tx.kind}")
    state.consume_nonce(signer_b64, nonce)
    state.debit(signer_b64, fee)
    return signer_b64, signer_raw


def _apply_setup_poll(state: State, tx: Transaction, *, params: ChainParams) -> int:
    body = tx.body
    try:
        fee = int(body["fee"])
        nonce = int(body["nonce"])
        setup_payload = b64decode(str(body["setup_payload_b64"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed setup_poll: {exc}") from exc
    if fee < params.setup_fee:
        raise StateError(f"setup fee {fee} below minimum {params.setup_fee}")
    creator_b64, creator_raw = _consume_fee_and_nonce(state, tx, "creator_pk_b64", fee, nonce)
    try:
        record = parse_payload(setup_payload)
    except RecordError as exc:
        raise StateError(f"setup_payload is not an ElectionSetup: {exc}") from exc
    if not isinstance(record, ElectionSetup):
        raise StateError("setup_payload must contain ElectionSetup")
    try:
        record.validate()
    except RecordError as exc:
        raise StateError(f"ElectionSetup invalid: {exc}") from exc
    if record.election_id in state.polls:
        raise StateError(f"election_id {record.election_id!r} already exists")
    state.polls[record.election_id] = PollState(
        election_id=record.election_id,
        creator_pk_b64=creator_b64,
        setup=record,
        phase="registration",
    )
    return fee


def _expect_poll_creator(poll: PollState, signer_b64: str) -> None:
    if signer_b64 != poll.creator_pk_b64:
        raise StateError(
            f"only poll creator may issue this tx (poll {poll.election_id[:12]}…)"
        )


def _apply_register_voter(
    state: State, tx: Transaction, *, params: ChainParams, block_timestamp: int
) -> int:
    body = tx.body
    try:
        fee = int(body["fee"])
        nonce = int(body["nonce"])
        election_id = str(body["election_id"])
        reg_payload = b64decode(str(body["registration_payload_b64"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed register_voter: {exc}") from exc
    if fee < params.registration_fee:
        raise StateError(f"registration fee {fee} below minimum {params.registration_fee}")
    sponsor_b64, _ = _consume_fee_and_nonce(state, tx, "sponsor_pk_b64", fee, nonce)
    poll = state.polls.get(election_id)
    if poll is None:
        raise StateError(f"unknown election_id {election_id!r}")
    if poll.phase != "registration":
        raise StateError(f"poll {election_id[:12]}… not in registration phase")
    if block_timestamp > poll.setup.registration_close:
        raise StateError("registration block timestamp past registration_close")
    try:
        record = parse_payload(reg_payload)
    except RecordError as exc:
        raise StateError(f"registration_payload invalid: {exc}") from exc
    if not isinstance(record, VoterRegistration):
        raise StateError("registration_payload must contain VoterRegistration")
    pk_raw = b64decode(record.voter_pk_b64)
    if len(pk_raw) != 32:
        raise StateError("voter_pk_b64 must decode to 32 bytes")
    try:
        PublicKey.from_bytes(pk_raw)
    except ValueError as exc:
        raise StateError(f"voter_pk is not a valid Ristretto255 point: {exc}") from exc
    if any(r.voter_pk_b64 == record.voter_pk_b64 for r in poll.registrations):
        raise StateError("voter already registered")
    poll.registrations.append(record)
    _ = sponsor_b64  # sponsor identity does not bind to the registration in this prototype
    return fee


def _apply_publish_ring(
    state: State, tx: Transaction, *, params: ChainParams
) -> int:
    body = tx.body
    try:
        fee = int(body["fee"])
        nonce = int(body["nonce"])
        election_id = str(body["election_id"])
        ring_payload = b64decode(str(body["ring_payload_b64"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed publish_ring: {exc}") from exc
    if fee < params.ring_fee:
        raise StateError(f"ring fee {fee} below minimum {params.ring_fee}")
    creator_b64, _ = _consume_fee_and_nonce(state, tx, "creator_pk_b64", fee, nonce)
    poll = state.polls.get(election_id)
    if poll is None:
        raise StateError(f"unknown election_id {election_id!r}")
    _expect_poll_creator(poll, creator_b64)
    if poll.phase != "registration":
        raise StateError(f"poll {election_id[:12]}… not in registration phase")
    try:
        record = parse_payload(ring_payload)
    except RecordError as exc:
        raise StateError(f"ring_payload invalid: {exc}") from exc
    if not isinstance(record, RingPublication):
        raise StateError("ring_payload must contain RingPublication")
    attested = {r.voter_pk_b64 for r in poll.registrations}
    declared = set(record.ring_b64)
    if attested != declared:
        raise StateError("published ring does not match attested registrations")
    if len(record.ring_b64) != len(declared):
        raise StateError("published ring contains duplicates")
    ring_raw = [b64decode(s) for s in record.ring_b64]
    ring_pks = [PublicKey.from_bytes(r) for r in ring_raw]
    poll.ring_pks = ring_pks
    poll.ring_bytes = encode_ring([pk.point for pk in ring_pks])
    poll.phase = "voting"
    return fee


def _apply_ballot(
    state: State, tx: Transaction, *, block_height: int, block_timestamp: int
) -> int:
    body = tx.body
    try:
        election_id = str(body["election_id"])
        ballot_payload = b64decode(str(body["ballot_payload_b64"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed ballot: {exc}") from exc
    poll = state.polls.get(election_id)
    if poll is None:
        raise StateError(f"unknown election_id {election_id!r}")
    if poll.phase != "voting":
        raise StateError(f"poll {election_id[:12]}… not in voting phase")
    if block_timestamp < poll.setup.voting_open:
        raise StateError("ballot block timestamp before voting_open")
    if block_timestamp > poll.setup.voting_close:
        raise StateError("ballot block timestamp after voting_close")
    try:
        record = parse_payload(ballot_payload)
    except RecordError as exc:
        raise StateError(f"ballot_payload invalid: {exc}") from exc
    if not isinstance(record, Ballot):
        raise StateError("ballot_payload must contain Ballot")
    if record.choice not in poll.setup.options:
        raise StateError(f"choice {record.choice!r} not in options")
    try:
        sig = Signature.from_bytes(b64decode(record.otrs_sig_b64))
    except (ValueError, Exception) as exc:  # noqa: BLE001
        raise StateError(f"malformed OTRS signature: {exc}") from exc
    msg = Ballot.message_for(record.choice)
    assert poll.ring_pks is not None
    if not otrs_verify(sig, bytes.fromhex(poll.setup.election_id), msg, poll.ring_pks):
        raise StateError("OTRS signature does not verify against the ring")
    poll.ballots.append((block_height, record.choice, sig, msg))
    return 0  # no fee for ballots


def _apply_close_poll(
    state: State, tx: Transaction, *, params: ChainParams, block_timestamp: int
) -> int:
    body = tx.body
    try:
        fee = int(body["fee"])
        nonce = int(body["nonce"])
        election_id = str(body["election_id"])
        closed_payload = b64decode(str(body["closed_payload_b64"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed close_poll: {exc}") from exc
    if fee < params.close_fee:
        raise StateError(f"close fee {fee} below minimum {params.close_fee}")
    creator_b64, _ = _consume_fee_and_nonce(state, tx, "creator_pk_b64", fee, nonce)
    poll = state.polls.get(election_id)
    if poll is None:
        raise StateError(f"unknown election_id {election_id!r}")
    _expect_poll_creator(poll, creator_b64)
    if poll.phase != "voting":
        raise StateError(f"poll {election_id[:12]}… not in voting phase")
    try:
        record = parse_payload(closed_payload)
    except RecordError as exc:
        raise StateError(f"closed_payload invalid: {exc}") from exc
    if not isinstance(record, VotingClosed):
        raise StateError("closed_payload must contain VotingClosed")
    if block_timestamp < poll.setup.voting_close:
        raise StateError("cannot close before voting_close")
    poll.phase = "closed"
    return fee


def _apply_tally(
    state: State, tx: Transaction, *, params: ChainParams
) -> int:
    body = tx.body
    try:
        fee = int(body["fee"])
        nonce = int(body["nonce"])
        election_id = str(body["election_id"])
        tally_payload = b64decode(str(body["tally_payload_b64"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed tally: {exc}") from exc
    if fee < params.tally_fee:
        raise StateError(f"tally fee {fee} below minimum {params.tally_fee}")
    creator_b64, _ = _consume_fee_and_nonce(state, tx, "creator_pk_b64", fee, nonce)
    poll = state.polls.get(election_id)
    if poll is None:
        raise StateError(f"unknown election_id {election_id!r}")
    _expect_poll_creator(poll, creator_b64)
    if poll.phase != "closed":
        raise StateError(f"poll {election_id[:12]}… not in closed phase")
    try:
        record = parse_payload(tally_payload)
    except RecordError as exc:
        raise StateError(f"tally_payload invalid: {exc}") from exc
    if not isinstance(record, TallyPublication):
        raise StateError("tally_payload must contain TallyPublication")
    poll.claimed_tally = record
    poll.phase = "tallied"
    return fee


# --------------------------------------------------------------------------- #
# Block application                                                            #
# --------------------------------------------------------------------------- #


def _apply_genesis_inner(state: State, block: Block, *, params: ChainParams) -> None:
    if not is_genesis(block):
        raise StateError("first block must be genesis (prev_hash all-zero, height 0)")
    for tx in block.transactions:
        if tx.kind != TxKind.COINBASE.value:
            raise StateError("genesis may only contain coinbase transactions")
        _apply_coinbase(state, tx, block_height=0)
    state.height = 0
    state.tip_hash = block.hash
    state.last_timestamp = block.timestamp
    state.cum_weight = block_weight(block.difficulty)


def _apply_block_inner(state: State, block: Block, *, params: ChainParams) -> None:
    if block.prev_hash != state.tip_hash:
        raise StateError("block prev_hash does not match tip")
    if block.height != state.height + 1:
        raise StateError(
            f"block height {block.height} != expected {state.height + 1}"
        )
    if block.timestamp <= state.last_timestamp:
        raise StateError(
            f"block timestamp {block.timestamp} not strictly after parent {state.last_timestamp}"
        )
    if not verify_pow(block.header):
        raise StateError("PoW puzzle does not verify")

    txs = block.transactions
    if not txs or txs[0].kind != TxKind.COINBASE.value:
        raise StateError("first transaction must be a coinbase")
    for tx in txs[1:]:
        if tx.kind == TxKind.COINBASE.value:
            raise StateError("only one coinbase per block")

    fees_collected = 0
    for tx in txs[1:]:
        if tx.kind in SIGNED_KINDS and "signature_b64" not in tx.body:
            raise StateError(f"tx kind {tx.kind} requires a signature")
        if tx.kind == TxKind.TRANSFER.value:
            fees_collected += _apply_transfer(state, tx)
        elif tx.kind == TxKind.SETUP_POLL.value:
            fees_collected += _apply_setup_poll(state, tx, params=params)
        elif tx.kind == TxKind.REGISTER_VOTER.value:
            fees_collected += _apply_register_voter(
                state, tx, params=params, block_timestamp=block.timestamp
            )
        elif tx.kind == TxKind.PUBLISH_RING.value:
            fees_collected += _apply_publish_ring(state, tx, params=params)
        elif tx.kind == TxKind.BALLOT.value:
            _apply_ballot(
                state, tx, block_height=block.height, block_timestamp=block.timestamp
            )
        elif tx.kind == TxKind.CLOSE_POLL.value:
            fees_collected += _apply_close_poll(
                state, tx, params=params, block_timestamp=block.timestamp
            )
        elif tx.kind == TxKind.TALLY.value:
            fees_collected += _apply_tally(state, tx, params=params)
        else:
            raise StateError(f"unknown tx kind {tx.kind!r}")

    minted = _apply_coinbase(state, txs[0], block_height=block.height)
    expected = params.block_reward + fees_collected
    if minted != expected:
        raise StateError(
            f"coinbase amount {minted} != block_reward {params.block_reward} + fees {fees_collected}"
        )

    state.height = block.height
    state.tip_hash = block.hash
    state.last_timestamp = block.timestamp
    state.cum_weight += block_weight(block.difficulty)


def apply_block(state: State, block: Block, *, params: ChainParams = DEFAULT_PARAMS) -> None:
    """
    Apply ``block`` to ``state``. Atomic: on any validation failure the
    original state is preserved unchanged. On success the input state is
    mutated to the new tip.
    """
    working = state.copy()
    if working.height == -1:
        _apply_genesis_inner(working, block, params=params)
    else:
        _apply_block_inner(working, block, params=params)
    # Commit on success.
    state.accounts = working.accounts
    state.polls = working.polls
    state.height = working.height
    state.tip_hash = working.tip_hash
    state.last_timestamp = working.last_timestamp
    state.cum_weight = working.cum_weight


def apply_chain(blocks: List[Block], *, params: ChainParams = DEFAULT_PARAMS) -> State:
    """Fold a chain of blocks into a fresh State."""
    state = State()
    for block in blocks:
        apply_block(state, block, params=params)
    return state
