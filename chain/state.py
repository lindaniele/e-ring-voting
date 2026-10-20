"""
Chain state: account ledger + per-poll election state machine.

The state is the result of folding a sequence of blocks. Applying a block
either succeeds and mutates the state in place, or raises
:class:`StateError` and leaves the state untouched.

This is where the e-ring-voting design lives (see ``paper/artifact.tex``):

* **Deterrence, not just detection.** Registering a voter locks
  ``setup.deposit`` eVotes from the sponsor. A registered key that signs
  two different messages under the same tag is exposed by the FS07 trace
  rule; at the end of the poll its deposit is *burned* (a forfeit: it goes
  to nobody, so no miner profits from including the evidence) and every
  other deposit is refunded.
* **Groups nobody chooses.** Ring signatures are O(n), so voters sign
  inside groups of at least ``setup.group_size`` members, assigned from a
  beacon (the hash of the block preceding the freeze), see
  :mod:`voting.groups`.
* **Key transfer between groups.** In every round but the last, a voter
  may instead sign a :class:`~voting.records.KeyTransfer` that moves their
  voting right to a fresh key, regrouped in the next round.
* **The chain's clock drives the poll.** Phases change at the first block
  whose timestamp crosses ``voting_open``, a round boundary, or
  ``voting_close``; nobody (including the poll creator) can stall the
  freeze, the regrouping, the tally, or the refunds.

Block-level rules
-----------------
* The first transaction MUST be a coinbase. No further coinbases.
* PoW must verify **at the difficulty the adjustment rule prescribes**,
  prev_hash must match the tip, height = tip.height + 1, timestamp >
  parent.timestamp.
* The coinbase amount must equal ``block_reward + sum(fees)``. Deposits
  are escrowed, never paid to the miner.

Transaction-level rules
-----------------------
* Transfers: signed by sender, nonce matches account, sufficient balance.
* Poll setup and voter registration are signed by the creator / sponsor;
  registration carries the voter's proof of possession.
* Ballots and key transfers are unsigned at the chain layer — anonymity
  preserved. The TRS signature inside the payload is what proves validity.
  A message linked to one already recorded (a replay) is invalid, and so is
  any further message from a signer already exposed, so a double-signer can
  add at most one extra message to the chain.
"""

from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass, field, replace
from statistics import median
from typing import Dict, List, Optional, Set, Tuple

from chain.block import Block, block_weight, is_genesis, verify_pow
from chain.transactions import (
    SIGNED_KINDS,
    Transaction,
    TxKind,
    verify_tx_sig,
)
from trs import PublicKey, Signature, verify as trs_verify, verify_possession
from voting.groups import assign_groups, issue_for
from voting.records import (
    Ballot,
    ElectionSetup,
    KeyTransfer,
    RecordError,
    VoterRegistration,
    parse_payload,
)
from voting.tally import EVIDENCE, FRESH, TagBook


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
    target_block_seconds: int = 60
    difficulty_adjust_window: int = 11
    difficulty_min: int = 1
    difficulty_max: int = 32


DEFAULT_PARAMS = ChainParams()


def next_difficulty(
    parent_difficulty: int,
    recent_timestamps: List[int],
    *,
    params: ChainParams = DEFAULT_PARAMS,
) -> int:
    """
    The difficulty the *next* block must carry (a consensus rule).

    ``recent_timestamps`` are the timestamps of the most recent
    ``difficulty_adjust_window`` blocks, oldest first. Until a full window
    exists the difficulty stays at the parent's value. Otherwise (as in the
    legacy node): a median inter-block interval below half the target raises
    difficulty by one bit, above 3/2 of the target lowers it by one.
    Bounded by [difficulty_min, difficulty_max].
    """
    if len(recent_timestamps) < params.difficulty_adjust_window:
        return parent_difficulty
    intervals = [b - a for a, b in zip(recent_timestamps, recent_timestamps[1:])]
    if not intervals:
        return parent_difficulty
    m = median(intervals)
    target = params.target_block_seconds
    if m < target * 0.5:
        new = parent_difficulty + 1
    elif m > target * 1.5:
        new = parent_difficulty - 1
    else:
        new = parent_difficulty
    return max(params.difficulty_min, min(params.difficulty_max, new))


# --------------------------------------------------------------------------- #
# Account ledger and poll state                                                #
# --------------------------------------------------------------------------- #


@dataclass
class Account:
    balance: int = 0
    nonce: int = 0  # number of txs sent — next tx must have nonce == this


@dataclass
class RoundState:
    """One voting round: its groups and the messages signed in each group."""

    beacon: bytes
    groups: List[List[PublicKey]]
    books: List[TagBook]

    def copy(self) -> "RoundState":
        return RoundState(
            beacon=self.beacon,
            groups=self.groups,
            books=[b.copy() for b in self.books],
        )


@dataclass(frozen=True)
class PollResult:
    """Computed by the chain itself at the first block past ``voting_close``."""

    tally: Dict[str, int]
    culprits: List[Tuple[int, str]]   # (round, pk_b64) of exposed double-signers
    slashed: int                      # eVotes burned (round-0 culprits' deposits)
    refunded: int                     # eVotes returned to sponsors
    transfers: List[int]              # accepted key transfers, per round


@dataclass
class PollState:
    election_id: str
    creator_pk_b64: str
    setup: ElectionSetup
    phase: str  # "registration" | "voting" | "closed" | "aborted"
    registrations: List[VoterRegistration] = field(default_factory=list)
    # voter_pk_b64 -> (sponsor_pk_b64, locked amount)
    escrow: Dict[str, Tuple[str, int]] = field(default_factory=dict)
    # every key that is or will be a member of some round (no key twice)
    known_keys: Set[bytes] = field(default_factory=set)
    rounds: List[RoundState] = field(default_factory=list)
    result: Optional[PollResult] = None

    @property
    def current_round(self) -> int:
        return len(self.rounds) - 1

    def copy(self) -> "PollState":
        return replace(
            self,
            registrations=list(self.registrations),
            escrow=dict(self.escrow),
            known_keys=set(self.known_keys),
            rounds=[r.copy() for r in self.rounds],
        )


@dataclass
class State:
    accounts: Dict[str, Account] = field(default_factory=dict)
    polls: Dict[str, PollState] = field(default_factory=dict)
    height: int = -1
    tip_hash: bytes = b""
    last_timestamp: int = 0
    cum_weight: int = 0  # sum of 2^difficulty across all applied blocks
    tip_difficulty: int = 0
    recent_timestamps: List[int] = field(default_factory=list)
    burned: int = 0  # eVotes destroyed by slashing, ever

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
        return replace(
            self,
            accounts={k: Account(balance=v.balance, nonce=v.nonce) for k, v in self.accounts.items()},
            polls={k: v.copy() for k, v in self.polls.items()},
            recent_timestamps=list(self.recent_timestamps),
        )


# --------------------------------------------------------------------------- #
# Poll lifecycle (driven by block timestamps)                                  #
# --------------------------------------------------------------------------- #


def round_at(setup: ElectionSetup, timestamp: int) -> int:
    """The round a timestamp inside [voting_open, voting_close) belongs to."""
    span = setup.voting_close - setup.voting_open
    r = (timestamp - setup.voting_open) * setup.rounds // span
    return max(0, min(setup.rounds - 1, r))


def _open_round(poll: PollState, members: List[bytes], beacon: bytes) -> None:
    r = len(poll.rounds)
    issue = issue_for(poll.election_id, r)
    groups_raw = assign_groups(members, poll.setup.group_size, beacon, issue)
    groups = [[PublicKey.from_bytes(pk) for pk in g] for g in groups_raw]
    poll.rounds.append(
        RoundState(
            beacon=beacon,
            groups=groups,
            books=[TagBook(issue=issue, ring=g) for g in groups],
        )
    )


def _transferred_keys(rnd: RoundState) -> List[bytes]:
    """New keys from this round's transfers whose signer did not double-sign."""
    out: List[bytes] = []
    for book in rnd.books:
        for i in book.classify().accepted:
            record = book.refs[i]
            if isinstance(record, KeyTransfer):
                out.append(b64decode(record.new_pk_b64))
    return out


def _settle(state: State, poll: PollState, slashed_keys: Set[str]) -> Tuple[int, int]:
    slashed = refunded = 0
    for voter_b64, (sponsor_b64, amount) in sorted(poll.escrow.items()):
        if voter_b64 in slashed_keys:
            slashed += amount
        else:
            state.credit(sponsor_b64, amount)
            refunded += amount
    state.burned += slashed
    poll.escrow = {}
    return slashed, refunded


def _finalize(state: State, poll: PollState) -> None:
    tally = {opt: 0 for opt in poll.setup.options}
    culprits: List[Tuple[int, str]] = []
    transfers: List[int] = []
    for r, rnd in enumerate(poll.rounds):
        moved = 0
        for group, book in zip(rnd.groups, rnd.books):
            verdict = book.classify()
            for i in verdict.accepted:
                record = book.refs[i]
                if isinstance(record, Ballot):
                    tally[record.choice] += 1
                else:
                    moved += 1
            culprits.extend(
                (r, b64encode(group[j].point.raw).decode()) for j in verdict.culprits
            )
        transfers.append(moved)
    # Only registered (round-0) keys have a deposit behind them. A key that
    # arrived by transfer is anonymous: its double-sign voids its messages
    # but there is no identity, hence no deposit, to slash.
    slashed, refunded = _settle(state, poll, {pk for r, pk in culprits if r == 0})
    poll.result = PollResult(
        tally=tally,
        culprits=culprits,
        slashed=slashed,
        refunded=refunded,
        transfers=transfers,
    )
    poll.phase = "closed"


def _advance_poll(state: State, poll: PollState, timestamp: int, beacon: bytes) -> None:
    setup = poll.setup
    if poll.phase == "registration" and timestamp >= setup.voting_open:
        members = [b64decode(r.voter_pk_b64) for r in poll.registrations]
        if len(members) < 2:
            _settle(state, poll, set())
            poll.phase = "aborted"
            return
        _open_round(poll, members, beacon)
        poll.phase = "voting"
    if poll.phase != "voting":
        return
    last = setup.rounds - 1 if timestamp >= setup.voting_close else round_at(setup, timestamp)
    while poll.current_round < last:
        _open_round(poll, _transferred_keys(poll.rounds[-1]), beacon)
    if timestamp >= setup.voting_close:
        _finalize(state, poll)


def advance_polls(state: State, timestamp: int, beacon: bytes) -> None:
    """
    Apply every phase change due at the start of a block.

    ``beacon`` is the block's ``prev_hash``: fixed before the block is mined,
    unknown when registrations (or the previous round's transfers) were
    made. Exposed so clients can compute the groups a ballot in the next
    block must use (see :func:`state_for_next_block`).
    """
    for eid in sorted(state.polls):
        _advance_poll(state, state.polls[eid], timestamp, beacon)


def state_for_next_block(state: State, timestamp: int) -> State:
    """A copy of ``state`` as seen by txs of a block at ``timestamp`` on the tip."""
    preview = state.copy()
    advance_polls(preview, timestamp, state.tip_hash)
    return preview


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


def _apply_setup_poll(
    state: State, tx: Transaction, *, params: ChainParams, block_timestamp: int
) -> int:
    body = tx.body
    try:
        fee = int(body["fee"])
        nonce = int(body["nonce"])
        setup_payload = b64decode(str(body["setup_payload_b64"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed setup_poll: {exc}") from exc
    if fee < params.setup_fee:
        raise StateError(f"setup fee {fee} below minimum {params.setup_fee}")
    creator_b64, _ = _consume_fee_and_nonce(state, tx, "creator_pk_b64", fee, nonce)
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
    if record.voting_open <= block_timestamp:
        # Otherwise the freeze (and its beacon) would already be in the past.
        raise StateError("voting_open must lie after the setup block")
    state.polls[record.election_id] = PollState(
        election_id=record.election_id,
        creator_pk_b64=creator_b64,
        setup=record,
        phase="registration",
    )
    return fee


def _apply_register_voter(
    state: State, tx: Transaction, *, params: ChainParams, block_timestamp: int
) -> int:
    body = tx.body
    try:
        fee = int(body["fee"])
        nonce = int(body["nonce"])
        deposit = int(body["deposit"])
        election_id = str(body["election_id"])
        reg_payload = b64decode(str(body["registration_payload_b64"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed register_voter: {exc}") from exc
    if fee < params.registration_fee:
        raise StateError(f"registration fee {fee} below minimum {params.registration_fee}")
    poll = state.polls.get(election_id)
    if poll is None:
        raise StateError(f"unknown election_id {election_id!r}")
    if deposit != poll.setup.deposit:
        raise StateError(f"deposit {deposit} != poll deposit {poll.setup.deposit}")
    sponsor_b64, _ = _consume_fee_and_nonce(state, tx, "sponsor_pk_b64", fee, nonce)
    state.debit(sponsor_b64, deposit)
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
        voter_pk = PublicKey.from_bytes(pk_raw)
    except ValueError as exc:
        raise StateError(f"voter_pk is not a valid Ristretto255 point: {exc}") from exc
    if pk_raw in poll.known_keys:
        raise StateError("voter already registered")
    context = VoterRegistration.pop_context(election_id, record.voter_handle)
    if not verify_possession(voter_pk, context, b64decode(record.pop_sig_b64)):
        raise StateError("registration lacks a valid proof of possession")
    poll.registrations.append(record)
    poll.known_keys.add(pk_raw)
    poll.escrow[record.voter_pk_b64] = (sponsor_b64, deposit)
    return fee


def _apply_anonymous(state: State, tx: Transaction) -> None:
    """A ballot or a key transfer: no sender, no fee; the TRS signature rules."""
    body = tx.body
    try:
        election_id = str(body["election_id"])
        payload = b64decode(str(body["payload_b64"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise StateError(f"malformed {tx.kind}: {exc}") from exc
    poll = state.polls.get(election_id)
    if poll is None:
        raise StateError(f"unknown election_id {election_id!r}")
    if poll.phase != "voting":
        raise StateError(f"poll {election_id[:12]}… not in voting phase")
    try:
        record = parse_payload(payload)
    except RecordError as exc:
        raise StateError(f"{tx.kind} payload invalid: {exc}") from exc
    expected = Ballot if tx.kind == TxKind.BALLOT.value else KeyTransfer
    if not isinstance(record, expected):
        raise StateError(f"{tx.kind} payload must contain {expected.__name__}")
    if record.round != poll.current_round:
        raise StateError(
            f"{tx.kind} for round {record.round}, current round is {poll.current_round}"
        )
    rnd = poll.rounds[record.round]
    if not 0 <= record.group < len(rnd.groups):
        raise StateError(f"no group {record.group} in round {record.round}")

    new_pk_raw = b""
    if isinstance(record, Ballot):
        if record.choice not in poll.setup.options:
            raise StateError(f"choice {record.choice!r} not in options")
        message = Ballot.message_for(record.choice)
    else:
        if record.round >= poll.setup.rounds - 1:
            raise StateError("no key transfers in the last round")
        new_pk_raw = b64decode(record.new_pk_b64)
        try:
            PublicKey.from_bytes(new_pk_raw)
        except ValueError as exc:
            raise StateError(f"new_pk is not a valid Ristretto255 point: {exc}") from exc
        if new_pk_raw in poll.known_keys:
            raise StateError("key transfer target is already a member of this poll")
        message = KeyTransfer.message_for(new_pk_raw)

    try:
        sig = Signature.from_bytes(b64decode(record.trs_sig_b64))
    except (ValueError, Exception) as exc:  # noqa: BLE001
        raise StateError(f"malformed TRS signature: {exc}") from exc
    issue = issue_for(election_id, record.round)
    if not trs_verify(sig, issue, message, rnd.groups[record.group]):
        raise StateError("TRS signature does not verify against the group")
    outcome = rnd.books[record.group].admit(message, sig, ref=record)
    if outcome not in (FRESH, EVIDENCE):
        raise StateError(f"{tx.kind} rejected: {outcome}")
    if new_pk_raw:
        poll.known_keys.add(new_pk_raw)


# --------------------------------------------------------------------------- #
# Block application                                                            #
# --------------------------------------------------------------------------- #


def _record_block(state: State, block: Block, params: ChainParams) -> None:
    state.height = block.height
    state.tip_hash = block.hash
    state.last_timestamp = block.timestamp
    state.cum_weight += block_weight(block.difficulty)
    state.tip_difficulty = block.difficulty
    state.recent_timestamps = (state.recent_timestamps + [block.timestamp])[
        -params.difficulty_adjust_window:
    ]


def _apply_genesis_inner(state: State, block: Block, *, params: ChainParams) -> None:
    if not is_genesis(block):
        raise StateError("first block must be genesis (prev_hash all-zero, height 0)")
    if not params.difficulty_min <= block.difficulty <= params.difficulty_max:
        raise StateError("genesis difficulty outside the protocol bounds")
    for tx in block.transactions:
        if tx.kind != TxKind.COINBASE.value:
            raise StateError("genesis may only contain coinbase transactions")
        _apply_coinbase(state, tx, block_height=0)
    _record_block(state, block, params)


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
    required = next_difficulty(state.tip_difficulty, state.recent_timestamps, params=params)
    if block.difficulty != required:
        raise StateError(f"block difficulty {block.difficulty} != required {required}")
    if not verify_pow(block.header):
        raise StateError("PoW puzzle does not verify")

    txs = block.transactions
    if not txs or txs[0].kind != TxKind.COINBASE.value:
        raise StateError("first transaction must be a coinbase")
    for tx in txs[1:]:
        if tx.kind == TxKind.COINBASE.value:
            raise StateError("only one coinbase per block")

    advance_polls(state, block.timestamp, block.prev_hash)

    fees_collected = 0
    for tx in txs[1:]:
        if tx.kind in SIGNED_KINDS and "signature_b64" not in tx.body:
            raise StateError(f"tx kind {tx.kind} requires a signature")
        if tx.kind == TxKind.TRANSFER.value:
            fees_collected += _apply_transfer(state, tx)
        elif tx.kind == TxKind.SETUP_POLL.value:
            fees_collected += _apply_setup_poll(
                state, tx, params=params, block_timestamp=block.timestamp
            )
        elif tx.kind == TxKind.REGISTER_VOTER.value:
            fees_collected += _apply_register_voter(
                state, tx, params=params, block_timestamp=block.timestamp
            )
        elif tx.kind in (TxKind.BALLOT.value, TxKind.KEY_TRANSFER.value):
            _apply_anonymous(state, tx)
        else:
            raise StateError(f"unknown tx kind {tx.kind!r}")

    minted = _apply_coinbase(state, txs[0], block_height=block.height)
    expected = params.block_reward + fees_collected
    if minted != expected:
        raise StateError(
            f"coinbase amount {minted} != block_reward {params.block_reward} + fees {fees_collected}"
        )
    _record_block(state, block, params)


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
    state.__dict__.update(working.__dict__)


def apply_chain(blocks: List[Block], *, params: ChainParams = DEFAULT_PARAMS) -> State:
    """Fold a chain of blocks into a fresh State."""
    state = State()
    for block in blocks:
        apply_block(state, block, params=params)
    return state
