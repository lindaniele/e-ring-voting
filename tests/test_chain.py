"""Integration tests for the PoW chain (chain/)."""

from __future__ import annotations

import hashlib
from base64 import b64decode, b64encode
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from chain.auditor import audit_chain
from chain.block import BlockHeader, leading_zero_bits, verify_pow
from chain.client import ballot_tx, key_transfer_tx, locate, registration_tx
from chain.mining import mine_block, next_difficulty
from chain.node import Node, make_genesis_node
from chain.state import ChainParams, StateError, state_for_next_block
from chain.transactions import (
    Transaction,
    TxKind,
    decode_tx_list,
    encode_tx_list,
    make_ballot,
    make_coinbase,
    make_setup_poll,
    make_transfer,
    sign_tx,
    verify_tx_sig,
)
from trs import keygen, prove_possession
from voting.records import Ballot, ElectionSetup, VoterRegistration


# Tests pin difficulty very low (a few bits) so mining is sub-second.
TEST_PARAMS = ChainParams(
    block_reward=50,
    setup_fee=5,
    registration_fee=1,
    target_block_seconds=60,
    difficulty_min=1,
    difficulty_max=8,
)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def new_account() -> tuple[bytes, ed25519.Ed25519PrivateKey]:
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return pk, sk


def mine_txs(
    node: Node, miner_pk: bytes, txs=(), *, fees: int = 0, ts: int | None = None,
    difficulty: int | None = None,
) -> None:
    """Mine ``txs`` into a new block on top of node.tip, at the required difficulty."""
    if ts is None:
        ts = node.last_timestamp + 1
    height = node.height + 1
    coinbase = make_coinbase(miner_pk, node.params.block_reward + fees, height=height)
    if difficulty is None:
        difficulty = next_difficulty(
            node.state.tip_difficulty, node.state.recent_timestamps, params=node.params
        )
    block = mine_block(
        prev_hash=node.tip_hash,
        height=height,
        difficulty=difficulty,
        timestamp=ts,
        miner_pk_raw=miner_pk,
        transactions=[coinbase, *txs],
    )
    node.append(block)


def mine_tx(node: Node, miner_pk: bytes, tx: Transaction, *, fee: int = 0, ts: int | None = None) -> None:
    mine_txs(node, miner_pk, [tx], fees=fee, ts=ts)


def mine_empty(node: Node, miner_pk: bytes, *, ts: int | None = None) -> None:
    mine_txs(node, miner_pk, [], ts=ts)


# --------------------------------------------------------------------------- #
# Block / PoW primitives                                                       #
# --------------------------------------------------------------------------- #


class TestPoW:
    def test_leading_zero_bits(self):
        assert leading_zero_bits(b"\x00\x00\xff") == 16
        assert leading_zero_bits(b"\x01\xff") == 7
        assert leading_zero_bits(b"\xff") == 0
        assert leading_zero_bits(b"\x00\x80") == 8

    def test_header_roundtrip(self):
        h = BlockHeader(
            prev_hash=b"\x00" * 32,
            height=1,
            difficulty=4,
            timestamp=12345,
            miner_pk=b"\x01" * 32,
            tx_root=b"\x02" * 32,
            nonce=42,
        )
        assert BlockHeader.decode(h.encode()) == h

    def test_mining_produces_valid_pow(self):
        miner_pk, _ = new_account()
        node = make_genesis_node(
            timestamp=1000, miner_pk_raw=miner_pk, initial_allocations=[],
            difficulty=4, params=TEST_PARAMS,
        )
        mine_empty(node, miner_pk, ts=1001)
        assert verify_pow(node.chain[-1].header)
        # Not every nonce works: find a neighbour that fails the puzzle.
        header = node.chain[-1].header
        bad = next(
            header.with_nonce(header.nonce + k)
            for k in range(1, 1000)
            if leading_zero_bits(header.with_nonce(header.nonce + k).hash()) < header.difficulty
        )
        assert not verify_pow(bad)


# --------------------------------------------------------------------------- #
# Transactions                                                                 #
# --------------------------------------------------------------------------- #


class TestTransactions:
    def test_tx_canonical_bytes_stable(self):
        pk, sk = new_account()
        tx1 = make_transfer(pk, [(pk, 10)], fee=1, nonce=0, sk=sk)
        tx2 = make_transfer(pk, [(pk, 10)], fee=1, nonce=0, sk=sk)
        # Ed25519 is deterministic — same body, same signature, same id.
        assert tx1.id == tx2.id

    def test_tx_list_roundtrip(self):
        pk, sk = new_account()
        coinbase = make_coinbase(pk, 50, height=1)
        transfer = make_transfer(pk, [(pk, 5)], fee=1, nonce=0, sk=sk)
        blob = encode_tx_list([coinbase, transfer])
        decoded, consumed = decode_tx_list(blob, 2)
        assert consumed == len(blob)
        assert decoded[0].kind == TxKind.COINBASE.value
        assert decoded[1].kind == TxKind.TRANSFER.value
        assert decoded[0].canonical_bytes() == coinbase.canonical_bytes()
        assert decoded[1].canonical_bytes() == transfer.canonical_bytes()

    def test_sign_and_verify(self):
        pk, sk = new_account()
        tx = sign_tx(TxKind.TRANSFER.value, {"x": 1, "nonce": 0}, sk)
        assert verify_tx_sig(tx, pk)

    def test_tampered_signature_fails(self):
        pk, sk = new_account()
        tx = sign_tx(TxKind.TRANSFER.value, {"x": 1, "nonce": 0}, sk)
        # Mutate the body before re-verification.
        bad = Transaction(kind=tx.kind, body={**tx.body, "x": 2})
        assert not verify_tx_sig(bad, pk)


# --------------------------------------------------------------------------- #
# Ledger                                                                       #
# --------------------------------------------------------------------------- #


class TestLedger:
    def test_genesis_allocations_credit_accounts(self):
        miner, _ = new_account()
        alice, _ = new_account()
        bob, _ = new_account()
        node = make_genesis_node(
            timestamp=1000, miner_pk_raw=miner,
            initial_allocations=[(alice, 100), (bob, 50)],
            difficulty=4, params=TEST_PARAMS,
        )
        assert node.state.balance(b64encode(alice).decode()) == 100
        assert node.state.balance(b64encode(bob).decode()) == 50

    def test_coinbase_credits_miner(self):
        miner, _ = new_account()
        node = make_genesis_node(
            timestamp=1000, miner_pk_raw=miner, initial_allocations=[],
            difficulty=4, params=TEST_PARAMS,
        )
        mine_empty(node, miner, ts=1001)
        assert node.state.balance(b64encode(miner).decode()) == TEST_PARAMS.block_reward

    def test_transfer_moves_value(self):
        miner, miner_sk = new_account()
        bob, _ = new_account()
        node = make_genesis_node(
            timestamp=1000, miner_pk_raw=miner,
            initial_allocations=[(miner, 100)],
            difficulty=4, params=TEST_PARAMS,
        )
        tx = make_transfer(miner, [(bob, 30)], fee=2, nonce=0, sk=miner_sk)
        mine_tx(node, miner, tx, fee=2, ts=1001)
        # miner: 100 - 30 - 2 + (50 reward + 2 fee) = 120
        assert node.state.balance(b64encode(miner).decode()) == 100 - 30 - 2 + 50 + 2
        assert node.state.balance(b64encode(bob).decode()) == 30

    def test_double_spend_rejected(self):
        miner, miner_sk = new_account()
        bob, _ = new_account()
        node = make_genesis_node(
            timestamp=1000, miner_pk_raw=miner,
            initial_allocations=[(miner, 10)],
            difficulty=4, params=TEST_PARAMS,
        )
        tx = make_transfer(miner, [(bob, 100)], fee=1, nonce=0, sk=miner_sk)
        with pytest.raises(StateError, match="insufficient balance"):
            mine_tx(node, miner, tx, fee=1, ts=1001)

    def test_nonce_replay_rejected(self):
        miner, miner_sk = new_account()
        bob, _ = new_account()
        node = make_genesis_node(
            timestamp=1000, miner_pk_raw=miner,
            initial_allocations=[(miner, 100)],
            difficulty=4, params=TEST_PARAMS,
        )
        tx0 = make_transfer(miner, [(bob, 10)], fee=1, nonce=0, sk=miner_sk)
        mine_tx(node, miner, tx0, fee=1, ts=1001)
        # Re-submitting tx0 (same nonce) must fail.
        with pytest.raises(StateError, match="nonce mismatch"):
            mine_tx(node, miner, tx0, fee=1, ts=1002)

    def test_bad_signature_rejected(self):
        miner, miner_sk = new_account()
        bob, _ = new_account()
        node = make_genesis_node(
            timestamp=1000, miner_pk_raw=miner,
            initial_allocations=[(miner, 100)],
            difficulty=4, params=TEST_PARAMS,
        )
        tx = make_transfer(miner, [(bob, 10)], fee=1, nonce=0, sk=miner_sk)
        # Tamper with the body after signing.
        bad = Transaction(kind=tx.kind, body={**tx.body, "fee": 99})
        with pytest.raises(StateError, match="signature"):
            mine_tx(node, miner, bad, fee=99, ts=1001)


class TestDifficultyRule:
    def _node(self):
        miner, _ = new_account()
        node = make_genesis_node(
            timestamp=1000, miner_pk_raw=miner, initial_allocations=[],
            difficulty=4, params=TEST_PARAMS,
        )
        return miner, node

    def test_block_must_carry_required_difficulty(self):
        # Regression: any self-declared difficulty, even 0, used to be accepted.
        miner, node = self._node()
        for wrong in (0, 3, 5):
            with pytest.raises(StateError, match="difficulty"):
                mine_txs(node, miner, ts=1001, difficulty=wrong)
        mine_txs(node, miner, ts=1001)
        assert node.chain[-1].difficulty == 4

    def test_difficulty_rises_when_blocks_come_too_fast(self):
        miner, node = self._node()
        for i in range(TEST_PARAMS.difficulty_adjust_window + 2):
            mine_empty(node, miner, ts=1001 + i)
        assert node.chain[-1].difficulty > 4

    def test_genesis_difficulty_bounded(self):
        miner, _ = new_account()
        with pytest.raises(StateError, match="genesis difficulty"):
            make_genesis_node(
                timestamp=1000, miner_pk_raw=miner, initial_allocations=[],
                difficulty=TEST_PARAMS.difficulty_max + 1, params=TEST_PARAMS,
            )


class TestForkChoice:
    def _fork(self, base: Node, miner: bytes, blocks: int, start_ts: int) -> Node:
        fork = Node(params=TEST_PARAMS)
        fork.append(base.chain[0])
        for i in range(blocks):
            mine_empty(fork, miner, ts=start_ts + i)
        return fork

    def test_heavier_valid_chain_wins(self):
        miner, _ = new_account()
        node = make_genesis_node(
            timestamp=1000, miner_pk_raw=miner, initial_allocations=[],
            difficulty=4, params=TEST_PARAMS,
        )
        mine_empty(node, miner, ts=1001)
        mine_empty(node, miner, ts=1002)
        lighter = self._fork(node, miner, 1, 1100)
        heavier = self._fork(node, miner, 3, 1100)
        assert node.consider(lighter.chain) is False
        assert node.consider(heavier.chain) is True
        assert node.tip_hash == heavier.tip_hash

    def test_invalid_fork_is_refused(self):
        miner, _ = new_account()
        node = make_genesis_node(
            timestamp=1000, miner_pk_raw=miner, initial_allocations=[],
            difficulty=4, params=TEST_PARAMS,
        )
        fork = self._fork(node, miner, 2, 1100)
        tampered = list(fork.chain)
        tampered[1] = mine_block(
            prev_hash=tampered[0].hash, height=1, difficulty=1, timestamp=1100,
            miner_pk_raw=miner,
            transactions=[make_coinbase(miner, TEST_PARAMS.block_reward, height=1)],
        )
        with pytest.raises(StateError):
            node.consider(tampered)


# --------------------------------------------------------------------------- #
# Polls: deterrence, groups, key transfers                                     #
# --------------------------------------------------------------------------- #


T0 = 1_000_000
REG_CLOSE = T0 + 100
OPEN = T0 + 200
CLOSE = T0 + 400
FUNDS = 10_000


class Election:
    """A poll on a fresh chain; the sponsor (= creator) and the miner differ."""

    def __init__(self, *, voters=4, group_size=0, rounds=1, deposit=10,
                 options=("yes", "no")):
        self.miner, _ = new_account()
        self.creator, self.creator_sk = new_account()
        self.creator_b64 = b64encode(self.creator).decode()
        self.node = make_genesis_node(
            timestamp=T0, miner_pk_raw=self.miner,
            initial_allocations=[(self.creator, FUNDS)],
            difficulty=4, params=TEST_PARAMS,
        )
        self.setup = ElectionSetup(
            election_id=hashlib.sha256(self.creator).hexdigest(),
            title="Demo", description="", options=list(options),
            registration_close=REG_CLOSE, voting_open=OPEN, voting_close=CLOSE,
            cohort_pks_b64=[self.creator_b64], threshold=1,
            group_size=group_size, rounds=rounds, deposit=deposit,
        )
        self.eid = self.setup.election_id
        tx = make_setup_poll(
            self.creator, self.setup.to_payload(), fee=TEST_PARAMS.setup_fee,
            nonce=self.node.state.nonce(self.creator_b64), sk=self.creator_sk,
        )
        mine_tx(self.node, self.miner, tx, fee=TEST_PARAMS.setup_fee, ts=T0 + 1)
        self.voters = [keygen() for _ in range(voters)]
        for i, kp in enumerate(self.voters):
            self.register(kp, f"v{i}")

    def register(self, kp, handle):
        tx = registration_tx(
            sponsor_pk_raw=self.creator, sponsor_sk=self.creator_sk,
            election_id=self.eid, voter=kp, handle=handle,
            fee=TEST_PARAMS.registration_fee, deposit=self.setup.deposit,
            nonce=self.node.state.nonce(self.creator_b64),
        )
        mine_tx(self.node, self.miner, tx, fee=TEST_PARAMS.registration_fee)

    @property
    def poll(self):
        return self.node.state.polls[self.eid]

    def poll_at(self, ts):
        """The poll as the transactions of a block at ``ts`` will see it."""
        return state_for_next_block(self.node.state, ts).polls[self.eid]

    def vote(self, kp, choice, ts):
        mine_tx(self.node, self.miner, ballot_tx(self.poll_at(ts), kp, choice), ts=ts)

    def transfer(self, kp, new_kp, ts):
        mine_tx(self.node, self.miner, key_transfer_tx(self.poll_at(ts), kp, new_kp.pk), ts=ts)

    def close(self):
        mine_empty(self.node, self.miner, ts=CLOSE)
        return self.poll.result

    def sponsor_balance(self):
        return self.node.state.balance(self.creator_b64)


def b64pk(kp) -> str:
    return b64encode(kp.pk.point.raw).decode()


class TestSingleRing:
    def test_full_election_tallies_and_refunds(self, tmp_path):
        e = Election(voters=3, deposit=10)
        assert e.sponsor_balance() == FUNDS - 5 - 3 * (1 + 10)
        for i, choice in enumerate(["yes", "yes", "no"]):
            e.vote(e.voters[i], choice, OPEN + i)
        result = e.close()
        assert result.tally == {"yes": 2, "no": 1}
        assert result.culprits == [] and result.slashed == 0
        assert result.refunded == 30
        assert e.sponsor_balance() == FUNDS - 5 - 3 * 1
        # An independent replay of the saved chain reaches the same verdict.
        path = tmp_path / "c.bin"
        e.node.save(path)
        report = audit_chain(path, params=TEST_PARAMS)
        (pr,) = report.polls
        assert pr.phase == "closed" and pr.tally == {"yes": 2, "no": 1}

    def test_double_vote_burns_the_deposit(self):
        e = Election(voters=4, deposit=10, options=("a", "b", "c"))
        cheater = e.voters[0]
        e.vote(cheater, "a", OPEN)
        e.vote(cheater, "b", OPEN + 1)          # evidence: exposes the key
        with pytest.raises(StateError, match="saturated"):
            e.vote(cheater, "c", OPEN + 2)      # nothing more to learn: invalid
        e.vote(e.voters[1], "a", OPEN + 3)
        e.vote(e.voters[2], "c", OPEN + 4)
        result = e.close()
        assert result.tally == {"a": 1, "b": 0, "c": 1}
        assert result.culprits == [(0, b64pk(cheater))]
        assert result.slashed == 10 and e.node.state.burned == 10
        assert result.refunded == 30
        # Burned, not paid out: the sponsor gets back three deposits of four.
        assert e.sponsor_balance() == FUNDS - 5 - 4 * (1 + 10) + 30

    def test_replayed_ballot_is_invalid(self):
        e = Election(voters=3)
        tx = ballot_tx(e.poll_at(OPEN), e.voters[0], "yes")
        mine_tx(e.node, e.miner, tx, ts=OPEN)
        with pytest.raises(StateError, match="replay"):
            mine_tx(e.node, e.miner, tx, ts=OPEN + 1)
        with pytest.raises(StateError, match="replay"):
            e.vote(e.voters[0], "yes", OPEN + 1)  # fresh signature, same message
        e.vote(e.voters[1], "no", OPEN + 1)
        assert e.close().tally == {"yes": 1, "no": 1}

    def test_poll_with_one_registrant_aborts_and_refunds(self):
        e = Election(voters=1, deposit=10)
        mine_empty(e.node, e.miner, ts=OPEN)
        assert e.poll.phase == "aborted"
        assert e.sponsor_balance() == FUNDS - 5 - 1

    def test_ballot_after_close_is_invalid(self):
        e = Election(voters=2)
        tx = ballot_tx(e.poll_at(OPEN), e.voters[0], "yes")
        e.close()
        with pytest.raises(StateError, match="not in voting phase"):
            mine_tx(e.node, e.miner, tx, ts=CLOSE + 1)


class TestRegistration:
    def _tx(self, e, voter, pop_record):
        from chain.transactions import make_register_voter
        return make_register_voter(
            e.creator, e.eid, pop_record.to_payload(), fee=1,
            deposit=e.setup.deposit, nonce=e.node.state.nonce(e.creator_b64),
            sk=e.creator_sk,
        )

    def test_proof_of_possession_required(self):
        e = Election(voters=0)
        victim, attacker = keygen(), keygen()
        # A sponsor cannot register a key whose secret it does not hold.
        forged = prove_possession(
            attacker.sk, victim.pk, VoterRegistration.pop_context(e.eid, "x")
        )
        record = VoterRegistration(
            voter_pk_b64=b64pk(victim), voter_handle="x",
            pop_sig_b64=b64encode(forged).decode(),
        )
        with pytest.raises(StateError, match="proof of possession"):
            mine_tx(e.node, e.miner, self._tx(e, victim, record), fee=1)
        # Nor replay a proof made for another handle.
        other = prove_possession(
            victim.sk, victim.pk, VoterRegistration.pop_context(e.eid, "y")
        )
        record = VoterRegistration(
            voter_pk_b64=b64pk(victim), voter_handle="x",
            pop_sig_b64=b64encode(other).decode(),
        )
        with pytest.raises(StateError, match="proof of possession"):
            mine_tx(e.node, e.miner, self._tx(e, victim, record), fee=1)

    def test_deposit_must_match_the_poll(self):
        e = Election(voters=0, deposit=10)
        with pytest.raises(StateError, match="deposit"):
            mine_tx(e.node, e.miner, registration_tx(
                sponsor_pk_raw=e.creator, sponsor_sk=e.creator_sk,
                election_id=e.eid, voter=keygen(), handle="v", fee=1, deposit=0,
                nonce=e.node.state.nonce(e.creator_b64),
            ), fee=1)

    def test_same_key_twice_rejected(self):
        e = Election(voters=2)
        with pytest.raises(StateError, match="already registered"):
            e.register(e.voters[0], "again")


class TestGroups:
    def test_every_voter_lands_in_one_group_of_min_size(self):
        e = Election(voters=10, group_size=3)
        poll = e.poll_at(OPEN)
        sizes = sorted(len(g) for g in poll.rounds[0].groups)
        assert sizes == [3, 3, 4]
        members = [pk.point.raw for g in poll.rounds[0].groups for pk in g]
        assert sorted(members) == sorted(kp.pk.point.raw for kp in e.voters)

    def test_ballots_are_signed_per_group_and_tallied_together(self):
        e = Election(voters=10, group_size=3)
        for i, kp in enumerate(e.voters):
            e.vote(kp, "yes" if i % 3 else "no", OPEN + i)
        result = e.close()
        assert result.tally == {"yes": 6, "no": 4}
        # Signatures are O(group), not O(electorate).
        assert all(len(g) <= 5 for g in e.poll.rounds[0].groups)

    def test_ballot_must_name_its_own_group(self):
        e = Election(voters=10, group_size=3)
        poll = e.poll_at(OPEN)
        tx = ballot_tx(poll, e.voters[0], "yes")
        record = Ballot.from_obj(__import__("json").loads(b64decode(tx.body["payload_b64"])))
        _, mine = locate(poll, e.voters[0].pk)
        other = (mine + 1) % len(poll.rounds[0].groups)
        moved = Ballot(choice="yes", trs_sig_b64=record.trs_sig_b64, round=0, group=other)
        with pytest.raises(StateError, match="does not verify"):
            mine_tx(e.node, e.miner, make_ballot(e.eid, moved.to_payload()), ts=OPEN)


class TestKeyTransfer:
    def test_transfer_moves_the_vote_to_the_next_round(self):
        e = Election(voters=6, group_size=3, rounds=2)
        new0, new1 = keygen(), keygen()
        e.transfer(e.voters[0], new0, OPEN)
        e.transfer(e.voters[1], new1, OPEN + 1)
        e.vote(e.voters[2], "yes", OPEN + 2)
        round1 = T0 + 300
        poll = e.poll_at(round1)
        assert poll.current_round == 1
        assert sorted(pk.point.raw for g in poll.rounds[1].groups for pk in g) == sorted(
            [new0.pk.point.raw, new1.pk.point.raw]
        )
        with pytest.raises(ValueError, match="not a member"):
            locate(poll, e.voters[0].pk)   # the old key has spent its right
        e.vote(new0, "no", round1)
        e.vote(new1, "yes", round1 + 1)
        result = e.close()
        assert result.tally == {"yes": 2, "no": 1}
        assert result.transfers == [2, 0]
        assert result.culprits == [] and result.refunded == 60

    def test_vote_and_transfer_is_a_double_sign(self):
        e = Election(voters=6, group_size=3, rounds=2, deposit=10)
        cheater, escape = e.voters[0], keygen()
        e.transfer(cheater, escape, OPEN)
        e.vote(cheater, "yes", OPEN + 1)
        poll = e.poll_at(T0 + 300)
        assert poll.rounds[1].groups == []          # the transfer is void
        result = e.close()
        assert result.tally == {"yes": 0, "no": 0}
        assert result.culprits == [(0, b64pk(cheater))]
        assert result.slashed == 10

    def test_round_discipline(self):
        e = Election(voters=4, rounds=2)
        moved = keygen()
        e.transfer(e.voters[1], moved, OPEN)
        stale = ballot_tx(e.poll_at(OPEN + 1), e.voters[0], "yes")
        with pytest.raises(StateError, match="current round is 1"):
            mine_tx(e.node, e.miner, stale, ts=T0 + 300)
        with pytest.raises(StateError, match="last round"):
            mine_tx(e.node, e.miner, key_transfer_tx(
                e.poll_at(T0 + 300), moved, keygen().pk), ts=T0 + 300)

    def test_transfer_target_must_be_new(self):
        e = Election(voters=4, rounds=2)
        with pytest.raises(StateError, match="already a member"):
            e.transfer(e.voters[0], e.voters[1], OPEN)
