"""Integration tests for the PoW chain (chain/)."""

from __future__ import annotations

import time
from base64 import b64decode, b64encode
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from chain.auditor import audit_chain
from chain.block import (
    BlockHeader,
    leading_zero_bits,
    make_genesis,
    verify_pow,
)
from chain.mining import mine_block, next_difficulty
from chain.node import Node, make_genesis_node
from chain.state import ChainParams, DEFAULT_PARAMS, StateError, apply_block
from chain.transactions import (
    Transaction,
    TxKind,
    decode_tx_list,
    encode_tx_list,
    make_ballot,
    make_close_poll,
    make_coinbase,
    make_publish_ring,
    make_register_voter,
    make_setup_poll,
    make_tally,
    make_transfer,
    sign_tx,
    verify_tx_sig,
)
from otrs import keygen, sign as otrs_sign
from voting.records import (
    Ballot,
    ElectionSetup,
    RingPublication,
    TallyPublication,
    VoterRegistration,
    VotingClosed,
)


# Tests pin difficulty very low (a few bits) so mining is sub-second.
TEST_PARAMS = ChainParams(
    block_reward=50,
    setup_fee=5,
    registration_fee=1,
    ring_fee=1,
    close_fee=1,
    tally_fee=1,
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


def mine_tx(
    node: Node, miner_pk: bytes, tx: Transaction, *, fee: int = 0, ts: int | None = None
) -> None:
    """Mine a single tx into a new block on top of node.tip."""
    if ts is None:
        ts = node.last_timestamp + 1
    height = node.height + 1
    coinbase = make_coinbase(miner_pk, node.params.block_reward + fee, height=height)
    parent_diff = node.chain[-1].difficulty if node.chain else node.params.difficulty_min
    diff = next_difficulty(
        parent_diff,
        node.recent_timestamps(node.params.difficulty_adjust_window),
        params=node.params,
    )
    block = mine_block(
        prev_hash=node.tip_hash,
        height=height,
        difficulty=diff,
        timestamp=ts,
        miner_pk_raw=miner_pk,
        transactions=[coinbase, tx],
    )
    node.append(block)


def mine_empty(node: Node, miner_pk: bytes, *, ts: int | None = None) -> None:
    if ts is None:
        ts = node.last_timestamp + 1
    height = node.height + 1
    coinbase = make_coinbase(miner_pk, node.params.block_reward, height=height)
    parent_diff = node.chain[-1].difficulty if node.chain else node.params.difficulty_min
    diff = next_difficulty(
        parent_diff,
        node.recent_timestamps(node.params.difficulty_adjust_window),
        params=node.params,
    )
    block = mine_block(
        prev_hash=node.tip_hash,
        height=height,
        difficulty=diff,
        timestamp=ts,
        miner_pk_raw=miner_pk,
        transactions=[coinbase],
    )
    node.append(block)


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
        # Tampering invalidates PoW.
        bad = node.chain[-1].header.with_nonce(node.chain[-1].header.nonce + 1)
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


# --------------------------------------------------------------------------- #
# End-to-end election on the chain                                             #
# --------------------------------------------------------------------------- #


@pytest.fixture
def now():
    return int(time.time())


def _build_setup_record(
    creator_pk: bytes, *, now: int, options=("yes", "no"), title="Demo"
) -> ElectionSetup:
    import hashlib
    election_id = hashlib.sha256(creator_pk + title.encode() + str(now).encode()).hexdigest()
    return ElectionSetup(
        election_id=election_id,
        title=title,
        description="demo",
        options=list(options),
        registration_close=now - 120,
        voting_open=now - 60,
        voting_close=now + 86400,
        cohort_pks_b64=[b64encode(creator_pk).decode()],
        threshold=1,
    )


class TestElection:
    def _bootstrap(self, now: int):
        """Genesis funds the miner-creator-sponsor with plenty of eVotes."""
        creator_pk, creator_sk = new_account()
        node = make_genesis_node(
            timestamp=now - 1000,
            miner_pk_raw=creator_pk,
            initial_allocations=[(creator_pk, 1000)],
            difficulty=4,
            params=TEST_PARAMS,
        )
        return creator_pk, creator_sk, node

    def test_full_election_audits_correctly(self, now):
        creator_pk, creator_sk, node = self._bootstrap(now)
        creator_b64 = b64encode(creator_pk).decode()

        setup = _build_setup_record(creator_pk, now=now)
        tx = make_setup_poll(
            creator_pk, setup.to_payload(),
            fee=TEST_PARAMS.setup_fee,
            nonce=node.state.nonce(creator_b64),
            sk=creator_sk,
        )
        mine_tx(node, creator_pk, tx, fee=TEST_PARAMS.setup_fee, ts=now - 500)

        voters = [keygen() for _ in range(3)]
        for i, kp in enumerate(voters):
            reg = VoterRegistration(
                voter_pk_b64=b64encode(kp.pk.point.raw).decode(),
                voter_handle=f"v{i}",
            )
            tx = make_register_voter(
                creator_pk, setup.election_id, reg.to_payload(),
                fee=TEST_PARAMS.registration_fee,
                nonce=node.state.nonce(creator_b64),
                sk=creator_sk,
            )
            mine_tx(node, creator_pk, tx, fee=TEST_PARAMS.registration_fee, ts=now - 400 + i)

        ring = RingPublication(
            ring_b64=sorted({b64encode(kp.pk.point.raw).decode() for kp in voters})
        )
        tx = make_publish_ring(
            creator_pk, setup.election_id, ring.to_payload(),
            fee=TEST_PARAMS.ring_fee,
            nonce=node.state.nonce(creator_b64),
            sk=creator_sk,
        )
        mine_tx(node, creator_pk, tx, fee=TEST_PARAMS.ring_fee, ts=now - 300)

        # Cast ballots — yes, yes, no.
        # Ring published by chain-state, get it back.
        poll = node.state.polls[setup.election_id]
        choices = ["yes", "yes", "no"]
        for kp, choice in zip(voters, choices):
            msg = Ballot.message_for(choice)
            sig = otrs_sign(
                kp.sk, kp.pk, bytes.fromhex(setup.election_id), msg, poll.ring_pks
            )
            ballot = Ballot(
                choice=choice,
                otrs_sig_b64=b64encode(sig.to_bytes()).decode(),
            )
            tx = make_ballot(setup.election_id, ballot.to_payload())
            mine_tx(node, creator_pk, tx, fee=0, ts=now)
            # Advance time by 1s per ballot to keep timestamps strictly increasing.
            now += 1

        # Close at voting_close.
        tx = make_close_poll(
            creator_pk, setup.election_id, VotingClosed().to_payload(),
            fee=TEST_PARAMS.close_fee,
            nonce=node.state.nonce(creator_b64),
            sk=creator_sk,
        )
        mine_tx(node, creator_pk, tx, fee=TEST_PARAMS.close_fee, ts=setup.voting_close + 1)

        chain_file = Path("/tmp/test_chain_full.bin")
        node.save(chain_file)
        report = audit_chain(chain_file, params=TEST_PARAMS)
        assert len(report.polls) == 1
        pr = report.polls[0]
        assert pr.tally == {"yes": 2, "no": 1}
        assert pr.rejected_ballot_heights == []
        assert pr.double_sign_culprits == []
        chain_file.unlink()

    def test_double_sign_detected_on_chain(self, now):
        creator_pk, creator_sk, node = self._bootstrap(now)
        creator_b64 = b64encode(creator_pk).decode()

        setup = _build_setup_record(creator_pk, now=now, options=("a", "b"))
        tx = make_setup_poll(
            creator_pk, setup.to_payload(),
            fee=TEST_PARAMS.setup_fee,
            nonce=node.state.nonce(creator_b64),
            sk=creator_sk,
        )
        mine_tx(node, creator_pk, tx, fee=TEST_PARAMS.setup_fee, ts=now - 500)

        voters = [keygen() for _ in range(3)]
        ts = now - 400
        for i, kp in enumerate(voters):
            reg = VoterRegistration(
                voter_pk_b64=b64encode(kp.pk.point.raw).decode(),
                voter_handle=f"v{i}",
            )
            tx = make_register_voter(
                creator_pk, setup.election_id, reg.to_payload(),
                fee=TEST_PARAMS.registration_fee,
                nonce=node.state.nonce(creator_b64),
                sk=creator_sk,
            )
            mine_tx(node, creator_pk, tx, fee=TEST_PARAMS.registration_fee, ts=ts + i)

        ring = RingPublication(
            ring_b64=sorted({b64encode(kp.pk.point.raw).decode() for kp in voters})
        )
        tx = make_publish_ring(
            creator_pk, setup.election_id, ring.to_payload(),
            fee=TEST_PARAMS.ring_fee,
            nonce=node.state.nonce(creator_b64),
            sk=creator_sk,
        )
        mine_tx(node, creator_pk, tx, fee=TEST_PARAMS.ring_fee, ts=now - 300)

        poll = node.state.polls[setup.election_id]

        # voter 0 double-signs: cast "a" then "b".
        for choice in ("a", "b"):
            msg = Ballot.message_for(choice)
            sig = otrs_sign(
                voters[0].sk, voters[0].pk,
                bytes.fromhex(setup.election_id), msg, poll.ring_pks,
            )
            ballot = Ballot(choice=choice, otrs_sig_b64=b64encode(sig.to_bytes()).decode())
            tx = make_ballot(setup.election_id, ballot.to_payload())
            mine_tx(node, creator_pk, tx, fee=0, ts=now)
            now += 1

        # voter 1 votes "a" honestly.
        msg = Ballot.message_for("a")
        sig = otrs_sign(
            voters[1].sk, voters[1].pk,
            bytes.fromhex(setup.election_id), msg, poll.ring_pks,
        )
        ballot = Ballot(choice="a", otrs_sig_b64=b64encode(sig.to_bytes()).decode())
        tx = make_ballot(setup.election_id, ballot.to_payload())
        mine_tx(node, creator_pk, tx, fee=0, ts=now)

        chain_file = Path("/tmp/test_chain_dbl.bin")
        node.save(chain_file)
        report = audit_chain(chain_file, params=TEST_PARAMS)
        pr = report.polls[0]
        assert pr.tally == {"a": 1, "b": 0}
        assert len(pr.rejected_ballot_heights) == 2
        assert all(r == "double-sign" for _, r in pr.rejected_ballot_heights)
        assert len(pr.double_sign_culprits) == 1
        assert pr.double_sign_culprits[0].point.raw == voters[0].pk.point.raw
        chain_file.unlink()

    def test_chain_replay_through_save_load(self, now):
        creator_pk, creator_sk, node = self._bootstrap(now)
        creator_b64 = b64encode(creator_pk).decode()
        setup = _build_setup_record(creator_pk, now=now)
        tx = make_setup_poll(
            creator_pk, setup.to_payload(),
            fee=TEST_PARAMS.setup_fee,
            nonce=node.state.nonce(creator_b64),
            sk=creator_sk,
        )
        mine_tx(node, creator_pk, tx, fee=TEST_PARAMS.setup_fee, ts=now - 500)
        path = Path("/tmp/test_chain_rt.bin")
        node.save(path)
        loaded = Node.load(path, params=TEST_PARAMS)
        assert loaded.height == node.height
        assert loaded.tip_hash == node.tip_hash
        assert setup.election_id in loaded.state.polls
        path.unlink()
