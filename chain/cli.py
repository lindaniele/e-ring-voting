"""
Command-line interface for the PoW chain (``evote-chain``).

Each subcommand that produces a new state mines its transaction into a
fresh block on top of the current tip — so one CLI invocation = one
block. This is simpler for demos and tests; a real deployment would
have a mempool and let miners batch transactions.

Quickstart::

    python3 -m chain.cli account-keygen --out alice.json
    python3 -m chain.cli account-keygen --out bob.json
    python3 -m chain.cli voter-keygen   --out v0.json
    python3 -m chain.cli voter-keygen   --out v1.json

    python3 -m chain.cli init-chain --chain chain.bin --miner alice.json \\
        --allocate $(jq -r .pk_b64 alice.json):1000

    python3 -m chain.cli setup-poll --chain chain.bin --miner alice.json \\
        --creator alice.json --title "Demo" --options "yes,no" \\
        --registration-close T0 --voting-open T1 --voting-close T2

    python3 -m chain.cli register-voter --chain chain.bin --miner alice.json \\
        --sponsor alice.json --election-id <id> \\
        --voter-pk $(jq -r .pk_b64 v0.json) --handle v0

    python3 -m chain.cli publish-ring --chain chain.bin --miner alice.json \\
        --creator alice.json --election-id <id>

    python3 -m chain.cli vote --chain chain.bin --miner alice.json \\
        --voter v0.json --election-id <id> --choice yes

    python3 -m chain.cli close-poll --chain chain.bin --miner alice.json \\
        --creator alice.json --election-id <id>

    python3 -m chain.cli audit --chain chain.bin
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from base64 import b64decode, b64encode
from pathlib import Path
from typing import List, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from chain.auditor import audit_chain
from chain.mining import mine_block, next_difficulty
from chain.node import Node, make_genesis_node
from chain.state import ChainParams, DEFAULT_PARAMS, StateError
from chain.transactions import (
    Transaction,
    make_ballot,
    make_close_poll,
    make_coinbase,
    make_publish_ring,
    make_register_voter,
    make_setup_poll,
    make_tally,
    make_transfer,
)
from otrs import keygen as otrs_keygen, sign as otrs_sign
from otrs.otrs import PublicKey as OtrsPublicKey, SecretKey as OtrsSecretKey
from voting.records import (
    Ballot,
    ElectionSetup,
    RingPublication,
    TallyPublication,
    VoterRegistration,
    VotingClosed,
)


# --------------------------------------------------------------------------- #
# Key file helpers                                                             #
# --------------------------------------------------------------------------- #


def _load_account(path: Path) -> Tuple[bytes, ed25519.Ed25519PrivateKey]:
    blob = json.loads(path.read_text())
    sk_raw = b64decode(blob["sk_b64"])
    pk_raw = b64decode(blob["pk_b64"])
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(sk_raw)
    return pk_raw, sk


def _save_account(path: Path, sk: ed25519.Ed25519PrivateKey) -> None:
    pk = sk.public_key()
    sk_raw = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pk_raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    path.write_text(json.dumps({
        "kind": "ed25519",
        "sk_b64": b64encode(sk_raw).decode(),
        "pk_b64": b64encode(pk_raw).decode(),
    }, indent=2))


def _load_voter(path: Path) -> Tuple[OtrsPublicKey, OtrsSecretKey]:
    from otrs.group import Scalar
    blob = json.loads(path.read_text())
    pk = OtrsPublicKey.from_bytes(b64decode(blob["pk_b64"]))
    sk = OtrsSecretKey(Scalar(b64decode(blob["sk_b64"])))
    return pk, sk


def _save_voter(path: Path, pk: OtrsPublicKey, sk: OtrsSecretKey) -> None:
    path.write_text(json.dumps({
        "kind": "otrs",
        "pk_b64": b64encode(pk.point.raw).decode(),
        "sk_b64": b64encode(sk.x.raw).decode(),
    }, indent=2))


# --------------------------------------------------------------------------- #
# Block-building helper                                                        #
# --------------------------------------------------------------------------- #


def _mine_one_tx(
    node: Node,
    miner_pk_raw: bytes,
    tx: Transaction,
    *,
    fee: int = 0,
    timestamp: int | None = None,
) -> None:
    """Build & mine a block containing exactly ``[coinbase, tx]`` on the current tip."""
    if node.height < 0:
        sys.exit("no genesis on chain — run `init-chain` first")
    if timestamp is None:
        # Strictly greater than parent timestamp.
        timestamp = max(int(time.time()), node.last_timestamp + 1)
    height = node.height + 1
    coinbase = make_coinbase(
        miner_pk_raw,
        node.params.block_reward + fee,
        height=height,
    )
    transactions = [coinbase, tx]
    parent_diff = node.chain[-1].difficulty if node.chain else node.params.difficulty_min
    difficulty = next_difficulty(
        parent_diff,
        node.recent_timestamps(node.params.difficulty_adjust_window),
        params=node.params,
    )
    block = mine_block(
        prev_hash=node.tip_hash,
        height=height,
        difficulty=difficulty,
        timestamp=timestamp,
        miner_pk_raw=miner_pk_raw,
        transactions=transactions,
    )
    node.append(block)


def _mine_empty(node: Node, miner_pk_raw: bytes, *, timestamp: int | None = None) -> None:
    """Mine a block whose only tx is the coinbase."""
    if node.height < 0:
        sys.exit("no genesis on chain — run `init-chain` first")
    if timestamp is None:
        timestamp = max(int(time.time()), node.last_timestamp + 1)
    height = node.height + 1
    coinbase = make_coinbase(miner_pk_raw, node.params.block_reward, height=height)
    parent_diff = node.chain[-1].difficulty if node.chain else node.params.difficulty_min
    difficulty = next_difficulty(
        parent_diff,
        node.recent_timestamps(node.params.difficulty_adjust_window),
        params=node.params,
    )
    block = mine_block(
        prev_hash=node.tip_hash,
        height=height,
        difficulty=difficulty,
        timestamp=timestamp,
        miner_pk_raw=miner_pk_raw,
        transactions=[coinbase],
    )
    node.append(block)


# --------------------------------------------------------------------------- #
# Subcommand handlers                                                          #
# --------------------------------------------------------------------------- #


def cmd_account_keygen(args: argparse.Namespace) -> None:
    sk = ed25519.Ed25519PrivateKey.generate()
    _save_account(Path(args.out), sk)
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print(b64encode(pk).decode())


def cmd_voter_keygen(args: argparse.Namespace) -> None:
    kp = otrs_keygen()
    _save_voter(Path(args.out), kp.pk, kp.sk)
    print(b64encode(kp.pk.point.raw).decode())


def cmd_init_chain(args: argparse.Namespace) -> None:
    miner_pk_raw, _ = _load_account(Path(args.miner))
    allocations: List[Tuple[bytes, int]] = []
    if args.allocate:
        for spec in args.allocate.split(","):
            pk_b64, amount = spec.rsplit(":", 1)
            allocations.append((b64decode(pk_b64), int(amount)))
    timestamp = args.timestamp or int(time.time())
    node = make_genesis_node(
        timestamp=timestamp,
        miner_pk_raw=miner_pk_raw,
        initial_allocations=allocations,
        difficulty=args.difficulty,
        params=_params_from_args(args),
    )
    node.save(Path(args.chain))
    print(f"genesis @ height 0, tip {node.tip_hash.hex()[:16]}…")


def cmd_mine_empty(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    miner_pk_raw, _ = _load_account(Path(args.miner))
    _mine_empty(node, miner_pk_raw, timestamp=args.timestamp)
    node.save(Path(args.chain))
    print(f"mined empty block @ height {node.height}, tip {node.tip_hash.hex()[:16]}…")


def cmd_setup_poll(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    miner_pk_raw, _ = _load_account(Path(args.miner))
    creator_pk_raw, creator_sk = _load_account(Path(args.creator))
    election_id = (
        args.election_id
        if args.election_id
        else _derive_election_id(creator_pk_raw, args.title, args.registration_close)
    )
    setup = ElectionSetup(
        election_id=election_id,
        title=args.title,
        description=args.description,
        options=args.options.split(","),
        registration_close=args.registration_close,
        voting_open=args.voting_open,
        voting_close=args.voting_close,
        # On the chain, the "cohort" degenerates to the single poll creator;
        # we still populate the field for record-format compatibility.
        cohort_pks_b64=[b64encode(creator_pk_raw).decode()],
        threshold=1,
    )
    setup.validate()
    creator_b64 = b64encode(creator_pk_raw).decode()
    nonce = node.state.nonce(creator_b64)
    tx = make_setup_poll(
        creator_pk_raw,
        setup.to_payload(),
        fee=args.fee,
        nonce=nonce,
        sk=creator_sk,
    )
    _mine_one_tx(node, miner_pk_raw, tx, fee=args.fee, timestamp=args.timestamp)
    node.save(Path(args.chain))
    print(election_id)


def cmd_register_voter(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    miner_pk_raw, _ = _load_account(Path(args.miner))
    sponsor_pk_raw, sponsor_sk = _load_account(Path(args.sponsor))
    reg = VoterRegistration(voter_pk_b64=args.voter_pk, voter_handle=args.handle)
    sponsor_b64 = b64encode(sponsor_pk_raw).decode()
    nonce = node.state.nonce(sponsor_b64)
    tx = make_register_voter(
        sponsor_pk_raw,
        args.election_id,
        reg.to_payload(),
        fee=args.fee,
        nonce=nonce,
        sk=sponsor_sk,
    )
    _mine_one_tx(node, miner_pk_raw, tx, fee=args.fee, timestamp=args.timestamp)
    node.save(Path(args.chain))
    print(f"registered voter {args.handle}")


def cmd_publish_ring(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    miner_pk_raw, _ = _load_account(Path(args.miner))
    creator_pk_raw, creator_sk = _load_account(Path(args.creator))
    poll = node.state.polls.get(args.election_id)
    if poll is None:
        sys.exit(f"unknown election_id {args.election_id!r}")
    ring_pks_b64 = sorted({r.voter_pk_b64 for r in poll.registrations})
    if args.shuffle:
        import secrets
        # Deterministic shuffle is unnecessary on-chain since the ring set
        # is what matters for verification, but a stable order means
        # everyone agrees on the ordered tuple. We sort by default.
        secrets.SystemRandom().shuffle(ring_pks_b64)
    ring = RingPublication(ring_b64=ring_pks_b64)
    creator_b64 = b64encode(creator_pk_raw).decode()
    nonce = node.state.nonce(creator_b64)
    tx = make_publish_ring(
        creator_pk_raw,
        args.election_id,
        ring.to_payload(),
        fee=args.fee,
        nonce=nonce,
        sk=creator_sk,
    )
    _mine_one_tx(node, miner_pk_raw, tx, fee=args.fee, timestamp=args.timestamp)
    node.save(Path(args.chain))
    print(f"ring of {len(ring_pks_b64)} voters published")


def cmd_vote(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    miner_pk_raw, _ = _load_account(Path(args.miner))
    voter_pk, voter_sk = _load_voter(Path(args.voter))
    poll = node.state.polls.get(args.election_id)
    if poll is None:
        sys.exit(f"unknown election_id {args.election_id!r}")
    if poll.ring_pks is None:
        sys.exit("ring not yet published")
    if args.choice not in poll.setup.options:
        sys.exit(f"choice {args.choice!r} not in options {poll.setup.options}")
    msg = Ballot.message_for(args.choice)
    sig = otrs_sign(
        voter_sk, voter_pk, bytes.fromhex(poll.setup.election_id), msg, poll.ring_pks
    )
    ballot = Ballot(choice=args.choice, otrs_sig_b64=b64encode(sig.to_bytes()).decode())
    tx = make_ballot(args.election_id, ballot.to_payload())
    _mine_one_tx(node, miner_pk_raw, tx, fee=0, timestamp=args.timestamp)
    node.save(Path(args.chain))
    print(f"ballot for {args.choice!r} sealed in block {node.height}")


def cmd_close_poll(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    miner_pk_raw, _ = _load_account(Path(args.miner))
    creator_pk_raw, creator_sk = _load_account(Path(args.creator))
    creator_b64 = b64encode(creator_pk_raw).decode()
    nonce = node.state.nonce(creator_b64)
    tx = make_close_poll(
        creator_pk_raw,
        args.election_id,
        VotingClosed().to_payload(),
        fee=args.fee,
        nonce=nonce,
        sk=creator_sk,
    )
    _mine_one_tx(node, miner_pk_raw, tx, fee=args.fee, timestamp=args.timestamp)
    node.save(Path(args.chain))
    print(f"poll {args.election_id[:12]}… closed at height {node.height}")


def cmd_tally(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    miner_pk_raw, _ = _load_account(Path(args.miner))
    creator_pk_raw, creator_sk = _load_account(Path(args.creator))
    poll = node.state.polls.get(args.election_id)
    if poll is None:
        sys.exit(f"unknown election_id {args.election_id!r}")
    # Recompute the tally locally to publish a faithful claim.
    from chain.auditor import _audit_poll, build_tally_record
    report = _audit_poll(poll)
    record = build_tally_record(report)
    creator_b64 = b64encode(creator_pk_raw).decode()
    nonce = node.state.nonce(creator_b64)
    tx = make_tally(
        creator_pk_raw,
        args.election_id,
        record.to_payload(),
        fee=args.fee,
        nonce=nonce,
        sk=creator_sk,
    )
    _mine_one_tx(node, miner_pk_raw, tx, fee=args.fee, timestamp=args.timestamp)
    node.save(Path(args.chain))
    print(json.dumps(record.tally, indent=2))


def cmd_audit(args: argparse.Namespace) -> None:
    report = audit_chain(Path(args.chain), params=_params_from_args(args))
    print(f"chain: height={report.chain_height}  cum_weight={report.chain_weight}")
    for poll in report.polls:
        print(f"poll {poll.election_id[:16]}…  phase={poll.phase}  ring={len(poll.ring)}")
        print(f"  tally: {dict(sorted(poll.tally.items()))}")
        if poll.double_sign_culprits:
            print(f"  double-sign culprits: {len(poll.double_sign_culprits)}")
        if poll.claimed_tally is not None:
            agree = poll.tally_matches_claim()
            tag = "AGREES" if agree else "MISMATCH"
            print(f"  claimed tally {tag}: {poll.claimed_tally.tally}")
            if not agree:
                sys.exit(1)


def cmd_show(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    print(f"height={node.height}")
    print(f"tip={node.tip_hash.hex()}")
    print(f"cum_weight={node.state.cum_weight}")
    print(f"accounts: {len(node.state.accounts)}")
    for pk_b64, acc in sorted(node.state.accounts.items()):
        print(f"  {pk_b64[:16]}…  bal={acc.balance}  nonce={acc.nonce}")
    print(f"polls: {len(node.state.polls)}")
    for eid, poll in node.state.polls.items():
        print(f"  {eid[:16]}…  phase={poll.phase}  regs={len(poll.registrations)}  ballots={len(poll.ballots)}")


# --------------------------------------------------------------------------- #
# Misc helpers                                                                 #
# --------------------------------------------------------------------------- #


def _derive_election_id(creator_pk_raw: bytes, title: str, t: int) -> str:
    import hashlib
    h = hashlib.sha256()
    h.update(creator_pk_raw)
    h.update(title.encode("utf-8"))
    h.update(t.to_bytes(8, "big"))
    return h.hexdigest()


def _params_from_args(args: argparse.Namespace) -> ChainParams:
    # All params are protocol constants in this prototype. Exposed here as
    # a single hook so tests can dial difficulty down without touching the
    # CLI body.
    return DEFAULT_PARAMS


# --------------------------------------------------------------------------- #
# Argparse plumbing                                                            #
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evote-chain", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_chain(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--chain", required=True, help="path to chain file")
        sp.add_argument("--miner", required=True, help="path to miner account .json")
        sp.add_argument("--timestamp", type=int, default=None, help="block timestamp")

    sp = sub.add_parser("account-keygen")
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=cmd_account_keygen)

    sp = sub.add_parser("voter-keygen")
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=cmd_voter_keygen)

    sp = sub.add_parser("init-chain")
    sp.add_argument("--chain", required=True)
    sp.add_argument("--miner", required=True)
    sp.add_argument("--allocate", default="", help="comma-separated pk_b64:amount")
    sp.add_argument("--timestamp", type=int, default=None)
    sp.add_argument("--difficulty", type=int, default=4)
    sp.set_defaults(func=cmd_init_chain)

    sp = sub.add_parser("mine-empty")
    add_chain(sp)
    sp.set_defaults(func=cmd_mine_empty)

    sp = sub.add_parser("setup-poll")
    add_chain(sp)
    sp.add_argument("--creator", required=True)
    sp.add_argument("--title", required=True)
    sp.add_argument("--description", default="")
    sp.add_argument("--options", required=True, help="comma-separated")
    sp.add_argument("--registration-close", type=int, required=True)
    sp.add_argument("--voting-open", type=int, required=True)
    sp.add_argument("--voting-close", type=int, required=True)
    sp.add_argument("--election-id", default=None)
    sp.add_argument("--fee", type=int, default=DEFAULT_PARAMS.setup_fee)
    sp.set_defaults(func=cmd_setup_poll)

    sp = sub.add_parser("register-voter")
    add_chain(sp)
    sp.add_argument("--sponsor", required=True)
    sp.add_argument("--election-id", required=True)
    sp.add_argument("--voter-pk", required=True)
    sp.add_argument("--handle", required=True)
    sp.add_argument("--fee", type=int, default=DEFAULT_PARAMS.registration_fee)
    sp.set_defaults(func=cmd_register_voter)

    sp = sub.add_parser("publish-ring")
    add_chain(sp)
    sp.add_argument("--creator", required=True)
    sp.add_argument("--election-id", required=True)
    sp.add_argument("--shuffle", action="store_true")
    sp.add_argument("--fee", type=int, default=DEFAULT_PARAMS.ring_fee)
    sp.set_defaults(func=cmd_publish_ring)

    sp = sub.add_parser("vote")
    add_chain(sp)
    sp.add_argument("--voter", required=True)
    sp.add_argument("--election-id", required=True)
    sp.add_argument("--choice", required=True)
    sp.set_defaults(func=cmd_vote)

    sp = sub.add_parser("close-poll")
    add_chain(sp)
    sp.add_argument("--creator", required=True)
    sp.add_argument("--election-id", required=True)
    sp.add_argument("--fee", type=int, default=DEFAULT_PARAMS.close_fee)
    sp.set_defaults(func=cmd_close_poll)

    sp = sub.add_parser("tally")
    add_chain(sp)
    sp.add_argument("--creator", required=True)
    sp.add_argument("--election-id", required=True)
    sp.add_argument("--fee", type=int, default=DEFAULT_PARAMS.tally_fee)
    sp.set_defaults(func=cmd_tally)

    sp = sub.add_parser("audit")
    sp.add_argument("--chain", required=True)
    sp.set_defaults(func=cmd_audit)

    sp = sub.add_parser("show")
    sp.add_argument("--chain", required=True)
    sp.set_defaults(func=cmd_show)

    return p


def main(argv: List[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except StateError as exc:
        sys.exit(f"state error: {exc}")


if __name__ == "__main__":
    main()
