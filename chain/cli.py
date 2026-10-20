"""
Command-line interface for the PoW chain (``evote-chain``).

Each subcommand that produces a new state mines its transaction into a
fresh block on top of the current tip — so one CLI invocation = one
block. This is simpler for demos and tests; a real deployment would
have a mempool and let miners batch transactions.

There is no command to publish the ring, close the poll or publish the
tally: the chain does those itself at the first block past
``voting_open`` / each round boundary / ``voting_close``. ``mine-empty``
with a ``--timestamp`` past the deadline is enough to trigger them.

Quickstart::

    python3 -m chain.cli account-keygen --out alice.json
    python3 -m chain.cli account-keygen --out miner.json
    python3 -m chain.cli voter-keygen   --out v0.json

    python3 -m chain.cli init-chain --chain chain.bin --miner miner.json \\
        --allocate $(jq -r .pk_b64 alice.json):1000

    python3 -m chain.cli setup-poll --chain chain.bin --miner miner.json \\
        --creator alice.json --title "Demo" --options "yes,no" \\
        --registration-close T0 --voting-open T1 --voting-close T2 \\
        --group-size 3 --rounds 2 --deposit 10

    python3 -m chain.cli register-voter --chain chain.bin --miner miner.json \\
        --sponsor alice.json --election-id <id> --voter v0.json --handle v0

    python3 -m chain.cli vote --chain chain.bin --miner miner.json \\
        --voter v0.json --election-id <id> --choice yes
    python3 -m chain.cli transfer --chain chain.bin --miner miner.json \\
        --voter v1.json --new-voter v1b.json --election-id <id>

    python3 -m chain.cli mine-empty --chain chain.bin --miner miner.json \\
        --timestamp T2
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
from chain.client import ballot_tx, key_transfer_tx, registration_tx
from chain.mining import mine_block, next_difficulty
from chain.node import Node, make_genesis_node
from chain.state import ChainParams, DEFAULT_PARAMS, StateError, state_for_next_block
from chain.transactions import Transaction, make_coinbase, make_setup_poll
from trs import KeyPair, keygen as trs_keygen
from trs.group import Scalar
from trs.trs import PublicKey as TrsPublicKey, SecretKey as TrsSecretKey
from voting.records import ElectionSetup


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


def _load_voter(path: Path) -> KeyPair:
    blob = json.loads(path.read_text())
    pk = TrsPublicKey.from_bytes(b64decode(blob["pk_b64"]))
    sk = TrsSecretKey(Scalar(b64decode(blob["sk_b64"])))
    return KeyPair(sk=sk, pk=pk)


def _save_voter(path: Path, kp: KeyPair) -> None:
    path.write_text(json.dumps({
        "kind": "trs",
        "pk_b64": b64encode(kp.pk.point.raw).decode(),
        "sk_b64": b64encode(kp.sk.x.raw).decode(),
    }, indent=2))


# --------------------------------------------------------------------------- #
# Block-building helper                                                        #
# --------------------------------------------------------------------------- #


def _block_timestamp(node: Node, requested: int | None) -> int:
    if node.height < 0:
        sys.exit("no genesis on chain — run `init-chain` first")
    if requested is not None:
        return requested
    # Strictly greater than parent timestamp.
    return max(int(time.time()), node.last_timestamp + 1)


def _mine(
    node: Node,
    miner_pk_raw: bytes,
    txs: List[Transaction],
    *,
    fees: int,
    timestamp: int,
) -> None:
    """Mine ``[coinbase, *txs]`` on the current tip at the required difficulty."""
    height = node.height + 1
    coinbase = make_coinbase(miner_pk_raw, node.params.block_reward + fees, height=height)
    difficulty = next_difficulty(
        node.state.tip_difficulty, node.state.recent_timestamps, params=node.params
    )
    block = mine_block(
        prev_hash=node.tip_hash,
        height=height,
        difficulty=difficulty,
        timestamp=timestamp,
        miner_pk_raw=miner_pk_raw,
        transactions=[coinbase, *txs],
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
    kp = trs_keygen()
    _save_voter(Path(args.out), kp)
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
    _mine(node, miner_pk_raw, [], fees=0, timestamp=_block_timestamp(node, args.timestamp))
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
        group_size=args.group_size,
        rounds=args.rounds,
        deposit=args.deposit,
    )
    setup.validate()
    creator_b64 = b64encode(creator_pk_raw).decode()
    tx = make_setup_poll(
        creator_pk_raw,
        setup.to_payload(),
        fee=args.fee,
        nonce=node.state.nonce(creator_b64),
        sk=creator_sk,
    )
    _mine(node, miner_pk_raw, [tx], fees=args.fee,
          timestamp=_block_timestamp(node, args.timestamp))
    node.save(Path(args.chain))
    print(election_id)


def cmd_register_voter(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    miner_pk_raw, _ = _load_account(Path(args.miner))
    sponsor_pk_raw, sponsor_sk = _load_account(Path(args.sponsor))
    poll = node.state.polls.get(args.election_id)
    if poll is None:
        sys.exit(f"unknown election_id {args.election_id!r}")
    tx = registration_tx(
        sponsor_pk_raw=sponsor_pk_raw,
        sponsor_sk=sponsor_sk,
        election_id=args.election_id,
        voter=_load_voter(Path(args.voter)),
        handle=args.handle,
        fee=args.fee,
        deposit=poll.setup.deposit,
        nonce=node.state.nonce(b64encode(sponsor_pk_raw).decode()),
    )
    _mine(node, miner_pk_raw, [tx], fees=args.fee,
          timestamp=_block_timestamp(node, args.timestamp))
    node.save(Path(args.chain))
    print(f"registered voter {args.handle} (deposit {poll.setup.deposit} locked)")


def _poll_for_next_block(node: Node, election_id: str, timestamp: int):
    poll = state_for_next_block(node.state, timestamp).polls.get(election_id)
    if poll is None:
        sys.exit(f"unknown election_id {election_id!r}")
    return poll


def cmd_vote(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    miner_pk_raw, _ = _load_account(Path(args.miner))
    timestamp = _block_timestamp(node, args.timestamp)
    poll = _poll_for_next_block(node, args.election_id, timestamp)
    if args.choice not in poll.setup.options:
        sys.exit(f"choice {args.choice!r} not in options {poll.setup.options}")
    try:
        tx = ballot_tx(poll, _load_voter(Path(args.voter)), args.choice)
    except ValueError as exc:
        sys.exit(str(exc))
    _mine(node, miner_pk_raw, [tx], fees=0, timestamp=timestamp)
    node.save(Path(args.chain))
    print(f"ballot for {args.choice!r} sealed in block {node.height}")


def cmd_transfer(args: argparse.Namespace) -> None:
    node = Node.load(Path(args.chain), params=_params_from_args(args))
    miner_pk_raw, _ = _load_account(Path(args.miner))
    timestamp = _block_timestamp(node, args.timestamp)
    poll = _poll_for_next_block(node, args.election_id, timestamp)
    new_voter = _load_voter(Path(args.new_voter))
    try:
        tx = key_transfer_tx(poll, _load_voter(Path(args.voter)), new_voter.pk)
    except ValueError as exc:
        sys.exit(str(exc))
    _mine(node, miner_pk_raw, [tx], fees=0, timestamp=timestamp)
    node.save(Path(args.chain))
    print(f"voting right moved to a new key for round {poll.current_round + 1}")


def cmd_audit(args: argparse.Namespace) -> None:
    report = audit_chain(Path(args.chain), params=_params_from_args(args))
    print(
        f"chain: height={report.chain_height}  cum_weight={report.chain_weight}"
        f"  burned={report.burned}"
    )
    for poll in report.polls:
        print(
            f"poll {poll.election_id[:16]}…  phase={poll.phase}"
            f"  registered={poll.registered}  groups={poll.group_sizes}"
        )
        if poll.tally is None:
            print("  tally: not yet (poll still open)")
            continue
        print(f"  tally: {dict(sorted(poll.tally.items()))}")
        print(f"  key transfers per round: {poll.transfers}")
        for r, pk_b64 in poll.culprits:
            print(f"  double-signer in round {r}: {pk_b64}")
        print(f"  deposits: {poll.slashed} burned, {poll.refunded} refunded")


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
        print(
            f"  {eid[:16]}…  phase={poll.phase}  regs={len(poll.registrations)}"
            f"  round={poll.current_round}"
        )


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

    sp = sub.add_parser("mine-empty", help="mine a block (also triggers due poll deadlines)")
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
    sp.add_argument("--group-size", type=int, default=0, help="0 = one ring for all")
    sp.add_argument("--rounds", type=int, default=1, help=">1 enables key transfers")
    sp.add_argument("--deposit", type=int, default=0, help="eVotes locked per voter")
    sp.add_argument("--election-id", default=None)
    sp.add_argument("--fee", type=int, default=DEFAULT_PARAMS.setup_fee)
    sp.set_defaults(func=cmd_setup_poll)

    sp = sub.add_parser("register-voter")
    add_chain(sp)
    sp.add_argument("--sponsor", required=True, help="account paying fee + deposit")
    sp.add_argument("--election-id", required=True)
    sp.add_argument("--voter", required=True, help="voter key file (signs the proof of possession)")
    sp.add_argument("--handle", required=True)
    sp.add_argument("--fee", type=int, default=DEFAULT_PARAMS.registration_fee)
    sp.set_defaults(func=cmd_register_voter)

    sp = sub.add_parser("vote")
    add_chain(sp)
    sp.add_argument("--voter", required=True)
    sp.add_argument("--election-id", required=True)
    sp.add_argument("--choice", required=True)
    sp.set_defaults(func=cmd_vote)

    sp = sub.add_parser("transfer", help="move this round's voting right to a new key")
    add_chain(sp)
    sp.add_argument("--voter", required=True)
    sp.add_argument("--new-voter", required=True, help="key file of the fresh key")
    sp.add_argument("--election-id", required=True)
    sp.set_defaults(func=cmd_transfer)

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
