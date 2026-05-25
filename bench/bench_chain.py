"""
Microbenchmarks for the PoW chain.

Two things we want to measure:

1. **Pure storage-layer cost**: how long it takes to mine and validate a
   block at a given difficulty. The PoW search is the dominant variable
   cost; ledger application is microseconds.

2. **End-to-end election cost**: wall-clock of a complete election on
   the chain (setup, N voter registrations, ring publication, N ballots,
   close, audit). Comparable to the same table for Architecture A in
   ``paper/artifact.tex``.

Difficulty is pinned low (a few leading zero bits) so the benchmark
finishes in seconds rather than minutes. The PoW cost scales as
``2^difficulty`` expected hashes per block; the difficulty knob lets us
extrapolate.

Run with::

    python3 -m bench.bench_chain --voters 5,10,25,50 --difficulty 8
    python3 -m bench.bench_chain --pow-only --difficulty 4,8,12,16
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from base64 import b64encode
from pathlib import Path
from typing import List, Tuple

# Local import path when run from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from chain.auditor import audit_chain
from chain.mining import mine_block, next_difficulty
from chain.node import Node, make_genesis_node
from chain.state import ChainParams
from chain.transactions import (
    Transaction,
    make_ballot,
    make_close_poll,
    make_coinbase,
    make_publish_ring,
    make_register_voter,
    make_setup_poll,
)
from otrs import keygen, sign as otrs_sign
from voting.records import (
    Ballot,
    ElectionSetup,
    RingPublication,
    VoterRegistration,
    VotingClosed,
)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _account() -> Tuple[bytes, ed25519.Ed25519PrivateKey]:
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return pk, sk


def _params(difficulty: int) -> ChainParams:
    # Bound difficulty so PoW never explodes during the bench.
    return ChainParams(
        block_reward=50,
        setup_fee=5,
        registration_fee=1,
        ring_fee=1,
        close_fee=1,
        tally_fee=1,
        target_block_seconds=60,
        difficulty_min=difficulty,
        difficulty_max=difficulty,  # pin difficulty for predictable cost
    )


def _mine_tx(
    node: Node,
    miner_pk: bytes,
    tx: Transaction,
    fee: int,
    timestamp: int,
) -> None:
    coinbase = make_coinbase(miner_pk, node.params.block_reward + fee, height=node.height + 1)
    block = mine_block(
        prev_hash=node.tip_hash,
        height=node.height + 1,
        difficulty=node.params.difficulty_min,
        timestamp=timestamp,
        miner_pk_raw=miner_pk,
        transactions=[coinbase, tx],
    )
    node.append(block)


def _mine_empty(node: Node, miner_pk: bytes, timestamp: int) -> None:
    coinbase = make_coinbase(miner_pk, node.params.block_reward, height=node.height + 1)
    block = mine_block(
        prev_hash=node.tip_hash,
        height=node.height + 1,
        difficulty=node.params.difficulty_min,
        timestamp=timestamp,
        miner_pk_raw=miner_pk,
        transactions=[coinbase],
    )
    node.append(block)


# --------------------------------------------------------------------------- #
# PoW-only microbench                                                          #
# --------------------------------------------------------------------------- #


def bench_pow(difficulties: List[int], repeats: int = 5) -> List[dict]:
    """Measure the wall-clock cost of mining one empty block at each
    difficulty. Reported figures are median over ``repeats`` trials."""
    rows = []
    for d in difficulties:
        params = _params(d)
        miner_pk, _ = _account()
        node = make_genesis_node(
            timestamp=1000,
            miner_pk_raw=miner_pk,
            initial_allocations=[],
            difficulty=d,
            params=params,
        )
        samples = []
        ts = 2000
        for _ in range(repeats):
            t0 = time.perf_counter()
            _mine_empty(node, miner_pk, timestamp=ts)
            samples.append(time.perf_counter() - t0)
            ts += 1
        rows.append({
            "difficulty_bits": d,
            "mine_ms_median": statistics.median(samples) * 1000.0,
            "expected_hashes": 2 ** d,
        })
    return rows


# --------------------------------------------------------------------------- #
# End-to-end election                                                          #
# --------------------------------------------------------------------------- #


def _build_setup(
    creator_pk: bytes, *, registration_close: int,
    voting_open: int, voting_close: int,
    options=("yes", "no"), title="Bench",
) -> ElectionSetup:
    import hashlib
    eid = hashlib.sha256(
        creator_pk + title.encode() + str(registration_close).encode()
    ).hexdigest()
    return ElectionSetup(
        election_id=eid,
        title=title,
        description="bench",
        options=list(options),
        registration_close=registration_close,
        voting_open=voting_open,
        voting_close=voting_close,
        cohort_pks_b64=[b64encode(creator_pk).decode()],
        threshold=1,
    )


def bench_election(voter_counts: List[int], difficulty: int = 8) -> List[dict]:
    """Run a complete election on the chain at each voter count and
    report per-phase wall-clock plus full audit cost."""
    rows = []
    params = _params(difficulty)
    for n in voter_counts:
        miner_pk, _ = _account()
        creator_pk, creator_sk = _account()
        creator_b64 = b64encode(creator_pk).decode()
        # Lay out timestamps so every block can have a strictly increasing
        # timestamp and the lifecycle phases fall in the right windows.
        T_genesis = 1_700_000_000
        T_setup = T_genesis + 100
        # registrations: N blocks at T_setup+1..T_setup+N
        # ring:          T_setup+N+1
        registration_close = T_setup + n + 5
        voting_open = registration_close + 1
        voting_close = voting_open + n + 10  # leave room for N ballots
        T_close = voting_close + 1

        # Genesis with ample creator funding.
        node = make_genesis_node(
            timestamp=T_genesis,
            miner_pk_raw=miner_pk,
            initial_allocations=[(creator_pk, 10000)],
            difficulty=difficulty,
            params=params,
        )

        # ---------- setup ----------
        setup = _build_setup(
            creator_pk,
            registration_close=registration_close,
            voting_open=voting_open,
            voting_close=voting_close,
        )
        ts = T_setup
        t0 = time.perf_counter()
        tx = make_setup_poll(
            creator_pk, setup.to_payload(),
            fee=params.setup_fee,
            nonce=node.state.nonce(creator_b64),
            sk=creator_sk,
        )
        _mine_tx(node, miner_pk, tx, fee=params.setup_fee, timestamp=ts)
        setup_ms = (time.perf_counter() - t0) * 1000.0

        # ---------- register N voters ----------
        voters = [keygen() for _ in range(n)]
        t0 = time.perf_counter()
        for i, kp in enumerate(voters):
            reg = VoterRegistration(
                voter_pk_b64=b64encode(kp.pk.point.raw).decode(),
                voter_handle=f"v{i}",
            )
            ts += 1
            tx = make_register_voter(
                creator_pk, setup.election_id, reg.to_payload(),
                fee=params.registration_fee,
                nonce=node.state.nonce(creator_b64),
                sk=creator_sk,
            )
            _mine_tx(node, miner_pk, tx, fee=params.registration_fee, timestamp=ts)
        register_total_ms = (time.perf_counter() - t0) * 1000.0

        # ---------- publish ring ----------
        ts += 1
        t0 = time.perf_counter()
        ring = RingPublication(
            ring_b64=sorted({b64encode(kp.pk.point.raw).decode() for kp in voters})
        )
        tx = make_publish_ring(
            creator_pk, setup.election_id, ring.to_payload(),
            fee=params.ring_fee,
            nonce=node.state.nonce(creator_b64),
            sk=creator_sk,
        )
        _mine_tx(node, miner_pk, tx, fee=params.ring_fee, timestamp=ts)
        ring_ms = (time.perf_counter() - t0) * 1000.0

        poll = node.state.polls[setup.election_id]

        # ---------- ballots: all N voters cast ----------
        # Jump timestamp into the voting window.
        ts = max(ts + 1, voting_open + 1)
        t0 = time.perf_counter()
        for i, kp in enumerate(voters):
            choice = "yes" if i % 2 == 0 else "no"
            msg = Ballot.message_for(choice)
            sig = otrs_sign(
                kp.sk, kp.pk,
                bytes.fromhex(setup.election_id),
                msg,
                poll.ring_pks,
            )
            ballot = Ballot(
                choice=choice,
                otrs_sig_b64=b64encode(sig.to_bytes()).decode(),
            )
            tx = make_ballot(setup.election_id, ballot.to_payload())
            _mine_tx(node, miner_pk, tx, fee=0, timestamp=ts)
            ts += 1
        ballots_total_ms = (time.perf_counter() - t0) * 1000.0

        # ---------- close ----------
        t0 = time.perf_counter()
        tx = make_close_poll(
            creator_pk, setup.election_id, VotingClosed().to_payload(),
            fee=params.close_fee,
            nonce=node.state.nonce(creator_b64),
            sk=creator_sk,
        )
        _mine_tx(node, miner_pk, tx, fee=params.close_fee, timestamp=T_close)
        close_ms = (time.perf_counter() - t0) * 1000.0

        # ---------- persist + audit (cold reload) ----------
        chain_path = Path("/tmp") / f"bench_chain_{n}.bin"
        node.save(chain_path)
        chain_size_kb = chain_path.stat().st_size / 1024.0

        t0 = time.perf_counter()
        report = audit_chain(chain_path, params=params)
        audit_ms = (time.perf_counter() - t0) * 1000.0
        chain_path.unlink()

        # sanity
        assert len(report.polls) == 1
        rep = report.polls[0]
        expected_yes = (n + 1) // 2
        expected_no = n // 2
        assert rep.tally == {"yes": expected_yes, "no": expected_no}, (
            f"unexpected tally at N={n}: {rep.tally}"
        )

        rows.append({
            "voters": n,
            "setup_ms": setup_ms,
            "register_total_ms": register_total_ms,
            "register_per_voter_ms": register_total_ms / n if n else 0.0,
            "ring_ms": ring_ms,
            "ballots_total_ms": ballots_total_ms,
            "ballot_per_voter_ms": ballots_total_ms / n if n else 0.0,
            "close_ms": close_ms,
            "audit_ms": audit_ms,
            "chain_kb": chain_size_kb,
        })
    return rows


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--pow-only", action="store_true",
                   help="Run only the PoW-cost-vs-difficulty bench")
    p.add_argument("--difficulty", default="8",
                   help=("Comma-separated difficulties (pow-only mode), "
                         "or a single fixed difficulty for end-to-end mode"))
    p.add_argument("--voters", default="5,10,25,50",
                   help="Comma-separated voter counts for end-to-end bench")
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--output", type=Path, default=None,
                   help="Write CSV results here in addition to stdout")
    args = p.parse_args(argv)

    if args.pow_only:
        diffs = [int(s) for s in args.difficulty.split(",") if s.strip()]
        rows = bench_pow(diffs, repeats=args.repeats)
        fieldnames = ["difficulty_bits", "mine_ms_median", "expected_hashes"]
    else:
        diff = int(args.difficulty.split(",")[0])
        voters = [int(s) for s in args.voters.split(",") if s.strip()]
        rows = bench_election(voters, difficulty=diff)
        fieldnames = [
            "voters", "setup_ms", "register_total_ms", "register_per_voter_ms",
            "ring_ms", "ballots_total_ms", "ballot_per_voter_ms",
            "close_ms", "audit_ms", "chain_kb",
        ]

    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        writer.writerow({
            k: (f"{v:.3f}" if isinstance(v, float) else v)
            for k, v in r.items()
        })

    if args.output:
        with args.output.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"# wrote {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
