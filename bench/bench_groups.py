"""
What fixed-size groups buy and what they cost.

Two tables, both on stdout as CSV:

1. ``--cost``: ballot cost as a function of the group size ``k`` for an
   electorate of ``N`` voters. Signature size and verification time are
   linear in ``|g|`` (OTRS at λ = 128: ``5 + 2064·|g|`` bytes), so one ring
   for everybody costs ``O(N²)`` to store and audit while groups cost
   ``O(N·k)``. Verify time is measured at a handful of ring sizes, fitted to
   ``a + b·n`` and summed over the groups that
   :func:`voting.groups.assign_groups` actually forms. ``--scheme`` picks
   ``otrs128`` (default), ``otrs256`` or ``fs07`` for comparison.

2. ``--anonymity``: Monte-Carlo estimate of the anonymity an honest voter
   keeps when a fraction of the registered keys are sybils controlled by
   the adversary (who knows which keys are its own). For round 0 the set is
   the honest members of the voter's group. For a key that arrived by
   transfer, the transfer was signed inside its round-0 group, so the
   observer knows that group; a round-1 ballot hides among the honest
   round-0 members of the origin groups of every key in its round-1 group.
   Reported: mean honest set, and the fraction of honest voters left with
   no honest peer at all (set of size 1).

Run with:
    python3 -m bench.bench_groups --cost --voters 1000 --sizes 0,4,8,16,32
    python3 -m bench.bench_groups --cost --scheme fs07 --voters 1000
    python3 -m bench.bench_groups --anonymity --voters 1000 --sizes 4,8,16 \\
        --sybils 0,0.25,0.5 --transfer 0.5
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, List, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import otrs  # noqa: E402
from voting.groups import assign_groups  # noqa: E402

ISSUE = b"bench-groups"
MSG = b"vote: yes"

OTRS_PARAMS = {"otrs128": otrs.OTRS128, "otrs256": otrs.OTRS256}


def sig_bytes(scheme: str, n: int) -> int:
    if scheme == "fs07":
        return 36 + 64 * n
    return OTRS_PARAMS[scheme].sig_bytes(n)


def pk_bytes(scheme: str) -> int:
    if scheme == "fs07":
        return 32
    return OTRS_PARAMS[scheme].key_bytes


# --------------------------------------------------------------------------- #
# Cost                                                                        #
# --------------------------------------------------------------------------- #


def _verifier(scheme: str, n: int):
    if scheme == "fs07":
        import fs07

        kps = [fs07.keygen() for _ in range(n)]
        ring = [kp.pk for kp in kps]
        sig = fs07.sign(kps[0].sk, kps[0].pk, ISSUE, MSG, ring)
        return lambda: fs07.verify(sig, ISSUE, MSG, ring)
    kps = [otrs.keygen(params=OTRS_PARAMS[scheme]) for _ in range(n)]
    ring = otrs.Ring([kp.pk for kp in kps])
    sig = ring.sign(kps[0], MSG, ISSUE)
    return lambda: ring.verify(sig, MSG, ISSUE)


def _verify_ms(scheme: str, n: int, repeats: int) -> float:
    check = _verifier(scheme, n)
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        assert check()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples) * 1000.0


def fit_verify(scheme: str, probe_sizes: Sequence[int], repeats: int):
    """Least-squares fit of verify time to ``a + b·n`` (milliseconds)."""
    xs = list(probe_sizes)
    ys = [_verify_ms(scheme, n, repeats) for n in xs]
    mx, my = statistics.mean(xs), statistics.mean(ys)
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    return my - b * mx, b


def bench_cost(
    scheme: str, n_voters: int, sizes: Sequence[int], a: float, b: float
) -> List[dict]:
    members = [os.urandom(32) for _ in range(n_voters)]
    rows = []
    for k in sizes:
        groups = assign_groups(members, k, os.urandom(32), ISSUE)
        lens = [len(g) for g in groups]
        audit_ms = sum(m * (a + b * m) for m in lens)
        rows.append({
            "scheme": scheme,
            "voters": n_voters,
            "group_size": k,
            "groups": len(lens),
            "min_group": min(lens),
            "max_group": max(lens),
            "mean_sig_bytes": statistics.mean(
                sig_bytes(scheme, m) for m in lens for _ in range(m)
            ),
            "ballots_mb": sum(m * sig_bytes(scheme, m) for m in lens) / 1e6,
            "keys_mb": n_voters * pk_bytes(scheme) / 1e6,
            "verify_per_ballot_ms": audit_ms / n_voters,
            "audit_all_ballots_s": audit_ms / 1000.0,
        })
    return rows


# --------------------------------------------------------------------------- #
# Anonymity                                                                   #
# --------------------------------------------------------------------------- #


def _simulate(n: int, k: int, sybil: float, transfer: float, rng: random.Random):
    keys = [rng.randbytes(32) for _ in range(n)]
    n_sybil = round(sybil * n)
    honest = set(keys[n_sybil:])

    groups0 = assign_groups(keys, k, rng.randbytes(32), ISSUE)
    group_of: Dict[bytes, int] = {pk: gi for gi, g in enumerate(groups0) for pk in g}
    honest_in = [sum(pk in honest for pk in g) for g in groups0]
    round0 = [honest_in[group_of[pk]] for pk in honest]

    # Round 1: a fraction of the honest voters move to a fresh key; the
    # adversary moves all its sybils so as to sit in as many groups as it can.
    movers = [pk for pk in keys if pk not in honest or rng.random() < transfer]
    new_key = {pk: rng.randbytes(32) for pk in movers}
    origin = {new_key[pk]: group_of[pk] for pk in movers}
    honest_new = {new_key[pk] for pk in movers if pk in honest}
    round1: List[int] = []
    if len(movers) >= 2:
        for g in assign_groups(list(origin), k, rng.randbytes(32), ISSUE + b"/1"):
            origins = {origin[pk] for pk in g}
            hidden_among = sum(honest_in[o] for o in origins)
            round1.extend(hidden_among for pk in g if pk in honest_new)
    return round0, round1


def bench_anonymity(
    n: int, sizes: Sequence[int], sybils: Sequence[float], transfer: float,
    trials: int, seed: int,
) -> List[dict]:
    rng = random.Random(seed)
    rows = []
    for k in sizes:
        for s in sybils:
            r0: List[int] = []
            r1: List[int] = []
            for _ in range(trials):
                a, b = _simulate(n, k, s, transfer, rng)
                r0 += a
                r1 += b
            rows.append({
                "voters": n,
                "group_size": k,
                "sybil_share": s,
                "transfer_share": transfer,
                "r0_mean_honest_set": statistics.mean(r0),
                "r0_isolated": sum(x == 1 for x in r0) / len(r0),
                "r1_mean_honest_set": statistics.mean(r1) if r1 else 0.0,
                "r1_isolated": (sum(x == 1 for x in r1) / len(r1)) if r1 else 0.0,
            })
    return rows


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def _emit(rows: List[dict], output: Path | None) -> None:
    def fmt(v):
        return f"{v:.4f}" if isinstance(v, float) else v

    fieldnames = list(rows[0])
    w = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    w.writeheader()
    for r in rows:
        w.writerow({k: fmt(v) for k, v in r.items()})
    if output:
        with output.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in rows:
                w.writerow({k: fmt(v) for k, v in r.items()})
        print(f"# wrote {output}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--cost", action="store_true")
    p.add_argument("--scheme", default="otrs128", choices=["otrs128", "otrs256", "fs07"])
    p.add_argument("--anonymity", action="store_true")
    p.add_argument("--voters", type=int, default=1000)
    p.add_argument("--sizes", default="0,4,8,16,32",
                   help="Comma-separated group sizes (0 = one ring)")
    p.add_argument("--probe", default="4,16,64,128",
                   help="Ring sizes at which verify time is measured")
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--sybils", default="0,0.25,0.5")
    p.add_argument("--transfer", type=float, default=0.5)
    p.add_argument("--trials", type=int, default=20)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--output", type=Path, default=None)
    args = p.parse_args(argv)
    if not (args.cost or args.anonymity):
        args.cost = True
    sizes = [int(x) for x in args.sizes.split(",") if x.strip()]

    if args.cost:
        a, b = fit_verify(args.scheme, [int(x) for x in args.probe.split(",")], args.repeats)
        print(f"# {args.scheme}: verify_ms ~= {a:.3f} + {b:.4f} * ring_size", file=sys.stderr)
        _emit(bench_cost(args.scheme, args.voters, sizes, a, b), args.output)
    if args.anonymity:
        sybils = [float(x) for x in args.sybils.split(",") if x.strip()]
        rows = bench_anonymity(
            args.voters, [k for k in sizes if k > 0], sybils,
            args.transfer, args.trials, args.seed,
        )
        _emit(rows, args.output if not args.cost else None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
