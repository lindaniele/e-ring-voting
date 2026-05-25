"""
Microbenchmarks for OTRS: sign / verify / trace cost vs ring size.

Run with:
    python -m bench.bench_otrs              # default sizes
    python -m bench.bench_otrs --sizes 2,4,8,16,32

The output is a CSV table on stdout and a printed summary; pipe to a file or
into ``bench/results/`` if you want to keep it. We deliberately keep this in
the standard library so the benchmark itself never crashes when ``numpy`` /
``matplotlib`` are absent.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from pathlib import Path
from typing import Iterable

# Local import path when run from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from otrs import keygen, sign, trace, verify  # noqa: E402


def _bench(fn, *args, repeat: int = 5):
    """Return median wall-clock seconds over ``repeat`` runs."""
    samples = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        out = fn(*args)
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples), out


def benchmark(sizes: Iterable[int], repeats: int = 5):
    issue = b"bench-2026-05-24"
    msg = b"vote: A"
    rows = []
    for n in sizes:
        ring_kp = [keygen() for _ in range(n)]
        ring = [kp.pk for kp in ring_kp]
        signer = ring_kp[0]

        sign_t, sig = _bench(sign, signer.sk, signer.pk, issue, msg, ring, repeat=repeats)
        verify_t, ok = _bench(verify, sig, issue, msg, ring, repeat=repeats)
        sig2 = sign(signer.sk, signer.pk, issue, b"vote: B", ring)
        trace_t, _ = _bench(trace, issue, ring, msg, sig, b"vote: B", sig2, repeat=repeats)
        size_bytes = len(sig.to_bytes())
        rows.append(
            {
                "ring_size": n,
                "sign_ms": sign_t * 1000.0,
                "verify_ms": verify_t * 1000.0,
                "trace_ms": trace_t * 1000.0,
                "sig_bytes": size_bytes,
            }
        )
        if not ok:
            raise RuntimeError(f"verify failed at n={n}; aborting bench")
    return rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--sizes",
        default="2,4,8,16,32,64",
        help="Comma-separated ring sizes",
    )
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--output", type=Path, default=None, help="Write CSV here")
    args = p.parse_args(argv)

    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    rows = benchmark(sizes, repeats=args.repeats)

    fieldnames = ["ring_size", "sign_ms", "verify_ms", "trace_ms", "sig_bytes"]
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()
    for r in rows:
        writer.writerow(
            {
                "ring_size": r["ring_size"],
                "sign_ms": f"{r['sign_ms']:.3f}",
                "verify_ms": f"{r['verify_ms']:.3f}",
                "trace_ms": f"{r['trace_ms']:.3f}",
                "sig_bytes": r["sig_bytes"],
            }
        )

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
