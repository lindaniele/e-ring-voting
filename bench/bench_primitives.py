"""
The two traceable ring signatures side by side: cost against ring size.

* ``otrs128`` / ``otrs256``: Scafuro–Zhang one-time traceable ring
  signature (:mod:`otrs`), the primitive the voting design uses, at
  λ = 128 and λ = 256. Pure Python + hashlib SHAKE256.
* ``fs07``: Fujisaki–Suzuki traceable ring signature (:mod:`fs07`) over
  Ristretto255 via libsodium, the scheme of the 2021–22 prototype, kept for
  comparison.

For each scheme and ring size: key generation, sign, verify and trace time
(median of ``--repeats``), public-key and signature size. CSV on stdout.

Run with::

    python3 -m bench.bench_primitives
    python3 -m bench.bench_primitives --schemes otrs128,fs07 --sizes 2,8,64
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import otrs  # noqa: E402

CTX = b"bench-primitives"
M1, M2 = b"ballot-v1yes", b"ballot-v1no"


def _median_ms(fn: Callable[[], object], repeats: int) -> float:
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples) * 1000.0


def _otrs_row(params, n: int, repeats: int) -> Dict:
    keygen_ms = _median_ms(lambda: otrs.keygen(params=params), repeats)
    kps = [otrs.keygen(params=params) for _ in range(n)]
    ring = otrs.Ring([kp.pk for kp in kps])
    signer = kps[-1]
    sign_ms = _median_ms(lambda: ring.sign(signer, M1, CTX), repeats)
    sig = ring.sign(signer, M1, CTX)
    verify_ms = _median_ms(lambda: ring.verify(sig, M1, CTX), repeats)
    sig2 = ring.sign(signer, M2, CTX)
    assert ring.verify(sig, M1, CTX) and ring.trace(sig, sig2).culprits == (n - 1,)
    # Trace as the chain does it: openings are kept from verification, so
    # tracing a pair is one XOR scan.
    o1, o2 = ring.check(sig, M1, CTX), ring.check(sig2, M2, CTX)
    trace_ms = _median_ms(lambda: ring.trace(sig, sig2), repeats)
    trace_cached_ms = _median_ms(lambda: ring.culprits(o1, o2), repeats)
    return {
        "keygen_ms": keygen_ms, "sign_ms": sign_ms, "verify_ms": verify_ms,
        "trace_ms": trace_ms, "trace_cached_ms": trace_cached_ms,
        "pk_bytes": len(kps[0].pk.to_bytes()), "sig_bytes": len(sig.to_bytes()),
    }


def _fs07_row(n: int, repeats: int) -> Dict:
    import fs07

    keygen_ms = _median_ms(fs07.keygen, repeats)
    kps = [fs07.keygen() for _ in range(n)]
    ring = [kp.pk for kp in kps]
    s = kps[-1]
    sign_ms = _median_ms(lambda: fs07.sign(s.sk, s.pk, CTX, M1, ring), repeats)
    sig = fs07.sign(s.sk, s.pk, CTX, M1, ring)
    verify_ms = _median_ms(lambda: fs07.verify(sig, CTX, M1, ring), repeats)
    sig2 = fs07.sign(s.sk, s.pk, CTX, M2, ring)
    assert fs07.trace(CTX, ring, M1, sig, M2, sig2).status == "double-sign"
    trace_ms = _median_ms(lambda: fs07.trace(CTX, ring, M1, sig, M2, sig2), repeats)
    return {
        "keygen_ms": keygen_ms, "sign_ms": sign_ms, "verify_ms": verify_ms,
        "trace_ms": trace_ms, "trace_cached_ms": float("nan"),
        "pk_bytes": 32, "sig_bytes": len(sig.to_bytes()),
    }


SCHEMES = {
    "otrs128": lambda n, r: _otrs_row(otrs.OTRS128, n, r),
    "otrs256": lambda n, r: _otrs_row(otrs.OTRS256, n, r),
    "fs07": _fs07_row,
}

FIELDS = ["scheme", "ring_size", "keygen_ms", "sign_ms", "verify_ms", "trace_ms",
          "trace_cached_ms", "pk_bytes", "sig_bytes"]


def benchmark(schemes: List[str], sizes: List[int], repeats: int) -> List[Dict]:
    rows = []
    for name in schemes:
        for n in sizes:
            rows.append({"scheme": name, "ring_size": n, **SCHEMES[name](n, repeats)})
    return rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--schemes", default="otrs128,otrs256,fs07")
    p.add_argument("--sizes", default="2,4,8,16,32,64")
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--output", type=Path, default=None)
    args = p.parse_args(argv)
    schemes = [s for s in args.schemes.split(",") if s]
    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    rows = benchmark(schemes, sizes, args.repeats)

    def fmt(v):
        return f"{v:.3f}" if isinstance(v, float) else v

    def emit(out):
        w = csv.DictWriter(out, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: fmt(v) for k, v in r.items()})

    emit(sys.stdout)
    if args.output:
        with args.output.open("w", newline="") as f:
            emit(f)
        print(f"# wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
