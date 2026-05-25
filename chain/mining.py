"""
PoW miner + difficulty adjustment.

The miner is single-process for simplicity (the legacy code used a
multiprocessing pool; for tests and demos a single Python thread is
more than enough at the difficulties we run). Difficulty is adjusted
once per block based on the median interval over a sliding window.

Mining a real PoW chain in Python is slow; the tests pin difficulty
low (around 8-10 bits) so each block solves in a fraction of a second.
"""

from __future__ import annotations

import os
from statistics import median
from typing import List, Optional

from chain.block import (
    Block,
    BlockHeader,
    block_weight,
    leading_zero_bits,
    verify_pow,
)
from chain.state import ChainParams, DEFAULT_PARAMS
from chain.transactions import Transaction, tx_list_root


def next_difficulty(
    parent_difficulty: int,
    recent_timestamps: List[int],
    *,
    params: ChainParams = DEFAULT_PARAMS,
) -> int:
    """
    Compute the difficulty for the *next* block.

    ``recent_timestamps`` is the list of timestamps for the most recent
    ``difficulty_adjust_window`` blocks, oldest first. If we don't yet
    have a full window, difficulty stays at the parent's value.

    Rule (mirrors legacy/mining/block.py): if the median inter-block
    interval falls *below* 1/2 the target, raise difficulty by one;
    if it exceeds 3/2 the target, lower it by one; otherwise unchanged.
    Bounded by [difficulty_min, difficulty_max].
    """
    if len(recent_timestamps) < params.difficulty_adjust_window:
        return parent_difficulty
    intervals = [
        b - a for a, b in zip(recent_timestamps, recent_timestamps[1:])
    ]
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


def assemble_block(
    *,
    prev_hash: bytes,
    height: int,
    difficulty: int,
    timestamp: int,
    miner_pk_raw: bytes,
    transactions: List[Transaction],
) -> BlockHeader:
    """Build the header (nonce=0) for a block whose body is ``transactions``."""
    return BlockHeader(
        prev_hash=prev_hash,
        height=height,
        difficulty=difficulty,
        timestamp=timestamp,
        miner_pk=miner_pk_raw,
        tx_root=tx_list_root(transactions),
        nonce=0,
    )


def mine(
    header_template: BlockHeader,
    *,
    max_iters: Optional[int] = None,
    nonce_start: Optional[int] = None,
) -> BlockHeader:
    """
    Search for a nonce that satisfies the PoW puzzle.

    Returns the header with the winning nonce set. Raises ``RuntimeError``
    if ``max_iters`` is exhausted (only used in tests to bail out fast).

    The search starts at a random 64-bit offset by default; in production
    miners would pick non-overlapping ranges so multiple miners don't
    waste work on the same nonces.
    """
    if nonce_start is None:
        nonce_start = int.from_bytes(os.urandom(8), "big")
    nonce = nonce_start & ((1 << 64) - 1)
    iters = 0
    while True:
        candidate = header_template.with_nonce(nonce)
        h = candidate.hash()
        if leading_zero_bits(h) >= header_template.difficulty:
            return candidate
        nonce = (nonce + 1) & ((1 << 64) - 1)
        iters += 1
        if max_iters is not None and iters >= max_iters:
            raise RuntimeError(f"mining exhausted after {iters} iterations")


def mine_block(
    *,
    prev_hash: bytes,
    height: int,
    difficulty: int,
    timestamp: int,
    miner_pk_raw: bytes,
    transactions: List[Transaction],
    max_iters: Optional[int] = None,
) -> Block:
    """Convenience: assemble + mine + return the full Block."""
    header = assemble_block(
        prev_hash=prev_hash,
        height=height,
        difficulty=difficulty,
        timestamp=timestamp,
        miner_pk_raw=miner_pk_raw,
        transactions=transactions,
    )
    mined = mine(header, max_iters=max_iters)
    assert verify_pow(mined), "miner returned a header that fails verify_pow"
    return Block(header=mined, transactions=transactions)


__all__ = [
    "next_difficulty",
    "assemble_block",
    "mine",
    "mine_block",
    "block_weight",
]
