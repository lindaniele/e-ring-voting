"""
Chain node: holds the canonical chain + the folded state.

The node is a thin object that owns ``(chain, state)`` and exposes
``append(block)``. State is rebuilt from the chain on load, so the only
on-disk artifact is a flat binary stream of blocks (length-prefixed).

Fork resolution is **not** implemented in this prototype — the node
accepts the chain it is given and rejects blocks that don't extend its
current tip. A multi-peer node would need a fork-choice rule (heaviest
chain by cumulative ``2^difficulty``); the math is in
``chain.block.block_weight`` and ``State.cum_weight``, so adding fork
resolution later is a small extension.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from chain.block import Block, make_genesis
from chain.state import ChainParams, DEFAULT_PARAMS, State, StateError, apply_block
from chain.transactions import Transaction, make_coinbase


class Node:
    def __init__(self, params: ChainParams = DEFAULT_PARAMS) -> None:
        self.params = params
        self.chain: List[Block] = []
        self.state: State = State()

    # ----- accessors ----------------------------------------------------- #
    @property
    def height(self) -> int:
        return self.state.height

    @property
    def tip_hash(self) -> bytes:
        return self.state.tip_hash

    @property
    def last_timestamp(self) -> int:
        return self.state.last_timestamp

    def recent_timestamps(self, window: int) -> List[int]:
        """Return the last ``window`` block timestamps, oldest first."""
        return [b.timestamp for b in self.chain[-window:]]

    # ----- chain ops ----------------------------------------------------- #
    def append(self, block: Block) -> None:
        """Apply ``block`` to the state and add it to the chain on success."""
        apply_block(self.state, block, params=self.params)
        self.chain.append(block)

    # ----- persistence --------------------------------------------------- #
    def save(self, path: Path) -> None:
        with open(path, "wb") as f:
            for block in self.chain:
                b = block.encode()
                f.write(len(b).to_bytes(4, "big"))
                f.write(b)

    @classmethod
    def load(cls, path: Path, *, params: ChainParams = DEFAULT_PARAMS) -> "Node":
        node = cls(params=params)
        if not path.exists() or path.stat().st_size == 0:
            return node
        data = path.read_bytes()
        pos = 0
        while pos < len(data):
            if pos + 4 > len(data):
                raise StateError("chain file truncated at length prefix")
            n = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
            if pos + n > len(data):
                raise StateError("chain file truncated at block body")
            block = Block.decode(data[pos:pos + n])
            pos += n
            node.append(block)
        return node


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def make_genesis_node(
    *,
    timestamp: int,
    miner_pk_raw: bytes,
    initial_allocations: List[Tuple[bytes, int]],
    difficulty: int = 4,
    params: ChainParams = DEFAULT_PARAMS,
) -> Node:
    """
    Build a fresh node with a genesis block that funds ``initial_allocations``.

    Each ``(recipient_pk_raw, amount)`` becomes a coinbase transaction in
    the genesis block. Recipients should be distinct (or amounts must
    differ) — duplicate canonical bytes are rejected at parse time.

    ``miner_pk_raw`` here is the symbolic genesis-block author; it does
    not receive coinbase eVotes by itself, only the named allocations do.
    """
    txs: List[Transaction] = [
        make_coinbase(pk_raw, amount, height=0)
        for pk_raw, amount in initial_allocations
    ]
    block = make_genesis(
        miner_pk=miner_pk_raw,
        timestamp=timestamp,
        difficulty=difficulty,
        transactions=txs,
    )
    node = Node(params=params)
    node.append(block)
    return node
