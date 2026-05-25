"""
PoW block format and proof-of-work puzzle.

A block is a header (fixed layout) plus a transaction list (variable). The
header is the only thing that gets hashed for the PoW puzzle; transactions
are bound into the header via a Merkle-flat ``tx_root`` (SHA-256 over the
canonical concatenation of canonical transaction encodings).

The puzzle is: ``SHA-256(header_bytes)`` must have at least ``difficulty``
leading zero **bits**. The nonce is the last field of the header and the
only thing the miner mutates.

Difficulty is a single byte in [0, 255]. The chain in practice will stay
well under 32 bits even on slow hardware; we use the full byte to leave
room for adversarial-grinding scenarios in tests.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List

from chain.transactions import Transaction, encode_tx_list, tx_list_root

HEADER_SIZE = 32 + 8 + 1 + 8 + 32 + 32 + 8  # 121 bytes
GENESIS_PREV_HASH = b"\x00" * 32


@dataclass(frozen=True)
class BlockHeader:
    """Fixed-layout block header. Total: 121 bytes."""

    prev_hash: bytes              # 32
    height: int                   # 8 BE
    difficulty: int               # 1 byte
    timestamp: int                # 8 BE
    miner_pk: bytes               # 32 (Ed25519 raw)
    tx_root: bytes                # 32
    nonce: int                    # 8 BE

    def __post_init__(self) -> None:
        if len(self.prev_hash) != 32:
            raise ValueError("prev_hash must be 32 bytes")
        if not (0 <= self.height < 2**64):
            raise ValueError("height out of range")
        if not (0 <= self.difficulty <= 255):
            raise ValueError("difficulty must be a single byte")
        if not (0 <= self.timestamp < 2**64):
            raise ValueError("timestamp out of range")
        if len(self.miner_pk) != 32:
            raise ValueError("miner_pk must be 32 bytes")
        if len(self.tx_root) != 32:
            raise ValueError("tx_root must be 32 bytes")
        if not (0 <= self.nonce < 2**64):
            raise ValueError("nonce out of range")

    def encode(self) -> bytes:
        return (
            self.prev_hash
            + self.height.to_bytes(8, "big")
            + self.difficulty.to_bytes(1, "big")
            + self.timestamp.to_bytes(8, "big")
            + self.miner_pk
            + self.tx_root
            + self.nonce.to_bytes(8, "big")
        )

    @classmethod
    def decode(cls, blob: bytes) -> "BlockHeader":
        if len(blob) != HEADER_SIZE:
            raise ValueError(f"header must be {HEADER_SIZE} bytes, got {len(blob)}")
        return cls(
            prev_hash=blob[0:32],
            height=int.from_bytes(blob[32:40], "big"),
            difficulty=blob[40],
            timestamp=int.from_bytes(blob[41:49], "big"),
            miner_pk=blob[49:81],
            tx_root=blob[81:113],
            nonce=int.from_bytes(blob[113:121], "big"),
        )

    def hash(self) -> bytes:
        return hashlib.sha256(self.encode()).digest()

    def with_nonce(self, nonce: int) -> "BlockHeader":
        return BlockHeader(
            prev_hash=self.prev_hash,
            height=self.height,
            difficulty=self.difficulty,
            timestamp=self.timestamp,
            miner_pk=self.miner_pk,
            tx_root=self.tx_root,
            nonce=nonce,
        )


@dataclass(frozen=True)
class Block:
    header: BlockHeader
    transactions: List[Transaction] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Bind tx list to the header.
        expected = tx_list_root(self.transactions)
        if expected != self.header.tx_root:
            raise ValueError("tx_root in header does not match transactions")

    @property
    def hash(self) -> bytes:
        return self.header.hash()

    @property
    def height(self) -> int:
        return self.header.height

    @property
    def prev_hash(self) -> bytes:
        return self.header.prev_hash

    @property
    def difficulty(self) -> int:
        return self.header.difficulty

    @property
    def timestamp(self) -> int:
        return self.header.timestamp

    def encode(self) -> bytes:
        """Canonical block serialization: header || tx_count(4 BE) || tx_blob."""
        tx_blob = encode_tx_list(self.transactions)
        return (
            self.header.encode()
            + len(self.transactions).to_bytes(4, "big")
            + tx_blob
        )

    @classmethod
    def decode(cls, blob: bytes) -> "Block":
        from chain.transactions import decode_tx_list  # local import: avoid cycle
        if len(blob) < HEADER_SIZE + 4:
            raise ValueError("block blob too short")
        header = BlockHeader.decode(blob[:HEADER_SIZE])
        tx_count = int.from_bytes(blob[HEADER_SIZE:HEADER_SIZE + 4], "big")
        txs, consumed = decode_tx_list(blob[HEADER_SIZE + 4:], tx_count)
        if consumed != len(blob) - HEADER_SIZE - 4:
            raise ValueError(
                f"trailing bytes after tx list: "
                f"{len(blob) - HEADER_SIZE - 4 - consumed}"
            )
        return cls(header=header, transactions=txs)


# --------------------------------------------------------------------------- #
# PoW                                                                          #
# --------------------------------------------------------------------------- #


def leading_zero_bits(h: bytes) -> int:
    """Count leading zero bits in a byte string."""
    count = 0
    for byte in h:
        if byte == 0:
            count += 8
            continue
        # bit_length tells us where the highest 1-bit sits in this byte.
        count += 8 - byte.bit_length()
        break
    return count


def verify_pow(header: BlockHeader) -> bool:
    """PoW check: header hash has at least ``difficulty`` leading zero bits."""
    return leading_zero_bits(header.hash()) >= header.difficulty


def block_weight(difficulty: int) -> int:
    """Per-block contribution to cumulative chain weight (GHOST-style)."""
    return 1 << difficulty


# --------------------------------------------------------------------------- #
# Genesis builder                                                              #
# --------------------------------------------------------------------------- #


def make_genesis(
    *,
    miner_pk: bytes,
    timestamp: int,
    difficulty: int = 4,
    transactions: List[Transaction] | None = None,
) -> Block:
    """
    Build a genesis block.

    Genesis is *not* mined: its hash does not need to satisfy the PoW
    puzzle, because no parent block has committed to it. We still hash it
    so subsequent blocks can refer to it by ``prev_hash``.

    The miner_pk on genesis is conventionally the address that receives
    any initial faucet allocations specified in ``transactions``.
    """
    txs = transactions or []
    header = BlockHeader(
        prev_hash=GENESIS_PREV_HASH,
        height=0,
        difficulty=difficulty,
        timestamp=timestamp,
        miner_pk=miner_pk,
        tx_root=tx_list_root(txs),
        nonce=0,
    )
    return Block(header=header, transactions=txs)


def is_genesis(block: Block) -> bool:
    return block.header.prev_hash == GENESIS_PREV_HASH and block.header.height == 0
