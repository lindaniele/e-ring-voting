"""
chain — PoW blockchain alternative to the federated bulletin board.

A from-scratch implementation of an OTRS-voting system whose storage and
ordering layer is a Bitcoin-style proof-of-work chain rather than the
threshold-signed bulletin board of :mod:`voting`. The cryptographic
primitive is the same (:mod:`otrs`); the typed voting records are reused
from :mod:`voting.records`. What changes is *who orders the records*: a
named t-of-N publisher cohort + witness federation in :mod:`voting`,
versus open mining + heaviest-chain selection here.

This is the second of the two architectures the artifact paper compares.
"""

from chain.block import Block, BlockHeader, make_genesis, verify_pow
from chain.node import Node, make_genesis_node
from chain.state import ChainParams, DEFAULT_PARAMS, State, StateError, apply_block
from chain.transactions import (
    Transaction,
    TxKind,
    make_ballot,
    make_close_poll,
    make_coinbase,
    make_publish_ring,
    make_register_voter,
    make_setup_poll,
    make_tally,
    make_transfer,
)

__all__ = [
    "Block",
    "BlockHeader",
    "ChainParams",
    "DEFAULT_PARAMS",
    "Node",
    "State",
    "StateError",
    "Transaction",
    "TxKind",
    "apply_block",
    "make_ballot",
    "make_close_poll",
    "make_coinbase",
    "make_genesis",
    "make_genesis_node",
    "make_publish_ring",
    "make_register_voter",
    "make_setup_poll",
    "make_tally",
    "make_transfer",
    "verify_pow",
]
