"""
chain — the e-ring-voting proof-of-work chain.

The chain carries an eVote ledger and runs polls whose rules realise the
original e-ring-voting design: one-time traceable ring signatures
(Scafuro–Zhang, :mod:`otrs`) for anonymous ballots, deposits burned when a
registered key is used twice, beacon-assigned fixed-size groups, and key
transfers between rounds. The poll records and the trace bookkeeping live
in :mod:`voting`.
"""

from chain.block import Block, BlockHeader, make_genesis, verify_pow
from chain.node import Node, make_genesis_node
from chain.state import (
    ChainParams,
    DEFAULT_PARAMS,
    State,
    StateError,
    apply_block,
    next_difficulty,
    state_for_next_block,
)
from chain.transactions import (
    Transaction,
    TxKind,
    make_ballot,
    make_coinbase,
    make_key_transfer,
    make_register_voter,
    make_setup_poll,
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
    "make_coinbase",
    "make_genesis",
    "make_genesis_node",
    "make_key_transfer",
    "make_register_voter",
    "make_setup_poll",
    "make_transfer",
    "next_difficulty",
    "state_for_next_block",
    "verify_pow",
]
