"""
chain — the e-ring-voting proof-of-work chain.

The chain carries an eVote ledger and runs polls whose rules realise the
original e-ring-voting design: traceable ring signatures (:mod:`trs`) for
anonymous ballots, deposits burned when a registered key double-signs,
beacon-assigned fixed-size groups, and key transfers between rounds. The
typed records are shared with :mod:`voting`, whose federated bulletin board
serves as the permissioned baseline the paper compares against.
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
