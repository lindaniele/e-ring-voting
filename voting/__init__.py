"""
voting — the election logic, independent of how records are published.

* ``records``: the poll records (setup, registration, ballot, key transfer)
  and the labels that bind each one-time key to its single use;
* ``groups``: beacon-driven assignment of voters to fixed-size groups, and
  the per-round tag and signing context;
* ``tally``: classification of the messages signed in one group with the
  Scafuro–Zhang trace (counted, void, culprits).

The chain in :mod:`chain` applies these rules as consensus rules.
"""

from voting.records import (
    Ballot,
    ElectionSetup,
    KeyTransfer,
    RecordError,
    RecordKind,
    VoterRegistration,
    parse_payload,
)

__all__ = [
    "Ballot",
    "ElectionSetup",
    "KeyTransfer",
    "RecordError",
    "RecordKind",
    "VoterRegistration",
    "parse_payload",
]
