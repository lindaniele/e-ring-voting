"""
voting — the election logic shared by both architectures.

* ``records``: the typed record schema (setup, registration, ballot, key
  transfer, and the board-only ring / close / tally records);
* ``groups``: beacon-driven assignment of voters to fixed-size groups;
* ``tally``: classification of the messages signed in one group
  (accepted, replayed, double-signed) with TRS tracing.

On top of these, ``log`` / ``manager`` / ``voter`` / ``auditor`` /
``witness`` implement Architecture A, the permissioned baseline: a single
publisher with a witness cohort, one ring, no deposits. The design this
project is about, Architecture B, lives in ``chain/``.

See ``paper/threat_model.md`` for what is and is not defended against.
"""

from voting.log import BulletinBoard, Entry, LogError
from voting.records import (
    Ballot,
    ElectionSetup,
    KeyTransfer,
    RecordKind,
    RingPublication,
    TallyPublication,
    VoterRegistration,
    VotingClosed,
)

__all__ = [
    "BulletinBoard",
    "Entry",
    "LogError",
    "Ballot",
    "ElectionSetup",
    "KeyTransfer",
    "RecordKind",
    "RingPublication",
    "TallyPublication",
    "VoterRegistration",
    "VotingClosed",
]
