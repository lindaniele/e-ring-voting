"""
voting — verifiable anonymous voting system built on the OTRS primitive.

The package layers a single-publisher append-only bulletin board, a typed
record schema for the election lifecycle, and three principal APIs (manager,
voter, auditor) on top of the ring-signature library in ``otrs/``.

See ``paper/threat_model.md`` for what is and is not defended against.
"""

from voting.log import BulletinBoard, Entry, LogError
from voting.records import (
    Ballot,
    ElectionSetup,
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
    "RecordKind",
    "RingPublication",
    "TallyPublication",
    "VoterRegistration",
    "VotingClosed",
]
