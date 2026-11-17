"""
Typed poll records carried by chain transactions.

Each record serialises to a canonical JSON object (``sort_keys``, compact
separators, binary fields in standard base64) whose first field is
``"kind"``. The chain (:mod:`chain.state`) parses them out of transaction
payloads and enforces the rules; this module only fixes their shape and
the byte strings that get signed.

The lifecycle of a poll on the chain::

    ElectionSetup → VoterRegistration* → (freeze, groups) →
        round 0: Ballot* | KeyTransfer* → (regroup) → round 1: ... →
        (close: tally, burn, refund)

Nothing in parentheses is a record: the chain does it by itself at the
first block whose timestamp crosses the corresponding deadline.

Key labels
----------
A one-time key must be used once, in one place. Every OTRS key carries a
public 32-byte label (:class:`otrs.PublicKey`), and the chain only accepts
a key whose label names its use:

* a registered key, :meth:`VoterRegistration.key_label` of the poll and
  the voter's handle;
* a key received by transfer, :meth:`KeyTransfer.key_label` of the poll
  and the round it enters.

So a key cannot be registered in two polls, nor under a handle other than
the one it was made for. This replaces the proof of possession of earlier
versions, which an OTRS key cannot give without spending its one use.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List

from otrs.primitives import PARAMS_BY_LAMBDA


class RecordError(Exception):
    """Raised on malformed records."""


class RecordKind(str, enum.Enum):
    SETUP = "election_setup"
    REGISTRATION = "voter_registration"
    BALLOT = "ballot"
    KEY_TRANSFER = "key_transfer"


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise RecordError(f"invalid base64: {exc}") from exc


def _canon_dump(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _u32(n: int) -> bytes:
    return int(n).to_bytes(4, "big")


# --------------------------------------------------------------------------- #
# ElectionSetup                                                                #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ElectionSetup:
    """
    A poll's parameters, fixed when the poll is created.

    * ``election_id``: 32 bytes in hex, unique on the chain.
    * ``registration_close`` / ``voting_open`` / ``voting_close``: block
      timestamps (Unix seconds) that drive the lifecycle.
    * ``group_size``: voters sign inside groups of ``group_size`` to
      ``2·group_size − 1`` members drawn from a beacon
      (:func:`voting.groups.assign_groups`); ``0`` means one ring for all.
    * ``rounds``: in every round but the last a voter may, instead of
      voting, move its voting right to a fresh key that is regrouped.
    * ``deposit``: eVotes locked per registered voter, burned if that key
      is traced, refunded otherwise.
    * ``security``: the OTRS security parameter ``λ`` (128 or 256); every
      key and signature of the poll uses it.
    """

    election_id: str
    title: str
    description: str
    options: List[str]
    registration_close: int
    voting_open: int
    voting_close: int
    group_size: int = 0
    rounds: int = 1
    deposit: int = 0
    security: int = 128

    def to_payload(self) -> bytes:
        return _canon_dump({"kind": RecordKind.SETUP.value, **asdict(self)})

    @classmethod
    def from_obj(cls, obj: Dict[str, Any]) -> "ElectionSetup":
        try:
            return cls(
                election_id=str(obj["election_id"]),
                title=str(obj["title"]),
                description=str(obj["description"]),
                options=[str(o) for o in obj["options"]],
                registration_close=int(obj["registration_close"]),
                voting_open=int(obj["voting_open"]),
                voting_close=int(obj["voting_close"]),
                group_size=int(obj.get("group_size", 0)),
                rounds=int(obj.get("rounds", 1)),
                deposit=int(obj.get("deposit", 0)),
                security=int(obj.get("security", 128)),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise RecordError(f"malformed ElectionSetup: {exc}") from exc

    def validate(self) -> None:
        if len(self.options) < 2:
            raise RecordError("election must have at least 2 options")
        if len(set(self.options)) != len(self.options):
            raise RecordError("duplicate options not allowed")
        if not (self.registration_close <= self.voting_open <= self.voting_close):
            raise RecordError("schedule must be monotonic")
        try:
            eid = bytes.fromhex(self.election_id)
        except ValueError as exc:
            raise RecordError("election_id must be hex") from exc
        if len(eid) != 32:
            raise RecordError("election_id must be 32 bytes")
        if self.group_size < 0 or self.group_size == 1:
            raise RecordError("group_size must be 0 (single ring) or at least 2")
        if self.rounds < 1:
            raise RecordError("rounds must be at least 1")
        if self.rounds > self.voting_close - self.voting_open:
            raise RecordError("voting window shorter than one second per round")
        if self.deposit < 0:
            raise RecordError("deposit must be non-negative")
        if self.security not in PARAMS_BY_LAMBDA:
            raise RecordError(f"security must be one of {sorted(PARAMS_BY_LAMBDA)}")


# --------------------------------------------------------------------------- #
# VoterRegistration                                                            #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VoterRegistration:
    """
    A voter's one-time key, registered by a sponsor who locks the deposit.

    ``voter_handle`` names the voter for the sponsor (a student number, an
    e-mail hash, ...). Deciding who is eligible is the sponsor's business;
    the chain only checks that the key was made for this poll and handle.
    """

    voter_pk_b64: str
    voter_handle: str

    def to_payload(self) -> bytes:
        return _canon_dump({"kind": RecordKind.REGISTRATION.value, **asdict(self)})

    @classmethod
    def from_obj(cls, obj: Dict[str, Any]) -> "VoterRegistration":
        try:
            return cls(
                voter_pk_b64=str(obj["voter_pk_b64"]),
                voter_handle=str(obj["voter_handle"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise RecordError(f"malformed VoterRegistration: {exc}") from exc

    @staticmethod
    def key_label(election_id: str, voter_handle: str) -> bytes:
        handle = voter_handle.encode("utf-8")
        return hashlib.sha256(
            b"e-ring-voting/register-v1" + bytes.fromhex(election_id)
            + _u32(len(handle)) + handle
        ).digest()


# --------------------------------------------------------------------------- #
# Ballot                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Ballot:
    """
    A ballot signed inside group ``group`` of round ``round``.

    The signed message is ``"ballot-v1" || choice`` and the signing context
    is :func:`voting.groups.signing_context` of the poll and round.
    """

    choice: str
    sig_b64: str
    round: int = 0
    group: int = 0

    def to_payload(self) -> bytes:
        return _canon_dump({"kind": RecordKind.BALLOT.value, **asdict(self)})

    @classmethod
    def from_obj(cls, obj: Dict[str, Any]) -> "Ballot":
        try:
            return cls(
                choice=str(obj["choice"]),
                sig_b64=str(obj["sig_b64"]),
                round=int(obj.get("round", 0)),
                group=int(obj.get("group", 0)),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise RecordError(f"malformed Ballot: {exc}") from exc

    @staticmethod
    def message_for(choice: str) -> bytes:
        return b"ballot-v1" + choice.encode("utf-8")


# --------------------------------------------------------------------------- #
# KeyTransfer                                                                  #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class KeyTransfer:
    """
    Spend this round's voting right on a fresh key for the next round.

    This is the original procedure's "transfer to another group with
    another key", and the use [SZ21, §1.1] suggests for one-time keys:
    while signing, name the next key. A ballot and a transfer are both one
    use of the key, so doing both (or transferring twice) is a second
    signature and traces the key.
    """

    new_pk_b64: str
    sig_b64: str
    round: int
    group: int

    def to_payload(self) -> bytes:
        return _canon_dump({"kind": RecordKind.KEY_TRANSFER.value, **asdict(self)})

    @classmethod
    def from_obj(cls, obj: Dict[str, Any]) -> "KeyTransfer":
        try:
            return cls(
                new_pk_b64=str(obj["new_pk_b64"]),
                sig_b64=str(obj["sig_b64"]),
                round=int(obj["round"]),
                group=int(obj["group"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise RecordError(f"malformed KeyTransfer: {exc}") from exc

    @staticmethod
    def message_for(new_pk_raw: bytes) -> bytes:
        return b"key-transfer-v1" + new_pk_raw

    @staticmethod
    def key_label(election_id: str, round_: int) -> bytes:
        """Label of a key that enters round ``round_`` by transfer."""
        return hashlib.sha256(
            b"e-ring-voting/transfer-v1" + bytes.fromhex(election_id) + _u32(round_)
        ).digest()


# --------------------------------------------------------------------------- #
# Polymorphic parse                                                            #
# --------------------------------------------------------------------------- #


_KIND_TO_CLS = {
    RecordKind.SETUP.value: ElectionSetup,
    RecordKind.REGISTRATION.value: VoterRegistration,
    RecordKind.BALLOT.value: Ballot,
    RecordKind.KEY_TRANSFER.value: KeyTransfer,
}


def parse_payload(payload: bytes) -> Any:
    """Parse a payload into the appropriate record class. Raises RecordError."""
    try:
        obj = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RecordError(f"payload not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise RecordError("payload must be a JSON object")
    kind = obj.get("kind")
    if kind not in _KIND_TO_CLS:
        raise RecordError(f"unknown record kind: {kind!r}")
    return _KIND_TO_CLS[kind].from_obj(obj)
