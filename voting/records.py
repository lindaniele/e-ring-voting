"""
Typed records that live on the bulletin board.

Each record serialises to a canonical JSON object that becomes the
``payload`` bytes of a :class:`voting.log.Entry`. The first field is always
``"kind"`` — a discriminator that the auditor uses to dispatch validation.

Canonical encoding rules:

* JSON with ``sort_keys=True`` and ``separators=(",", ":")`` — byte-stable.
* Binary blobs (public keys, signatures) are base64-standard-encoded.
* All timestamps are Unix seconds, integers.

The kinds form a state machine on the bulletin board:

::

    ElectionSetup → (VoterRegistration*) → RingPublication
                  → (Ballot*) → VotingClosed → TallyPublication

Any record out of order is a validation error caught by the auditor.
"""

from __future__ import annotations

import base64
import enum
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

# Re-exported so existing callers can keep importing `field` from records.


class RecordError(Exception):
    """Raised on malformed or out-of-state records."""


class RecordKind(str, enum.Enum):
    SETUP = "election_setup"
    REGISTRATION = "voter_registration"
    RING = "ring_publication"
    BALLOT = "ballot"
    CLOSED = "voting_closed"
    TALLY = "tally_publication"


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise RecordError(f"invalid base64: {exc}") from exc


def _canon_dump(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------- #
# ElectionSetup                                                                #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ElectionSetup:
    """
    Genesis record. Fixes the election parameters once and for all.

    ``election_id`` is the OTRS ``issue`` value — a 32-byte random hex string.
    It must be unique per election; we recommend deriving it as
    ``SHA-256(cohort_pks[0] || title || created_at)`` but the protocol accepts
    any unique value.

    ``cohort_pks_b64`` lists the Ed25519 public keys of the publisher cohort
    in canonical order (the index into this list is the cohort member ID).
    ``threshold`` is the t-of-N value required to commit an entry.

    ``witness_pks_b64`` lists Ed25519 keys of independent witnesses who may
    co-sign log heads off-band; ``witness_threshold`` is the k-of-M value
    required for the audit step. Both default to empty / 0 for elections
    that do not require an external witness federation.
    """

    election_id: str  # 64-char hex
    title: str
    description: str
    options: List[str]
    registration_close: int
    voting_open: int
    voting_close: int
    cohort_pks_b64: List[str]
    threshold: int
    witness_pks_b64: List[str] = field(default_factory=list)
    witness_threshold: int = 0

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
                cohort_pks_b64=[str(s) for s in obj["cohort_pks_b64"]],
                threshold=int(obj["threshold"]),
                witness_pks_b64=[str(s) for s in obj.get("witness_pks_b64", [])],
                witness_threshold=int(obj.get("witness_threshold", 0)),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise RecordError(f"malformed ElectionSetup: {exc}") from exc

    # ----- protocol-level invariants ------------------------------------- #
    def validate(self) -> None:
        if len(self.options) < 2:
            raise RecordError("election must have at least 2 options")
        if len(set(self.options)) != len(self.options):
            raise RecordError("duplicate options not allowed")
        if not (self.registration_close <= self.voting_open <= self.voting_close):
            raise RecordError("schedule must be monotonic")
        try:
            bytes.fromhex(self.election_id)
        except ValueError as exc:
            raise RecordError("election_id must be hex") from exc
        n = len(self.cohort_pks_b64)
        if n < 1:
            raise RecordError("cohort must have at least 1 member")
        if not (1 <= self.threshold <= n):
            raise RecordError(
                f"threshold {self.threshold} not in [1, {n}]"
            )
        if len(set(self.cohort_pks_b64)) != n:
            raise RecordError("duplicate cohort public keys")
        m = len(self.witness_pks_b64)
        if not (0 <= self.witness_threshold <= m):
            raise RecordError(
                f"witness_threshold {self.witness_threshold} not in [0, {m}]"
            )
        if m and len(set(self.witness_pks_b64)) != m:
            raise RecordError("duplicate witness public keys")

    # ----- helpers ------------------------------------------------------- #
    def manager_pk_raw(self) -> bytes:
        """Backward-compat: in v0.2 there was one "manager pk"; in v0.3
        the cohort signs attestations collectively. For voter attestations
        we adopt the convention that cohort member 0's key is the
        canonical "manager" identity that signs attestations; the cohort
        as a whole signs log entries."""
        from base64 import b64decode
        return b64decode(self.cohort_pks_b64[0])


# --------------------------------------------------------------------------- #
# VoterRegistration                                                            #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VoterRegistration:
    """
    A voter's OTRS public key, attested by the publisher cohort.

    In v0.3 there is no separate Ed25519 "attestation" field: the cohort's
    threshold signature on the *entry containing this record* is the
    attestation. Whoever fetches the log can see exactly which cohort
    members vouched for this voter — and a minority of corrupted cohort
    members cannot register a fake voter without convincing the rest.

    The handle is a human-readable identifier (e.g. email or student-id
    hash). Identity-proofing remains out of scope: the cohort is trusted
    to only co-sign registration entries for genuine eligible voters.
    """

    voter_pk_b64: str         # 32-byte Ristretto255 OTRS pk
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


# --------------------------------------------------------------------------- #
# RingPublication                                                              #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RingPublication:
    """
    The final, ordered list of voter public keys.

    Once published, registration is closed and voting opens. Voters use this
    *exact* ordered ring (the OTRS encoding is order-sensitive). Auditors
    verify the ring is exactly the multiset of attested registrations seen
    so far on the log.
    """

    ring_b64: List[str]   # ordered list of base64-encoded 32-byte pks

    def to_payload(self) -> bytes:
        return _canon_dump({"kind": RecordKind.RING.value, "ring_b64": list(self.ring_b64)})

    @classmethod
    def from_obj(cls, obj: Dict[str, Any]) -> "RingPublication":
        try:
            return cls(ring_b64=[str(s) for s in obj["ring_b64"]])
        except (KeyError, ValueError, TypeError) as exc:
            raise RecordError(f"malformed RingPublication: {exc}") from exc


# --------------------------------------------------------------------------- #
# Ballot                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Ballot:
    """
    A single OTRS-signed ballot.

    The choice must equal one of the strings in ``ElectionSetup.options``.
    The signature is over the message bytes ``"ballot-v1" || choice_utf8``,
    bound to the election's ``election_id`` (used as the OTRS ``issue``) and
    the ring from :class:`RingPublication`.
    """

    choice: str
    otrs_sig_b64: str

    def to_payload(self) -> bytes:
        return _canon_dump({"kind": RecordKind.BALLOT.value, **asdict(self)})

    @classmethod
    def from_obj(cls, obj: Dict[str, Any]) -> "Ballot":
        try:
            return cls(
                choice=str(obj["choice"]),
                otrs_sig_b64=str(obj["otrs_sig_b64"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise RecordError(f"malformed Ballot: {exc}") from exc

    @staticmethod
    def message_for(choice: str) -> bytes:
        return b"ballot-v1" + choice.encode("utf-8")


# --------------------------------------------------------------------------- #
# VotingClosed                                                                 #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VotingClosed:
    """Manager-published marker that no further ballots will be accepted."""

    def to_payload(self) -> bytes:
        return _canon_dump({"kind": RecordKind.CLOSED.value})

    @classmethod
    def from_obj(cls, obj: Dict[str, Any]) -> "VotingClosed":  # noqa: ARG003
        return cls()


# --------------------------------------------------------------------------- #
# TallyPublication                                                             #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TallyPublication:
    """
    The manager's claimed tally plus any double-sign evidence.

    Auditors recompute the tally from the log and compare to this record;
    if they disagree, the manager is lying. The double-sign evidence is
    deterministic — anyone running ``Trace`` over the ballot pairs gets the
    same result.
    """

    tally: Dict[str, int]
    double_sign_culprits_b64: List[str] = field(default_factory=list)

    def to_payload(self) -> bytes:
        return _canon_dump({
            "kind": RecordKind.TALLY.value,
            "tally": dict(sorted(self.tally.items())),
            "double_sign_culprits_b64": list(self.double_sign_culprits_b64),
        })

    @classmethod
    def from_obj(cls, obj: Dict[str, Any]) -> "TallyPublication":
        try:
            return cls(
                tally={str(k): int(v) for k, v in dict(obj["tally"]).items()},
                double_sign_culprits_b64=[
                    str(s) for s in obj.get("double_sign_culprits_b64", [])
                ],
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise RecordError(f"malformed TallyPublication: {exc}") from exc


# --------------------------------------------------------------------------- #
# Polymorphic parse                                                            #
# --------------------------------------------------------------------------- #


_KIND_TO_CLS = {
    RecordKind.SETUP.value: ElectionSetup,
    RecordKind.REGISTRATION.value: VoterRegistration,
    RecordKind.RING.value: RingPublication,
    RecordKind.BALLOT.value: Ballot,
    RecordKind.CLOSED.value: VotingClosed,
    RecordKind.TALLY.value: TallyPublication,
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
