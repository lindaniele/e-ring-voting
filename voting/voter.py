"""
Voter API.

Voters do three things in this artifact:

1. Generate an OTRS key pair locally.
2. Hand their public key + handle to the manager (out-of-band channel).
3. Once the ring is published, sign a ballot and submit it (in our
   single-publisher model, "submit" means the manager appends it to the
   bulletin board; in a distributed deployment voters would post directly).

The voter holds the secret key. The library never persists it for them —
that's a CLI / wallet concern.
"""

from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass
from pathlib import Path
from typing import List

from otrs import KeyPair, PublicKey, SecretKey, keygen, sign
from otrs.group import Scalar, base_mul
from voting.log import BulletinBoard
from voting.records import (
    Ballot,
    ElectionSetup,
    RingPublication,
    parse_payload,
)


# --------------------------------------------------------------------------- #
# Keys                                                                         #
# --------------------------------------------------------------------------- #


def new_keypair() -> KeyPair:
    """Generate a fresh OTRS key pair."""
    return keygen()


def export_keypair(kp: KeyPair) -> tuple[str, str]:
    """Return ``(sk_b64, pk_b64)`` for file persistence."""
    return b64encode(kp.sk.x.raw).decode(), b64encode(kp.pk.point.raw).decode()


def import_keypair(sk_b64: str, pk_b64: str) -> KeyPair:
    sk_raw = b64decode(sk_b64)
    pk_raw = b64decode(pk_b64)
    if len(sk_raw) != 32 or len(pk_raw) != 32:
        raise ValueError("OTRS keys must be 32 bytes")
    sk = SecretKey(Scalar(sk_raw))
    pk = PublicKey.from_bytes(pk_raw)
    # Optional sanity: pk should equal g^sk. We do not enforce it here
    # because the caller may legitimately want to load a key that we don't
    # control; verification at signing time will catch mismatches.
    return KeyPair(sk=sk, pk=pk)


# --------------------------------------------------------------------------- #
# Ballot construction                                                          #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class VotingContext:
    """The on-log facts a voter needs to sign a ballot."""

    election_id_bytes: bytes  # OTRS issue
    options: List[str]
    ring: List[PublicKey]     # in the order published on the log


def load_voting_context(log_path: Path) -> VotingContext:
    """
    Read the bulletin board and assemble the parameters needed to sign.

    Raises ``ValueError`` if the log has not reached the voting phase
    (no :class:`RingPublication` yet).
    """
    log = BulletinBoard(log_path)
    setup: ElectionSetup | None = None
    ring_b64: List[str] | None = None
    for entry in log.read_all():
        rec = parse_payload(entry.payload)
        if isinstance(rec, ElectionSetup):
            setup = rec
        elif isinstance(rec, RingPublication):
            ring_b64 = rec.ring_b64
            break  # later entries are ballots / closed / tally
    if setup is None:
        raise ValueError("log does not contain an ElectionSetup")
    if ring_b64 is None:
        raise ValueError("voting is not yet open (no RingPublication)")
    return VotingContext(
        election_id_bytes=bytes.fromhex(setup.election_id),
        options=list(setup.options),
        ring=[PublicKey.from_bytes(b64decode(s)) for s in ring_b64],
    )


def cast_ballot(
    *,
    voter: KeyPair,
    context: VotingContext,
    choice: str,
) -> Ballot:
    """Build (but do not publish) a signed ballot for ``choice``."""
    if choice not in context.options:
        raise ValueError(f"choice {choice!r} not in election options")
    if voter.pk.point.raw not in {pk.point.raw for pk in context.ring}:
        raise ValueError("voter is not a member of the published ring")
    msg = Ballot.message_for(choice)
    sig = sign(voter.sk, voter.pk, context.election_id_bytes, msg, context.ring)
    return Ballot(choice=choice, otrs_sig_b64=b64encode(sig.to_bytes()).decode())
