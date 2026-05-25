"""
Witness federation: off-band co-signing of log heads.

A witness is an independent third party who fetches the bulletin board,
verifies it under the published publisher cohort, and signs an
*attestation* of the form ::

    Checkpoint(log_index, head_hash, witness_index, sig)

Checkpoints live in a sidecar file (``<log>.witnesses``). Auditors require
at least :attr:`ElectionSetup.witness_threshold` distinct witnesses to
have signed a checkpoint at the index they care about, with the same
``head_hash``.

This buys us **equivocation resistance** at the publisher layer: a cohort
that has crossed its threshold (≥ t corrupted members) can publish two
divergent logs, but honest witnesses who see both will sign two different
hashes for the same index — public proof of equivocation. If you only
care about a single witness federation watching a single log, you get
the property "either the cohort is consistent or there's machine-readable
evidence that it isn't."

The actual witness gossip protocol is out of scope: in this artifact
witnesses write their checkpoints to a local file. A real deployment
would replicate the file (or publish over HTTPS) and voters would query
multiple independent witnesses.
"""

from __future__ import annotations

import hashlib
import json
from base64 import b64decode, b64encode
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from voting.log import BulletinBoard, LogError, PublisherCohort, pk_raw


@dataclass(frozen=True)
class Checkpoint:
    """A signed attestation that the log head at ``log_index`` is ``head_hash``."""

    log_index: int
    head_hash: bytes      # SHA-256 of the entry at log_index
    witness_index: int
    sig: bytes            # Ed25519 signature over signing_preimage()

    def signing_preimage(self) -> bytes:
        return b"".join(
            [
                b"otrs-witness-checkpoint-v1",
                self.log_index.to_bytes(8, "big"),
                self.head_hash,
                self.witness_index.to_bytes(4, "big"),
            ]
        )

    def to_json_line(self) -> str:
        return json.dumps(
            {
                "log_index": self.log_index,
                "head_hash": b64encode(self.head_hash).decode(),
                "witness_index": self.witness_index,
                "sig": b64encode(self.sig).decode(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json_line(cls, line: str) -> "Checkpoint":
        obj = json.loads(line)
        return cls(
            log_index=int(obj["log_index"]),
            head_hash=b64decode(obj["head_hash"]),
            witness_index=int(obj["witness_index"]),
            sig=b64decode(obj["sig"]),
        )


def _checkpoints_path(log_path: Path) -> Path:
    return log_path.with_suffix(log_path.suffix + ".witnesses")


def read_checkpoints(log_path: Path) -> List[Checkpoint]:
    p = _checkpoints_path(log_path)
    if not p.exists():
        return []
    out: List[Checkpoint] = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(Checkpoint.from_json_line(line))
    return out


def emit_checkpoint(
    *,
    log_path: Path,
    cohort: PublisherCohort,
    witness_sk: ed25519.Ed25519PrivateKey,
    witness_index: int,
) -> Checkpoint:
    """
    Verify the entire log, then sign and append a checkpoint to the
    sidecar. Raises :class:`LogError` if the log itself fails to verify.
    """
    log = BulletinBoard(log_path)
    log.verify(cohort)  # raises LogError on any inconsistency
    entries = log.read_all()
    if not entries:
        raise LogError("cannot checkpoint an empty log")
    head = entries[-1]
    cp = Checkpoint(
        log_index=head.index,
        head_hash=head.hash(),
        witness_index=witness_index,
        sig=b"",  # filled in below
    )
    sig = witness_sk.sign(cp.signing_preimage())
    cp = Checkpoint(
        log_index=cp.log_index,
        head_hash=cp.head_hash,
        witness_index=cp.witness_index,
        sig=sig,
    )
    p = _checkpoints_path(log_path)
    with p.open("a", encoding="utf-8") as f:
        f.write(cp.to_json_line() + "\n")
    return cp


def verify_checkpoints(
    *,
    log_path: Path,
    witness_pks: Sequence[ed25519.Ed25519PublicKey],
    witness_threshold: int,
) -> List[Checkpoint]:
    """
    Return the list of *valid* checkpoints. Raises :class:`LogError` if:

    * a checkpoint's signature is invalid, or
    * two valid checkpoints sign the same ``log_index`` with different
      ``head_hash`` (equivocation evidence).

    Does *not* by itself enforce the ``witness_threshold``; the caller
    decides whether the latest co-signed index meets their inclusion
    requirements (see :func:`latest_cosigned_index`).
    """
    raw = read_checkpoints(log_path)
    valid: List[Checkpoint] = []
    seen: dict[int, bytes] = {}
    for cp in raw:
        if not (0 <= cp.witness_index < len(witness_pks)):
            raise LogError(
                f"checkpoint references witness {cp.witness_index} outside set"
            )
        try:
            witness_pks[cp.witness_index].verify(cp.sig, cp.signing_preimage())
        except InvalidSignature as exc:
            raise LogError(
                f"checkpoint by witness {cp.witness_index} at index "
                f"{cp.log_index} has invalid signature"
            ) from exc
        prior = seen.get(cp.log_index)
        if prior is None:
            seen[cp.log_index] = cp.head_hash
        elif prior != cp.head_hash:
            raise LogError(
                f"EQUIVOCATION: log index {cp.log_index} co-signed with "
                f"two different head hashes {prior.hex()} and {cp.head_hash.hex()}"
            )
        valid.append(cp)
    return valid


def latest_cosigned_index(
    checkpoints: Iterable[Checkpoint], witness_threshold: int
) -> int | None:
    """
    Among ``checkpoints``, return the largest ``log_index`` that has been
    signed by at least ``witness_threshold`` *distinct* witnesses, all
    agreeing on the same ``head_hash``. Returns ``None`` if no index meets
    the bar.
    """
    if witness_threshold <= 0:
        return None
    by_index: dict[int, dict[bytes, set[int]]] = {}
    for cp in checkpoints:
        by_index.setdefault(cp.log_index, {}).setdefault(cp.head_hash, set()).add(
            cp.witness_index
        )
    best: int | None = None
    for idx, hashes in by_index.items():
        for _h, witnesses in hashes.items():
            if len(witnesses) >= witness_threshold:
                if best is None or idx > best:
                    best = idx
    return best
