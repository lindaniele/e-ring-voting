"""
Append-only, hash-chained, threshold-signed bulletin board.

v0.3 generalises v0.2's single-publisher model to a *publisher cohort* of
$N$ Ed25519 keys with a $t$-of-$N$ threshold for entry commit. The data
structure is otherwise unchanged: a JSON-Lines file where each line is an
:class:`Entry`. The cohort public keys and the threshold $t$ are pinned in
the :class:`ElectionSetup` genesis record, not in the log file itself, so
that auditors have a single point of truth for the publisher set.

The single-manager v0.2 model is the degenerate case ``N = 1, t = 1``.

What this gives us, in addition to v0.2:

* **Liveness against a minority of unavailable publishers.** Up to
  $N - t$ cohort members may be offline; the election still progresses.
* **Resistance to a minority colluding to censor.** A faction smaller
  than $t$ cannot append on its own, so they cannot publish a forged
  record without convincing $t - 1$ honest members to co-sign.

What it still does not give us (this is the witness layer in
``voting/witness.py``):

* **Equivocation resistance.** A *majority* cohort that has compromised
  $t$ members can still publish two divergent logs. Witnesses co-sign
  log heads off-band; auditors require k-of-M-co-signed checkpoints and
  reject elections where witnesses disagree.

Hash-chain semantics: the entry hash covers only the *content*
``(index, prev_hash, timestamp, payload)`` — signatures are metadata.
This matches the transparency-log convention (CT, Sigsum) and means a
collection of valid signatures over time does not change the hash of an
entry, which keeps the chain stable while the cohort collects co-signs.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS_PREV_HASH = b"\x00" * 32
HASH_BYTES = 32
ED25519_PK_BYTES = 32
ED25519_SIG_BYTES = 64


class LogError(Exception):
    """Raised on any inconsistency in a bulletin-board log."""


# --------------------------------------------------------------------------- #
# Entry                                                                        #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Entry:
    """A single entry in the bulletin board.

    ``publisher_sigs`` is a list of ``(cohort_member_index, ed25519_sig)``
    tuples. The entry is *committed* iff there are at least ``threshold``
    distinct member indices, each with a valid Ed25519 signature over
    :meth:`signing_preimage`.
    """

    index: int
    prev_hash: bytes
    timestamp: int
    payload: bytes
    publisher_sigs: List[Tuple[int, bytes]]

    def __post_init__(self) -> None:
        if self.index < 0:
            raise LogError("entry.index must be non-negative")
        if len(self.prev_hash) != HASH_BYTES:
            raise LogError(f"entry.prev_hash must be {HASH_BYTES} bytes")
        if self.timestamp < 0:
            raise LogError("entry.timestamp must be non-negative")
        if not self.publisher_sigs:
            raise LogError("entry.publisher_sigs must be non-empty")
        seen: set[int] = set()
        for idx, sig in self.publisher_sigs:
            if idx < 0:
                raise LogError("publisher_sig index must be non-negative")
            if idx in seen:
                raise LogError(f"duplicate cohort member index {idx}")
            seen.add(idx)
            if len(sig) != ED25519_SIG_BYTES:
                raise LogError("publisher_sig must be 64 bytes (Ed25519)")

    # ----- canonical encoding -------------------------------------------- #

    def signing_preimage(self) -> bytes:
        """
        Bytes that every cohort member signs and that go into the entry hash.

        Layout (all big-endian, fixed widths):
            index           : 8 bytes
            prev_hash       : 32 bytes
            timestamp       : 8 bytes
            payload_len     : 4 bytes
            payload         : payload_len bytes
        """
        return b"".join(
            [
                self.index.to_bytes(8, "big"),
                self.prev_hash,
                self.timestamp.to_bytes(8, "big"),
                len(self.payload).to_bytes(4, "big"),
                self.payload,
            ]
        )

    def hash(self) -> bytes:
        """SHA-256 over the signing preimage — independent of signatures."""
        return hashlib.sha256(self.signing_preimage()).digest()

    # ----- JSON-Lines serialization -------------------------------------- #

    def to_json_line(self) -> str:
        obj = {
            "index": self.index,
            "prev_hash": b64encode(self.prev_hash).decode(),
            "timestamp": self.timestamp,
            "payload": b64encode(self.payload).decode(),
            "publisher_sigs": [
                {"i": i, "sig": b64encode(s).decode()}
                for i, s in sorted(self.publisher_sigs, key=lambda x: x[0])
            ],
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json_line(cls, line: str) -> "Entry":
        try:
            obj = json.loads(line)
            return cls(
                index=int(obj["index"]),
                prev_hash=b64decode(obj["prev_hash"]),
                timestamp=int(obj["timestamp"]),
                payload=b64decode(obj["payload"]),
                publisher_sigs=[
                    (int(s["i"]), b64decode(s["sig"]))
                    for s in obj["publisher_sigs"]
                ],
            )
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise LogError(f"malformed log line: {exc}") from exc


# --------------------------------------------------------------------------- #
# Cohort                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PublisherCohort:
    """The static publisher set agreed at election setup."""

    pks: List[ed25519.Ed25519PublicKey]
    threshold: int

    def __post_init__(self) -> None:
        n = len(self.pks)
        if n < 1:
            raise LogError("publisher cohort must have at least 1 member")
        if not (1 <= self.threshold <= n):
            raise LogError(
                f"threshold {self.threshold} not in [1, {n}]"
            )

    @property
    def size(self) -> int:
        return len(self.pks)


# --------------------------------------------------------------------------- #
# BulletinBoard                                                                #
# --------------------------------------------------------------------------- #


class BulletinBoard:
    """
    Append-only log persisted as JSON Lines on disk.

    The :class:`PublisherCohort` is supplied at every operation; we do not
    cache it because the *authoritative* source of cohort identity is the
    :class:`ElectionSetup` record on the log itself (see
    ``voting/records.py``). For convenience, ``append`` performs a quick
    cross-check against the cohort it is given.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    # ----- writing (publisher cohort only) ------------------------------- #

    def append(
        self,
        payload: bytes,
        signers: Sequence[Tuple[int, ed25519.Ed25519PrivateKey]],
        cohort: PublisherCohort,
    ) -> Entry:
        """
        Sign and append an entry. ``signers`` is a list of
        ``(member_index, sk)`` for *at least* :attr:`cohort.threshold`
        distinct cohort members.

        We immediately verify every signature against ``cohort.pks`` before
        writing to disk, so the log file always satisfies the cohort
        threshold invariant. (If you need a multi-round protocol where
        different cohort members sign over time, see
        :class:`PendingEntry`.)
        """
        if len(signers) < cohort.threshold:
            raise LogError(
                f"only {len(signers)} signer(s) provided; need at least "
                f"{cohort.threshold}"
            )
        seen: set[int] = set()
        for idx, _ in signers:
            if idx in seen:
                raise LogError(f"duplicate signer index {idx}")
            if not (0 <= idx < cohort.size):
                raise LogError(
                    f"signer index {idx} out of cohort range [0, {cohort.size})"
                )
            seen.add(idx)

        entries = self.read_all()
        if entries:
            prev = entries[-1]
            index = prev.index + 1
            prev_hash = prev.hash()
        else:
            index = 0
            prev_hash = GENESIS_PREV_HASH

        timestamp = int(time.time())
        # The preimage is independent of signatures, so we can compute it
        # once and have every member sign it.
        preimage = b"".join(
            [
                index.to_bytes(8, "big"),
                prev_hash,
                timestamp.to_bytes(8, "big"),
                len(payload).to_bytes(4, "big"),
                payload,
            ]
        )
        sigs: List[Tuple[int, bytes]] = []
        for idx, sk in signers:
            sig = sk.sign(preimage)
            try:
                cohort.pks[idx].verify(sig, preimage)
            except InvalidSignature as exc:
                raise LogError(
                    f"signer index {idx}'s sig does not verify under cohort pk[{idx}]"
                ) from exc
            sigs.append((idx, sig))

        entry = Entry(
            index=index,
            prev_hash=prev_hash,
            timestamp=timestamp,
            payload=payload,
            publisher_sigs=sigs,
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(entry.to_json_line() + "\n")
        return entry

    # ----- reading (everyone) -------------------------------------------- #

    def read_all(self) -> List[Entry]:
        if not self.path.exists():
            return []
        out: List[Entry] = []
        with self.path.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(Entry.from_json_line(line))
                except LogError as e:
                    raise LogError(f"line {lineno}: {e}") from e
        return out

    def iter_entries(self) -> Iterator[Entry]:
        return iter(self.read_all())

    def head_hash(self) -> bytes:
        entries = self.read_all()
        return entries[-1].hash() if entries else GENESIS_PREV_HASH

    def head_index(self) -> int:
        entries = self.read_all()
        return entries[-1].index if entries else -1

    # ----- verification --------------------------------------------------- #

    def verify(self, cohort: PublisherCohort) -> None:
        """
        Verify the entire log under the supplied cohort.

        Raises :class:`LogError` on the first inconsistency. Checks:

        1. Indices are 0, 1, 2, ... contiguous.
        2. Each prev_hash equals the previous entry's hash (genesis = zeros).
        3. Every signature in :attr:`Entry.publisher_sigs` is a valid Ed25519
           signature under the cohort key at that index.
        4. The set of distinct signer indices has size ≥ ``cohort.threshold``.
        5. Timestamps are non-decreasing.
        """
        entries = self.read_all()
        expected_prev = GENESIS_PREV_HASH
        last_ts: Optional[int] = None
        for i, e in enumerate(entries):
            if e.index != i:
                raise LogError(f"entry {i}: bad index {e.index}")
            if e.prev_hash != expected_prev:
                raise LogError(f"entry {i}: prev_hash mismatch")
            distinct = {idx for idx, _ in e.publisher_sigs}
            if len(distinct) < cohort.threshold:
                raise LogError(
                    f"entry {i}: only {len(distinct)} distinct cohort signers, "
                    f"need ≥ {cohort.threshold}"
                )
            preimage = e.signing_preimage()
            for idx, sig in e.publisher_sigs:
                if not (0 <= idx < cohort.size):
                    raise LogError(
                        f"entry {i}: cohort index {idx} out of range"
                    )
                try:
                    cohort.pks[idx].verify(sig, preimage)
                except InvalidSignature as exc:
                    raise LogError(
                        f"entry {i}: invalid signature for cohort member {idx}"
                    ) from exc
            if last_ts is not None and e.timestamp < last_ts:
                raise LogError(f"entry {i}: timestamp decreased")
            expected_prev = e.hash()
            last_ts = e.timestamp


# --------------------------------------------------------------------------- #
# Pending entry (for asynchronous cohort co-signing)                          #
# --------------------------------------------------------------------------- #


@dataclass
class PendingEntry:
    """
    A proposed entry that has not yet collected enough signatures.

    Persisted as a sidecar JSON file at ``<log>.pending``. Cohort members
    each fetch the pending file, sign the preimage, and append their
    ``(index, sig)`` pair. When the number of distinct sigs reaches the
    threshold, anyone in the cohort can commit it to the log by calling
    :meth:`BulletinBoard.commit_pending`.
    """

    index: int
    prev_hash: bytes
    timestamp: int
    payload: bytes
    sigs: List[Tuple[int, bytes]] = field(default_factory=list)

    def preimage(self) -> bytes:
        return b"".join(
            [
                self.index.to_bytes(8, "big"),
                self.prev_hash,
                self.timestamp.to_bytes(8, "big"),
                len(self.payload).to_bytes(4, "big"),
                self.payload,
            ]
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "index": self.index,
                "prev_hash": b64encode(self.prev_hash).decode(),
                "timestamp": self.timestamp,
                "payload": b64encode(self.payload).decode(),
                "sigs": [
                    {"i": i, "sig": b64encode(s).decode()} for i, s in self.sigs
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, s: str) -> "PendingEntry":
        obj = json.loads(s)
        return cls(
            index=int(obj["index"]),
            prev_hash=b64decode(obj["prev_hash"]),
            timestamp=int(obj["timestamp"]),
            payload=b64decode(obj["payload"]),
            sigs=[(int(s["i"]), b64decode(s["sig"])) for s in obj.get("sigs", [])],
        )


def _pending_path(log_path: Path) -> Path:
    return log_path.with_suffix(log_path.suffix + ".pending")


def propose_entry(log_path: Path, payload: bytes) -> PendingEntry:
    """Create the pending sidecar (or refuse if one already exists)."""
    log = BulletinBoard(log_path)
    pp = _pending_path(log_path)
    if pp.exists():
        raise LogError("a pending entry already exists; commit or abort it first")
    entries = log.read_all()
    if entries:
        index = entries[-1].index + 1
        prev = entries[-1].hash()
    else:
        index = 0
        prev = GENESIS_PREV_HASH
    pending = PendingEntry(
        index=index,
        prev_hash=prev,
        timestamp=int(time.time()),
        payload=payload,
    )
    pp.write_text(pending.to_json())
    return pending


def cosign_pending(
    log_path: Path,
    member_index: int,
    member_sk: ed25519.Ed25519PrivateKey,
    cohort: PublisherCohort,
) -> PendingEntry:
    """Add one cohort member's signature to the pending entry on disk."""
    pp = _pending_path(log_path)
    if not pp.exists():
        raise LogError("no pending entry")
    pending = PendingEntry.from_json(pp.read_text())
    if member_index in {i for i, _ in pending.sigs}:
        raise LogError(f"member {member_index} has already signed")
    sig = member_sk.sign(pending.preimage())
    try:
        cohort.pks[member_index].verify(sig, pending.preimage())
    except InvalidSignature as exc:
        raise LogError(
            f"member {member_index} sig does not verify under cohort pk"
        ) from exc
    pending.sigs.append((member_index, sig))
    pp.write_text(pending.to_json())
    return pending


def commit_pending(log_path: Path, cohort: PublisherCohort) -> Entry:
    """If the pending entry has ≥ threshold valid sigs, commit it to the log."""
    pp = _pending_path(log_path)
    if not pp.exists():
        raise LogError("no pending entry")
    pending = PendingEntry.from_json(pp.read_text())
    distinct = {i for i, _ in pending.sigs}
    if len(distinct) < cohort.threshold:
        raise LogError(
            f"pending has {len(distinct)} sigs, need ≥ {cohort.threshold}"
        )
    entry = Entry(
        index=pending.index,
        prev_hash=pending.prev_hash,
        timestamp=pending.timestamp,
        payload=pending.payload,
        publisher_sigs=pending.sigs,
    )
    with log_path.open("a", encoding="utf-8") as f:
        f.write(entry.to_json_line() + "\n")
    pp.unlink()
    return entry


# --------------------------------------------------------------------------- #
# Key persistence (Ed25519, unchanged from v0.2)                              #
# --------------------------------------------------------------------------- #


def save_publisher_sk(path: Path, sk: ed25519.Ed25519PrivateKey) -> None:
    from cryptography.hazmat.primitives import serialization

    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = Path(path)
    path.write_bytes(pem)
    os.chmod(path, 0o600)


def load_publisher_sk(path: Path) -> ed25519.Ed25519PrivateKey:
    from cryptography.hazmat.primitives import serialization

    pem = Path(path).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)  # type: ignore[return-value]


def save_publisher_pk(path: Path, pk: ed25519.Ed25519PublicKey) -> None:
    from cryptography.hazmat.primitives import serialization

    pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(path).write_bytes(pem)


def load_publisher_pk(path: Path) -> ed25519.Ed25519PublicKey:
    from cryptography.hazmat.primitives import serialization

    pem = Path(path).read_bytes()
    return serialization.load_pem_public_key(pem)  # type: ignore[return-value]


def pk_raw(pk: ed25519.Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def pk_from_raw(raw: bytes) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)
