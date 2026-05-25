"""
Typed transactions for the PoW chain.

The chain is **value-bearing** (eVotes) and **poll-bearing** (election
records). Every transaction has a kind discriminator and a kind-specific
body. The eight kinds are:

==========================  ===========  ======================================
kind                        signed by    purpose
==========================  ===========  ======================================
``coinbase``                — (none)     mint block reward to miner
``transfer``                sender       eVote payment between accounts
``setup_poll``              poll creator open a new poll (wraps ElectionSetup)
``register_voter``          sponsor      register a voter pubkey for a poll
``publish_ring``            poll creator freeze the voter set into a ring
``ballot``                  — (none)     submit an OTRS-signed ballot
``close_poll``              poll creator declare voting closed
``tally``                   poll creator publish a claimed tally
==========================  ===========  ======================================

**Anonymity note.** The ``ballot`` kind carries *no* Ed25519 sender
identity and *no* fee — anyone may broadcast a valid OTRS-signed ballot
and miners are expected to include it (a policy rule enforced by the
validator). This preserves voter anonymity at the chain layer: a ballot
on-chain is indistinguishable in metadata across voters in the ring.

The trade-off is that ballots are not Sybil-priced; spamming
attacker-generated ballots is prevented by their *OTRS verification
cost*: only ring members can produce a valid signature. Outside that
ring, anyone trying to flood the mempool gets their transactions
rejected at validation time.

Canonical encoding: JSON with ``sort_keys=True`` and
``separators=(",", ":")`` over a top-level ``{"kind": ..., "body": ...}``
object. Binary blobs are base64-standard-encoded. This matches the
``voting/records.py`` convention so the wrapped voting records remain
byte-identical to their bulletin-board form.
"""

from __future__ import annotations

import enum
import hashlib
import json
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

# --------------------------------------------------------------------------- #
# Kind enum                                                                    #
# --------------------------------------------------------------------------- #


class TxKind(str, enum.Enum):
    COINBASE = "coinbase"
    TRANSFER = "transfer"
    SETUP_POLL = "setup_poll"
    REGISTER_VOTER = "register_voter"
    PUBLISH_RING = "publish_ring"
    BALLOT = "ballot"
    CLOSE_POLL = "close_poll"
    TALLY = "tally"


SIGNED_KINDS = frozenset({
    TxKind.TRANSFER.value,
    TxKind.SETUP_POLL.value,
    TxKind.REGISTER_VOTER.value,
    TxKind.PUBLISH_RING.value,
    TxKind.CLOSE_POLL.value,
    TxKind.TALLY.value,
})


class TxError(Exception):
    """Raised on malformed transactions or invalid signatures."""


# --------------------------------------------------------------------------- #
# Canonical JSON                                                               #
# --------------------------------------------------------------------------- #


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------- #
# Transaction dataclass                                                        #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Transaction:
    """
    Type-tagged transaction. The kind discriminator drives validation in
    :mod:`chain.state`. The body is an arbitrary JSON-serialisable dict
    whose schema depends on the kind.

    Two transactions with the same canonical bytes have the same ``id`` —
    so coinbase transactions intentionally include the block ``height`` in
    their body to keep them unique across blocks (otherwise miners with
    deterministic block-template generators would replay the same id).
    """

    kind: str
    body: Dict[str, Any]

    def canonical_bytes(self) -> bytes:
        return canonical_json({"kind": self.kind, "body": self.body})

    @property
    def id(self) -> bytes:
        """Transaction id = SHA-256 of canonical bytes."""
        return hashlib.sha256(self.canonical_bytes()).digest()


# --------------------------------------------------------------------------- #
# Signature helpers                                                            #
# --------------------------------------------------------------------------- #


def _signing_message(kind: str, body_without_sig: Dict[str, Any]) -> bytes:
    return canonical_json({"kind": kind, "body": body_without_sig})


def sign_tx(
    kind: str, body: Dict[str, Any], sk: ed25519.Ed25519PrivateKey
) -> Transaction:
    """Sign ``body`` under ``sk`` and return a Transaction with the sig embedded."""
    if "signature_b64" in body:
        raise TxError("body must not pre-set 'signature_b64'")
    msg = _signing_message(kind, body)
    sig = sk.sign(msg)
    return Transaction(
        kind=kind,
        body={**body, "signature_b64": b64encode(sig).decode()},
    )


def verify_tx_sig(tx: Transaction, signer_pk_raw: bytes) -> bool:
    """Verify ``tx``'s embedded signature against ``signer_pk_raw`` (32 bytes)."""
    sig_b64 = tx.body.get("signature_b64")
    if sig_b64 is None:
        return False
    if len(signer_pk_raw) != 32:
        return False
    body_without_sig = {k: v for k, v in tx.body.items() if k != "signature_b64"}
    msg = _signing_message(tx.kind, body_without_sig)
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(signer_pk_raw)
        pk.verify(b64decode(sig_b64), msg)
        return True
    except (ValueError, InvalidSignature):
        return False


# --------------------------------------------------------------------------- #
# Constructors — coinbase + transfer                                           #
# --------------------------------------------------------------------------- #


def make_coinbase(miner_pk_raw: bytes, amount: int, height: int) -> Transaction:
    """Mint ``amount`` eVotes to ``miner_pk_raw``. Tied to ``height`` for uniqueness."""
    if len(miner_pk_raw) != 32:
        raise TxError("miner_pk must be 32 bytes")
    if amount < 0:
        raise TxError("coinbase amount must be non-negative")
    return Transaction(
        kind=TxKind.COINBASE.value,
        body={
            "miner_pk_b64": b64encode(miner_pk_raw).decode(),
            "amount": int(amount),
            "height": int(height),
        },
    )


def make_transfer(
    sender_pk_raw: bytes,
    recipients: List[Tuple[bytes, int]],
    fee: int,
    nonce: int,
    sk: ed25519.Ed25519PrivateKey,
) -> Transaction:
    """
    Transfer eVotes from ``sender_pk_raw`` to ``recipients`` (a list of
    ``(pk_raw, amount)`` tuples), paying ``fee`` to the miner.

    The signer (``sk``) must correspond to ``sender_pk_raw`` — we don't
    cross-check here; validation in ``chain.state`` will reject the tx if
    the keys disagree.
    """
    if len(sender_pk_raw) != 32:
        raise TxError("sender_pk must be 32 bytes")
    body = {
        "sender_pk_b64": b64encode(sender_pk_raw).decode(),
        "recipients": [
            {"pk_b64": b64encode(pk).decode(), "amount": int(amt)}
            for pk, amt in recipients
        ],
        "fee": int(fee),
        "nonce": int(nonce),
    }
    return sign_tx(TxKind.TRANSFER.value, body, sk)


# --------------------------------------------------------------------------- #
# Constructors — voting transactions                                           #
# --------------------------------------------------------------------------- #


def make_setup_poll(
    creator_pk_raw: bytes,
    setup_payload: bytes,
    fee: int,
    nonce: int,
    sk: ed25519.Ed25519PrivateKey,
) -> Transaction:
    """Open a new poll. ``setup_payload`` is the canonical bytes of an
    :class:`voting.records.ElectionSetup`."""
    body = {
        "creator_pk_b64": b64encode(creator_pk_raw).decode(),
        "setup_payload_b64": b64encode(setup_payload).decode(),
        "fee": int(fee),
        "nonce": int(nonce),
    }
    return sign_tx(TxKind.SETUP_POLL.value, body, sk)


def make_register_voter(
    sponsor_pk_raw: bytes,
    election_id: str,
    registration_payload: bytes,
    fee: int,
    nonce: int,
    sk: ed25519.Ed25519PrivateKey,
) -> Transaction:
    body = {
        "sponsor_pk_b64": b64encode(sponsor_pk_raw).decode(),
        "election_id": str(election_id),
        "registration_payload_b64": b64encode(registration_payload).decode(),
        "fee": int(fee),
        "nonce": int(nonce),
    }
    return sign_tx(TxKind.REGISTER_VOTER.value, body, sk)


def make_publish_ring(
    creator_pk_raw: bytes,
    election_id: str,
    ring_payload: bytes,
    fee: int,
    nonce: int,
    sk: ed25519.Ed25519PrivateKey,
) -> Transaction:
    body = {
        "creator_pk_b64": b64encode(creator_pk_raw).decode(),
        "election_id": str(election_id),
        "ring_payload_b64": b64encode(ring_payload).decode(),
        "fee": int(fee),
        "nonce": int(nonce),
    }
    return sign_tx(TxKind.PUBLISH_RING.value, body, sk)


def make_ballot(election_id: str, ballot_payload: bytes) -> Transaction:
    """
    Anonymous ballot. No Ed25519 signature, no sender, no fee, no nonce.

    Validity is checked by the state machine: the OTRS signature inside
    ``ballot_payload`` must verify against the published ring for this
    election, and the choice must be in the option set.
    """
    return Transaction(
        kind=TxKind.BALLOT.value,
        body={
            "election_id": str(election_id),
            "ballot_payload_b64": b64encode(ballot_payload).decode(),
        },
    )


def make_close_poll(
    creator_pk_raw: bytes,
    election_id: str,
    closed_payload: bytes,
    fee: int,
    nonce: int,
    sk: ed25519.Ed25519PrivateKey,
) -> Transaction:
    body = {
        "creator_pk_b64": b64encode(creator_pk_raw).decode(),
        "election_id": str(election_id),
        "closed_payload_b64": b64encode(closed_payload).decode(),
        "fee": int(fee),
        "nonce": int(nonce),
    }
    return sign_tx(TxKind.CLOSE_POLL.value, body, sk)


def make_tally(
    creator_pk_raw: bytes,
    election_id: str,
    tally_payload: bytes,
    fee: int,
    nonce: int,
    sk: ed25519.Ed25519PrivateKey,
) -> Transaction:
    body = {
        "creator_pk_b64": b64encode(creator_pk_raw).decode(),
        "election_id": str(election_id),
        "tally_payload_b64": b64encode(tally_payload).decode(),
        "fee": int(fee),
        "nonce": int(nonce),
    }
    return sign_tx(TxKind.TALLY.value, body, sk)


# --------------------------------------------------------------------------- #
# Tx-list encoding (used by block.py)                                          #
# --------------------------------------------------------------------------- #


def encode_tx_list(txs: List[Transaction]) -> bytes:
    out = bytearray()
    for tx in txs:
        b = tx.canonical_bytes()
        out += len(b).to_bytes(4, "big")
        out += b
    return bytes(out)


def decode_tx_list(blob: bytes, count: int) -> Tuple[List[Transaction], int]:
    """
    Returns ``(transactions, bytes_consumed)``. Raises if truncated.
    """
    out: List[Transaction] = []
    pos = 0
    for _ in range(count):
        if pos + 4 > len(blob):
            raise TxError("truncated tx-length prefix")
        n = int.from_bytes(blob[pos:pos + 4], "big")
        pos += 4
        if pos + n > len(blob):
            raise TxError("truncated tx body")
        out.append(_parse_tx_bytes(blob[pos:pos + n]))
        pos += n
    return out, pos


def _parse_tx_bytes(blob: bytes) -> Transaction:
    try:
        obj = json.loads(blob)
    except json.JSONDecodeError as exc:
        raise TxError(f"tx is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict) or "kind" not in obj or "body" not in obj:
        raise TxError("tx must be a JSON object with 'kind' and 'body'")
    kind = obj["kind"]
    if kind not in {k.value for k in TxKind}:
        raise TxError(f"unknown tx kind: {kind!r}")
    body = obj["body"]
    if not isinstance(body, dict):
        raise TxError("tx body must be an object")
    # Recompute canonical bytes; if the input wasn't canonical it would have
    # a different id, but we accept it for parsing — validation later will
    # detect canonical-bytes mismatch when verifying signatures.
    return Transaction(kind=kind, body=body)


def tx_list_root(txs: List[Transaction]) -> bytes:
    """SHA-256 over the concatenation of each tx's canonical bytes."""
    h = hashlib.sha256()
    for tx in txs:
        h.update(tx.canonical_bytes())
    return h.digest()
