"""Bulletin board (voting/log.py) tests."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from voting.log import (
    GENESIS_PREV_HASH,
    BulletinBoard,
    Entry,
    LogError,
    PublisherCohort,
    load_publisher_pk,
    load_publisher_sk,
    save_publisher_pk,
    save_publisher_sk,
)


@pytest.fixture
def cohort1():
    """Trivial single-publisher cohort (N=1, t=1) — v0.2 model."""
    sk = ed25519.Ed25519PrivateKey.generate()
    return PublisherCohort(pks=[sk.public_key()], threshold=1), [(0, sk)]


@pytest.fixture
def board(tmp_path):
    return BulletinBoard(tmp_path / "log.jsonl")


class TestBasicAppend:
    def test_empty_log(self, board):
        assert board.read_all() == []
        assert board.head_hash() == GENESIS_PREV_HASH

    def test_first_entry_genesis_prev_hash(self, board, cohort1):
        cohort, signers = cohort1
        e = board.append(b"hello", signers, cohort)
        assert e.index == 0
        assert e.prev_hash == GENESIS_PREV_HASH

    def test_chain_linked(self, board, cohort1):
        cohort, signers = cohort1
        e0 = board.append(b"a", signers, cohort)
        e1 = board.append(b"b", signers, cohort)
        e2 = board.append(b"c", signers, cohort)
        assert e1.prev_hash == e0.hash()
        assert e2.prev_hash == e1.hash()

    def test_indices_contiguous(self, board, cohort1):
        cohort, signers = cohort1
        for i in range(5):
            board.append(f"x{i}".encode(), signers, cohort)
        assert [e.index for e in board.read_all()] == [0, 1, 2, 3, 4]


class TestVerify:
    def test_verifies_clean_log(self, board, cohort1):
        cohort, signers = cohort1
        for i in range(5):
            board.append(f"payload-{i}".encode(), signers, cohort)
        board.verify(cohort)  # no exception

    def test_rejects_wrong_cohort(self, board, cohort1):
        cohort, signers = cohort1
        board.append(b"x", signers, cohort)
        evil = ed25519.Ed25519PrivateKey.generate()
        evil_cohort = PublisherCohort(pks=[evil.public_key()], threshold=1)
        with pytest.raises(LogError, match="invalid signature"):
            board.verify(evil_cohort)

    def test_rejects_chain_break(self, board, cohort1, tmp_path):
        cohort, signers = cohort1
        board.append(b"a", signers, cohort)
        board.append(b"b", signers, cohort)
        # Surgically corrupt the second line's prev_hash field.
        lines = (tmp_path / "log.jsonl").read_text().splitlines()
        bad = lines[1].replace(
            lines[1].split('"prev_hash":"')[1].split('"')[0],
            "A" * 44,
        )
        (tmp_path / "log.jsonl").write_text("\n".join([lines[0], bad]) + "\n")
        with pytest.raises(LogError):
            board.verify(cohort)

    def test_rejects_reordered_indices(self, board, cohort1, tmp_path):
        cohort, signers = cohort1
        board.append(b"a", signers, cohort)
        board.append(b"b", signers, cohort)
        lines = (tmp_path / "log.jsonl").read_text().splitlines()
        (tmp_path / "log.jsonl").write_text("\n".join(reversed(lines)) + "\n")
        with pytest.raises(LogError):
            board.verify(cohort)


class TestKeyPersistence:
    def test_sk_round_trip(self, tmp_path):
        sk = ed25519.Ed25519PrivateKey.generate()
        p = tmp_path / "sk.pem"
        save_publisher_sk(p, sk)
        assert (p.stat().st_mode & 0o777) == 0o600
        sk2 = load_publisher_sk(p)
        msg = b"hello"
        sig = sk2.sign(msg)
        sk.public_key().verify(sig, msg)

    def test_pk_round_trip(self, tmp_path):
        sk = ed25519.Ed25519PrivateKey.generate()
        p = tmp_path / "pk.pem"
        save_publisher_pk(p, sk.public_key())
        pk2 = load_publisher_pk(p)
        msg = b"hello"
        pk2.verify(sk.sign(msg), msg)


class TestEntryShape:
    def test_rejects_bad_field_widths(self):
        with pytest.raises(LogError):
            Entry(
                index=0, prev_hash=b"\x00" * 31, timestamp=0, payload=b"",
                publisher_sigs=[(0, b"\x00" * 64)],
            )
        with pytest.raises(LogError):
            Entry(
                index=0, prev_hash=b"\x00" * 32, timestamp=0, payload=b"",
                publisher_sigs=[(0, b"\x00" * 63)],
            )
        with pytest.raises(LogError):
            Entry(
                index=-1, prev_hash=b"\x00" * 32, timestamp=0, payload=b"",
                publisher_sigs=[(0, b"\x00" * 64)],
            )
        with pytest.raises(LogError, match="non-empty"):
            Entry(
                index=0, prev_hash=b"\x00" * 32, timestamp=0, payload=b"",
                publisher_sigs=[],
            )

    def test_rejects_duplicate_member_indices(self):
        with pytest.raises(LogError, match="duplicate"):
            Entry(
                index=0, prev_hash=b"\x00" * 32, timestamp=0, payload=b"",
                publisher_sigs=[(0, b"\x00" * 64), (0, b"\x11" * 64)],
            )

    def test_hash_changes_with_payload(self):
        sig = b"\x00" * 64
        e_a = Entry(
            index=0, prev_hash=GENESIS_PREV_HASH, timestamp=0, payload=b"a",
            publisher_sigs=[(0, sig)],
        )
        e_b = Entry(
            index=0, prev_hash=GENESIS_PREV_HASH, timestamp=0, payload=b"b",
            publisher_sigs=[(0, sig)],
        )
        assert e_a.hash() != e_b.hash()

    def test_hash_is_independent_of_sigs(self):
        """Per the v0.3 design, the entry hash covers only the content."""
        sig_a = b"\x00" * 64
        sig_b = b"\xff" * 64
        e_a = Entry(
            index=0, prev_hash=GENESIS_PREV_HASH, timestamp=0, payload=b"x",
            publisher_sigs=[(0, sig_a)],
        )
        e_b = Entry(
            index=0, prev_hash=GENESIS_PREV_HASH, timestamp=0, payload=b"x",
            publisher_sigs=[(0, sig_b)],
        )
        assert e_a.hash() == e_b.hash()
