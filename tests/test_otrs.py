"""Tests for the Scafuro-Zhang one-time traceable ring signature (otrs/)."""

from __future__ import annotations

import os
import random
from typing import Dict, List, Sequence

import pytest

from otrs import (
    OTRS128,
    OTRS256,
    PublicKey,
    Ring,
    SecretKey,
    Signature,
    keygen,
    sign,
    trace,
    verify,
)
from otrs.primitives import H, LABEL_BYTES, params_for

CTX = b"poll-7/round-0"


def make_ring(n: int, params=OTRS128):
    kps = [keygen(params=params) for _ in range(n)]
    return kps, Ring([kp.pk for kp in kps])


# --------------------------------------------------------------------------- #
# A signer that chooses every opening by hand (for attack tests)               #
# --------------------------------------------------------------------------- #


def hand_sign(
    ring: Ring,
    message: bytes,
    equivocator: Sequence[int],
    secrets: Dict[int, SecretKey],
    rng: random.Random,
    context: bytes = CTX,
    planted: Dict[tuple, bytes] | None = None,
) -> Signature:
    """
    Produce a signature where row ``j`` is equivocated by member
    ``equivocator[j]`` (whose secret is in ``secrets``). Every other opening
    is an honest Naor commitment with a random bit and seed, except the
    ``planted`` ``(i, j) -> seed`` entries, whose bit is 0. This is the full
    freedom an adversary controlling ``secrets`` has.
    """
    p = ring.params
    n, lam, sb = len(ring), p.rows, p.seed_bytes
    bits = [[rng.getrandbits(1) for _ in range(lam)] for _ in range(n)]
    seeds = [[rng.randbytes(sb) for _ in range(lam)] for _ in range(n)]
    for (i, j), seed in (planted or {}).items():
        bits[i][j], seeds[i][j] = 0, seed
    for j, e in enumerate(equivocator):
        bits[e][j], seeds[e][j] = 0, secrets[e].seed(j, 0)

    def pack(rows):
        return int("".join(map(str, rows)), 2).to_bytes(sb, "big")

    xs = [pack(b) for b in bits]
    cat = b"".join(s for row in seeds for s in row)
    commitments = ring._commitments(xs, ring._openings(cat))
    z = int.from_bytes(H(p, context, ring.digest, message, commitments), "big")
    for j, e in enumerate(equivocator):
        parity = 0
        for i in range(n):
            parity ^= bits[i][j]
        want = (z >> (lam - 1 - j)) & 1
        if parity != want:
            bits[e][j] = 1
            seeds[e][j] = secrets[e].seed(j, 1)
    xs = [pack(b) for b in bits]
    return Signature(params=p, xs=tuple(xs), seeds=b"".join(s for row in seeds for s in row))


# --------------------------------------------------------------------------- #
# Correctness                                                                  #
# --------------------------------------------------------------------------- #


class TestCorrectness:
    @pytest.mark.parametrize("n", [1, 2, 3, 8])
    def test_every_position_signs_and_verifies(self, n):
        kps, ring = make_ring(n)
        for kp in kps:
            sig = ring.sign(kp, b"yes", CTX)
            assert ring.verify(sig, b"yes", CTX)

    def test_lambda_256(self):
        kps, ring = make_ring(3, OTRS256)
        sig = ring.sign(kps[1], b"yes", CTX)
        assert ring.verify(sig, b"yes", CTX)
        assert len(sig.to_bytes()) == OTRS256.sig_bytes(3)
        assert ring.trace(sig, ring.sign(kps[1], b"no", CTX)).culprits == (1,)

    def test_functional_interface(self):
        kps, ring = make_ring(4)
        pks = list(ring.keys)
        sig = sign(kps[2], pks, b"m", CTX)
        assert verify(pks, b"m", sig, CTX)
        assert trace(pks, sig, sign(kps[2], pks, b"m'", CTX)).culprit_pks == (kps[2].pk,)

    def test_sizes_match_the_paper(self):
        # Public key 3λ² bits, signature N·λ·(λ+1) bits (+ our headers).
        kps, ring = make_ring(8)
        assert len(kps[0].pk.to_bytes()) == 1 + 32 + 128 * 48
        sig = ring.sign(kps[0], b"m")
        assert len(sig.to_bytes()) == 5 + 8 * 128 * 129 // 8

    def test_signing_is_deterministic(self):
        kps, ring = make_ring(4)
        a = ring.sign(kps[0], b"yes", CTX)
        assert ring.sign(kps[0], b"yes", CTX).to_bytes() == a.to_bytes()
        assert ring.sign(kps[0], b"yes", b"other").to_bytes() != a.to_bytes()
        assert ring.trace(a, ring.sign(kps[0], b"yes", CTX)).status == "identical"

    def test_encodings_round_trip(self):
        kps, ring = make_ring(3)
        sig = ring.sign(kps[1], b"m", CTX)
        assert Signature.from_bytes(sig.to_bytes()) == sig
        assert PublicKey.from_bytes(kps[1].pk.to_bytes()) == kps[1].pk
        sk = SecretKey.from_bytes(kps[1].sk.to_bytes())
        assert sk.public_key() == kps[1].pk

    def test_master_and_label_determine_the_key(self):
        master = os.urandom(32)
        a = keygen(b"\x01" * 32, master=master)
        b = keygen(b"\x01" * 32, master=master)
        c = keygen(b"\x02" * 32, master=master)
        assert a.pk == b.pk
        # A wallet can derive one key per poll from a single master secret.
        assert set(a.pk.rows).isdisjoint(c.pk.rows)

    def test_params_lookup(self):
        assert params_for(128) is OTRS128 and params_for(256) is OTRS256
        with pytest.raises(ValueError):
            params_for(192)


class TestRejection:
    def test_wrong_message_context_or_ring(self):
        kps, ring = make_ring(4)
        sig = ring.sign(kps[0], b"yes", CTX)
        assert not ring.verify(sig, b"no", CTX)
        assert not ring.verify(sig, b"yes", b"poll-8")
        other = Ring(list(ring.keys[:3]) + [keygen().pk])
        assert not other.verify(sig, b"yes", CTX)
        permuted = Ring(list(reversed(ring.keys)))
        assert not permuted.verify(sig, b"yes", CTX)

    def test_tampered_seed_or_bit(self):
        kps, ring = make_ring(3)
        sig = ring.sign(kps[2], b"yes", CTX)
        flipped = bytearray(sig.seeds)
        flipped[100] ^= 1
        assert not ring.verify(
            Signature(sig.params, sig.xs, bytes(flipped)), b"yes", CTX
        )
        xs = list(sig.xs)
        xs[0] = bytes([xs[0][0] ^ 0x80]) + xs[0][1:]
        assert not ring.verify(Signature(sig.params, tuple(xs), sig.seeds), b"yes", CTX)

    def test_malformed_encodings(self):
        kps, ring = make_ring(2)
        blob = ring.sign(kps[0], b"m").to_bytes()
        with pytest.raises(ValueError):
            Signature.from_bytes(blob[:-1])
        with pytest.raises(ValueError):
            Signature.from_bytes(b"\x07" + blob[1:])
        with pytest.raises(ValueError):
            PublicKey.from_bytes(kps[0].pk.to_bytes()[:-1])

    def test_ring_rules(self):
        kps, ring = make_ring(2)
        with pytest.raises(ValueError, match="duplicate"):
            Ring([kps[0].pk, kps[0].pk])
        with pytest.raises(ValueError, match="parameter"):
            Ring([kps[0].pk, keygen(params=OTRS256).pk])
        with pytest.raises(ValueError, match="not a member"):
            ring.sign(keygen(), b"m")
        with pytest.raises(ValueError):
            Ring([])

    def test_signature_for_another_ring_size(self):
        kps, ring = make_ring(3)
        _, small = make_ring(2)
        assert not small.verify(ring.sign(kps[0], b"m"), b"m")


# --------------------------------------------------------------------------- #
# Traceability                                                                 #
# --------------------------------------------------------------------------- #


class TestTraceability:
    def test_two_messages_expose_the_signer(self):
        kps, ring = make_ring(6)
        a = ring.sign(kps[4], b"yes", CTX)
        b = ring.sign(kps[4], b"no", CTX)
        result = ring.trace(a, b)
        assert result.status == "traced"
        assert result.culprits == (4,)
        assert result.culprit_pks == (kps[4].pk,)

    def test_same_message_with_fresh_randomness_is_traced(self):
        # The stronger traceability of [SZ21]: FS07 would only *link* these.
        kps, ring = make_ring(5)
        a = ring.sign(kps[1], b"yes", CTX, randomized=True)
        b = ring.sign(kps[1], b"yes", CTX, randomized=True)
        assert a.to_bytes() != b.to_bytes()
        assert ring.verify(a, b"yes", CTX) and ring.verify(b, b"yes", CTX)
        assert ring.trace(a, b).culprits == (1,)

    def test_other_context_still_traced(self):
        # Trace looks at the key, not at what was signed or under which tag.
        kps, ring = make_ring(3)
        a = ring.sign(kps[0], b"x", b"round-0")
        b = ring.sign(kps[0], b"x", b"round-1")
        assert ring.trace(a, b).culprits == (0,)

    def test_different_signers_are_independent(self):
        kps, ring = make_ring(6)
        sigs = [ring.sign(kp, b"yes", CTX) for kp in kps]
        for i in range(6):
            for j in range(i + 1, 6):
                assert ring.trace(sigs[i], sigs[j]).status == "independent"

    def test_singleton_ring(self):
        # Outside the paper's |R| >= 2, and without anonymity, but trace
        # still works; a poll round may contain a single transferred key.
        kps, ring = make_ring(1)
        a, b = ring.sign(kps[0], b"a"), ring.sign(kps[0], b"b")
        assert ring.verify(a, b"a") and ring.trace(a, b).culprits == (0,)

    def test_culprits_from_openings(self):
        kps, ring = make_ring(4)
        a = ring.check(ring.sign(kps[3], b"a", CTX), b"a", CTX)
        b = ring.check(ring.sign(kps[3], b"b", CTX), b"b", CTX)
        c = ring.check(ring.sign(kps[0], b"c", CTX), b"c", CTX)
        assert ring.culprits(a, b) == [3]
        assert ring.culprits(a, c) == [] and ring.culprits(b, c) == []


class TestCoalition:
    """Public traceability: ``t`` keys yield at most ``t`` untraced signatures."""

    def test_two_keys_two_signatures_third_is_traced(self):
        rng = random.Random(1)
        kps, ring = make_ring(5)
        A, B = 1, 3
        secrets = {A: kps[A].sk, B: kps[B].sk}
        lam = ring.params.rows
        half = lam // 2
        s1 = hand_sign(ring, b"m1", [A] * half + [B] * half, secrets, rng)
        s2 = hand_sign(ring, b"m2", [B] * half + [A] * half, secrets, rng)
        for s, m in ((s1, b"m1"), (s2, b"m2")):
            assert ring.verify(s, m, CTX)
        # Each key's rows were opened by only one of the two: no trace yet.
        assert ring.trace(s1, s2).status == "independent"
        s3 = hand_sign(ring, b"m3", [A] * lam, secrets, rng)
        assert ring.verify(s3, b"m3", CTX)
        culprits = set(ring.trace(s1, s3).culprits) | set(ring.trace(s2, s3).culprits)
        assert culprits and culprits <= {A, B}

    def test_a_coalition_signature_can_trace_several_keys(self):
        rng = random.Random(2)
        kps, ring = make_ring(4)
        secrets = {0: kps[0].sk, 2: kps[2].sk}
        lam = ring.params.rows
        a = hand_sign(ring, b"a", [0, 2] * (lam // 2), secrets, rng)
        b = hand_sign(ring, b"b", [0, 2] * (lam // 2), secrets, rng)
        assert ring.trace(a, b).culprits == (0, 2)


# --------------------------------------------------------------------------- #
# Exculpability                                                                #
# --------------------------------------------------------------------------- #


class TestExculpability:
    def test_copied_seeds_do_not_frame_an_honest_signer(self):
        rng = random.Random(3)
        kps, ring = make_ring(4)
        honest, adv = 0, 2
        sig = ring.sign(kps[honest], b"yes", CTX)
        lam = ring.params.rows
        # The adversary plants the honest signer's revealed seeds at the
        # honest position of its own signatures, then signs twice.
        planted = {(honest, j): sig.seed(honest, j) for j in range(lam)}
        a = hand_sign(ring, b"x", [adv] * lam, {adv: kps[adv].sk}, rng, planted=planted)
        b = hand_sign(ring, b"y", [adv] * lam, {adv: kps[adv].sk}, rng, planted=planted)
        assert ring.verify(a, b"x", CTX) and ring.verify(b, b"y", CTX)
        assert honest not in ring.trace(sig, a).culprits
        assert honest not in ring.trace(sig, b).culprits
        assert ring.trace(a, b).culprits == (adv,)

    def test_signer_reveals_exactly_one_seed_per_row(self):
        kps, ring = make_ring(3)
        sk = kps[1].sk
        sig = ring.sign(kps[1], b"m", CTX)
        for j in range(ring.params.rows):
            assert sig.seed(1, j) in (sk.seed(j, 0), sk.seed(j, 1))
        # Only the holder of a secret can see it was used; everybody else
        # sees openings that, without the other seed, look like any others.
        assert all(sig.seed(0, j) not in (kps[0].sk.seed(j, 0), kps[0].sk.seed(j, 1))
                   for j in range(ring.params.rows))


# --------------------------------------------------------------------------- #
# The zero-row gap                                                             #
# --------------------------------------------------------------------------- #


class TestZeroRow:
    """A key with zero rows breaks traceability; ``Ring`` refuses it."""

    def _zero_key(self) -> PublicKey:
        p = OTRS128
        return PublicKey(params=p, label=bytes(LABEL_BYTES),
                         rows=tuple(bytes(p.row_bytes) for _ in range(p.rows)))

    def test_zero_key_signs_twice_untraced_if_unchecked(self):
        rng = random.Random(4)
        kps = [keygen() for _ in range(3)]
        zero = self._zero_key()
        ring = Ring([kp.pk for kp in kps] + [zero], _check_keys=False)
        z = 3
        lam = ring.params.rows

        class AnySeed:
            # With pk_{z,j} = 0 the same seed opens either bit.
            def seed(self, j, bit):
                return seeds[j]

        sigs = []
        for m in (b"yes", b"no", b"yes"):
            seeds = [rng.randbytes(16) for _ in range(lam)]
            sig = hand_sign(ring, m, [z] * lam, {z: AnySeed()}, rng)
            assert ring.verify(sig, m, CTX)  # Fig. 1 verification accepts
            sigs.append(sig)
        for i in range(3):
            for j in range(i + 1, 3):
                assert ring.trace(sigs[i], sigs[j]).status == "independent"

    def test_zero_rows_are_refused(self):
        zero = self._zero_key()
        with pytest.raises(ValueError, match="zero"):
            Ring([keygen().pk, zero])
        with pytest.raises(ValueError, match="zero"):
            PublicKey.from_bytes(zero.to_bytes())
        one_zero = PublicKey(
            params=OTRS128, label=bytes(32),
            rows=(bytes(48),) + keygen().pk.rows[1:],
        )
        assert any("row 0 is zero" in p for p in one_zero.problems())
