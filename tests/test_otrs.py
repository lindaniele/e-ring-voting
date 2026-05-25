"""Functional tests for the OTRS scheme."""

import os

import pytest

from otrs import (
    KeyPair,
    Signature,
    keygen,
    sign,
    trace,
    verify,
)
from otrs.group import Scalar, base_mul
from otrs.otrs import PublicKey


def make_ring(n: int) -> list[KeyPair]:
    return [keygen() for _ in range(n)]


@pytest.fixture(params=[2, 3, 5, 8])
def ring_kp(request):
    return make_ring(request.param)


@pytest.fixture
def issue():
    return b"election:2026-05-24:demo"


class TestCorrectness:
    def test_sign_verify_roundtrip(self, ring_kp, issue):
        ring = [kp.pk for kp in ring_kp]
        signer = ring_kp[0]
        sig = sign(signer.sk, signer.pk, issue, b"vote: A", ring)
        assert verify(sig, issue, b"vote: A", ring) is True

    def test_singleton_ring(self, issue):
        # Degenerate but mathematically valid: ring of size 1 reduces to a
        # plain Schnorr proof of knowledge of x. No anonymity, but the scheme
        # must still produce a verifiable signature.
        kp = keygen()
        ring = [kp.pk]
        sig = sign(kp.sk, kp.pk, issue, b"m", ring)
        assert verify(sig, issue, b"m", ring)
        # Tracing a "double-sign" on a size-1 ring is degenerate: the
        # "all-columns-match" branch fires because n = 1 trivially equals the
        # match count, so the status label is "linked" rather than
        # "double-sign". Both labels indicate misbehavior; the distinction
        # only matters when |ring| ≥ 2, which is the realistic regime.
        sig2 = sign(kp.sk, kp.pk, issue, b"m'", ring)
        res = trace(issue, ring, b"m", sig, b"m'", sig2)
        assert res.status in {"double-sign", "linked"}
        assert res.status != "independent"

    def test_sign_verify_each_position(self, issue):
        ring_kp = make_ring(5)
        ring = [kp.pk for kp in ring_kp]
        for i, signer in enumerate(ring_kp):
            sig = sign(signer.sk, signer.pk, issue, f"msg-{i}".encode(), ring)
            assert verify(sig, issue, f"msg-{i}".encode(), ring), f"position {i+1} failed"

    def test_signature_round_trip_bytes(self, ring_kp, issue):
        ring = [kp.pk for kp in ring_kp]
        signer = ring_kp[0]
        sig = sign(signer.sk, signer.pk, issue, b"vote", ring)
        blob = sig.to_bytes()
        sig2 = Signature.from_bytes(blob)
        assert verify(sig2, issue, b"vote", ring) is True


class TestNegative:
    def test_verify_rejects_tampered_message(self, ring_kp, issue):
        ring = [kp.pk for kp in ring_kp]
        signer = ring_kp[0]
        sig = sign(signer.sk, signer.pk, issue, b"vote: A", ring)
        assert verify(sig, issue, b"vote: B", ring) is False

    def test_verify_rejects_tampered_issue(self, ring_kp, issue):
        ring = [kp.pk for kp in ring_kp]
        signer = ring_kp[0]
        sig = sign(signer.sk, signer.pk, issue, b"vote", ring)
        assert verify(sig, b"different-issue", b"vote", ring) is False

    def test_verify_rejects_wrong_ring(self, issue):
        ring_kp = make_ring(4)
        ring = [kp.pk for kp in ring_kp]
        signer = ring_kp[0]
        sig = sign(signer.sk, signer.pk, issue, b"vote", ring)
        # Swap one member out for a fresh key.
        new_member = keygen().pk
        bad_ring = [new_member] + ring[1:]
        assert verify(sig, issue, b"vote", bad_ring) is False

    def test_verify_rejects_permuted_ring(self, issue):
        ring_kp = make_ring(4)
        ring = [kp.pk for kp in ring_kp]
        signer = ring_kp[0]
        sig = sign(signer.sk, signer.pk, issue, b"vote", ring)
        # Permute — the canonical encoding includes order, so this must fail.
        permuted = [ring[1], ring[0]] + ring[2:]
        assert verify(sig, issue, b"vote", permuted) is False

    def test_verify_rejects_modified_response(self, ring_kp, issue):
        ring = [kp.pk for kp in ring_kp]
        signer = ring_kp[0]
        sig = sign(signer.sk, signer.pk, issue, b"vote", ring)
        # Flip z[0] to a random scalar.
        tampered = Signature(
            A1=sig.A1,
            c=sig.c,
            z=[Scalar.random()] + sig.z[1:],
        )
        assert verify(tampered, issue, b"vote", ring) is False

    def test_verify_rejects_modified_challenge(self, ring_kp, issue):
        ring = [kp.pk for kp in ring_kp]
        signer = ring_kp[0]
        sig = sign(signer.sk, signer.pk, issue, b"vote", ring)
        tampered = Signature(
            A1=sig.A1,
            c=[Scalar.random()] + sig.c[1:],
            z=sig.z,
        )
        assert verify(tampered, issue, b"vote", ring) is False

    def test_verify_rejects_random_blob(self, issue):
        # A random "signature" — no honest signer involved — must be rejected.
        # This is the forgery-resistance smoke test; the security proof in
        # [SZ21] proves the strong statement that this rejection holds for
        # any PPT adversary under DDH + ROM.
        ring_kp = make_ring(5)
        ring = [kp.pk for kp in ring_kp]
        forged = Signature(
            A1=base_mul(Scalar.random()),
            c=[Scalar.random() for _ in range(5)],
            z=[Scalar.random() for _ in range(5)],
        )
        assert verify(forged, issue, b"vote", ring) is False

    def test_wrong_secret_key_for_pk(self, issue):
        # Even if a signer manages to embed someone else's pk in the ring and
        # signs with their own (unrelated) sk, Verify must reject because the
        # Sigma equation a_position = g^z · pk_position^c fails.
        kp1 = keygen()
        kp2 = keygen()
        ring = [kp2.pk]  # ring contains kp2's pk, not kp1's
        # Bypass _find_position by lying about the pk while supplying kp1's sk.
        # _find_position checks raw bytes, so we must pass kp2.pk to "sign".
        # Now sigma_i = h^{kp1.sk.x}, but the OR equation requires kp2.x. Fails.
        sig = sign(kp1.sk, kp2.pk, issue, b"m", ring)
        assert verify(sig, issue, b"m", ring) is False

    def test_signer_not_in_ring_raises(self, issue):
        ring_kp = make_ring(3)
        outsider = keygen()
        ring = [kp.pk for kp in ring_kp]
        with pytest.raises(ValueError, match="not in the supplied ring"):
            sign(outsider.sk, outsider.pk, issue, b"vote", ring)

    def test_duplicate_ring_raises(self, issue):
        kp = keygen()
        with pytest.raises(ValueError, match="duplicate"):
            sign(kp.sk, kp.pk, issue, b"vote", [kp.pk, kp.pk])


class TestTraceability:
    def test_double_sign_detected(self, issue):
        ring_kp = make_ring(6)
        ring = [kp.pk for kp in ring_kp]
        culprit_idx = 2  # 0-indexed
        culprit = ring_kp[culprit_idx]
        s1 = sign(culprit.sk, culprit.pk, issue, b"vote: yes", ring)
        s2 = sign(culprit.sk, culprit.pk, issue, b"vote: no", ring)
        assert verify(s1, issue, b"vote: yes", ring)
        assert verify(s2, issue, b"vote: no", ring)
        result = trace(issue, ring, b"vote: yes", s1, b"vote: no", s2)
        assert result.status == "double-sign"
        assert result.culprit_index == culprit_idx + 1
        assert result.culprit_pk is not None
        assert result.culprit_pk.point.raw == culprit.pk.point.raw

    def test_independent_signers(self, issue):
        ring_kp = make_ring(6)
        ring = [kp.pk for kp in ring_kp]
        s1 = sign(ring_kp[0].sk, ring_kp[0].pk, issue, b"vote: yes", ring)
        s2 = sign(ring_kp[4].sk, ring_kp[4].pk, issue, b"vote: yes", ring)
        result = trace(issue, ring, b"vote: yes", s1, b"vote: yes", s2)
        assert result.status == "independent"

    def test_linked_replay_detected(self, issue):
        # Identical message twice — same column-by-column equality.
        # (In voting, replay is benign — same vote — but the protocol still
        #  classifies it as linked rather than independent.)
        ring_kp = make_ring(4)
        ring = [kp.pk for kp in ring_kp]

        # Force a deterministic signer by reusing a fixed nonce path is hard
        # without internal hooks. Instead, simulate "linked" by re-encoding
        # the same signature object.
        s = sign(ring_kp[1].sk, ring_kp[1].pk, issue, b"vote: A", ring)
        result = trace(issue, ring, b"vote: A", s, b"vote: A", s)
        assert result.status == "linked"

    def test_different_issue_not_traceable(self):
        # Tracing only applies within a single (issue, ring). Distinct issues
        # are by design unlinkable.
        ring_kp = make_ring(4)
        ring = [kp.pk for kp in ring_kp]
        signer = ring_kp[0]
        s1 = sign(signer.sk, signer.pk, b"election-A", b"vote", ring)
        s2 = sign(signer.sk, signer.pk, b"election-B", b"vote", ring)
        # The trace API requires a single issue; we only ensure the protocol
        # cannot link across issues. Concretely, signatures from distinct
        # issues produce distinct h = H0(issue || ring), so trace under
        # "election-A" of s2 would yield independence — but we don't even
        # supply s2 with a mismatched issue; we just confirm the construction
        # does not cross-leak. We assert by reproducing s1's σ_i_under_A and
        # s2's σ_i_under_B differ.
        from otrs.hash import hash_to_group
        from otrs.otrs import DST_H0
        from otrs.serialize import encode_ring
        ring_bytes = encode_ring([pk.point for pk in ring])
        h_A = hash_to_group(b"election-A" + ring_bytes, DST_H0)
        h_B = hash_to_group(b"election-B" + ring_bytes, DST_H0)
        sigma_A = h_A.scalar_mul(signer.sk.x)
        sigma_B = h_B.scalar_mul(signer.sk.x)
        assert sigma_A.raw != sigma_B.raw


class TestAnonymity:
    """
    Anonymity is information-theoretic in the (DDH, ROM) model — we cannot
    "test" the security proof. What we *can* test is the directly-observable
    invariant a correct implementation must satisfy: the distribution of
    signatures is invariant in the signer's index, conditioned on (issue, ring,
    message). We approximate this by asserting that signatures by different
    members produce non-trivially differing signature blobs (sanity) and that
    a single signature reveals nothing structurally about the position.
    """

    def test_signatures_from_different_members_have_same_size(self):
        ring_kp = make_ring(5)
        ring = [kp.pk for kp in ring_kp]
        sizes = set()
        for kp in ring_kp:
            sig = sign(kp.sk, kp.pk, b"e", b"m", ring)
            sizes.add(len(sig.to_bytes()))
        assert len(sizes) == 1, "Signature size leaks signer index"

    def test_position_not_revealed_by_a1(self):
        # A_1 = (σ_i − A_0)·(1/i). Different members yield different σ_i and
        # different positions, but A_1 should be distributed over the group.
        # We assert simply that two members at different positions produce
        # distinct A_1 (with overwhelming probability).
        ring_kp = make_ring(5)
        ring = [kp.pk for kp in ring_kp]
        s_a = sign(ring_kp[0].sk, ring_kp[0].pk, b"e", b"m", ring)
        s_b = sign(ring_kp[3].sk, ring_kp[3].pk, b"e", b"m", ring)
        assert s_a.A1.raw != s_b.A1.raw
