"""Property-based tests with Hypothesis."""

from hypothesis import HealthCheck, given, settings, strategies as st

from otrs import keygen, sign, trace, verify
from otrs.group import ORDER, Scalar, base_mul
from otrs.otrs import PublicKey


@st.composite
def ring_of_size(draw, min_size=2, max_size=8):
    n = draw(st.integers(min_value=min_size, max_value=max_size))
    return [keygen() for _ in range(n)]


# Keygen and signing are cryptographic ops; cap the example count and disable
# the "slow data generation" health check so we can keep meaningful sizes.
PROP_SETTINGS = settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)


@PROP_SETTINGS
@given(
    ring=ring_of_size(),
    issue=st.binary(min_size=1, max_size=64),
    message=st.binary(min_size=0, max_size=128),
    signer_idx_seed=st.integers(min_value=0, max_value=1000),
)
def test_sign_then_verify(ring, issue, message, signer_idx_seed):
    signer = ring[signer_idx_seed % len(ring)]
    pks = [kp.pk for kp in ring]
    sig = sign(signer.sk, signer.pk, issue, message, pks)
    assert verify(sig, issue, message, pks)


@PROP_SETTINGS
@given(
    ring=ring_of_size(min_size=2, max_size=6),
    issue=st.binary(min_size=1, max_size=32),
    m1=st.binary(min_size=0, max_size=32),
    m2=st.binary(min_size=0, max_size=32),
    seed=st.integers(min_value=0, max_value=10_000),
)
def test_double_sign_always_traces(ring, issue, m1, m2, seed):
    # Force m1 ≠ m2 so we exercise the "double-sign" path rather than "linked".
    if m1 == m2:
        m2 = m2 + b"x"
    culprit = ring[seed % len(ring)]
    pks = [kp.pk for kp in ring]
    s1 = sign(culprit.sk, culprit.pk, issue, m1, pks)
    s2 = sign(culprit.sk, culprit.pk, issue, m2, pks)
    res = trace(issue, pks, m1, s1, m2, s2)
    assert res.status == "double-sign"
    assert res.culprit_pk.point.raw == culprit.pk.point.raw


@PROP_SETTINGS
@given(
    ring=ring_of_size(min_size=2, max_size=6),
    issue=st.binary(min_size=1, max_size=32),
    message=st.binary(min_size=0, max_size=32),
    s1_seed=st.integers(min_value=0, max_value=1000),
    s2_seed=st.integers(min_value=0, max_value=1000),
)
def test_independent_signers_not_flagged(ring, issue, message, s1_seed, s2_seed):
    if len(ring) < 2:
        return
    i1 = s1_seed % len(ring)
    i2 = s2_seed % len(ring)
    if i1 == i2:
        i2 = (i2 + 1) % len(ring)
    pks = [kp.pk for kp in ring]
    s1 = sign(ring[i1].sk, ring[i1].pk, issue, message, pks)
    s2 = sign(ring[i2].sk, ring[i2].pk, issue, message, pks)
    res = trace(issue, pks, message, s1, message, s2)
    # When the same message is signed by different members, σ_j columns differ
    # for j ≠ i1, i2 (different A_0 doesn't apply here since m is same, but
    # σ_{i1} differs from σ_{i2}). Expected: "independent".
    assert res.status == "independent"
