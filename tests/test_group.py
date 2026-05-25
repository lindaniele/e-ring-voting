"""Tests for the Ristretto255 wrapper."""

import os

import pytest

from otrs.group import ORDER, POINT_BYTES, SCALAR_BYTES, Point, Scalar, base_mul


class TestScalar:
    def test_round_trip_int(self):
        for v in [0, 1, 2, ORDER - 1, ORDER, ORDER + 1, 2**251]:
            s = Scalar.from_int(v)
            assert s.to_int() == v % ORDER
            assert len(s.raw) == SCALAR_BYTES

    def test_random_uniform(self):
        s1 = Scalar.random()
        s2 = Scalar.random()
        assert s1.raw != s2.raw
        assert 0 <= s1.to_int() < ORDER
        assert 0 <= s2.to_int() < ORDER

    def test_arithmetic_consistent_with_int(self):
        a = Scalar.from_int(12345)
        b = Scalar.from_int(67890)
        assert (a + b).to_int() == (12345 + 67890) % ORDER
        assert (a - b).to_int() == (12345 - 67890) % ORDER
        assert (a * b).to_int() == (12345 * 67890) % ORDER

    def test_invert_round_trip(self):
        a = Scalar.from_int(7)
        a_inv = a.invert()
        assert (a * a_inv).to_int() == 1

    def test_zero_invert_raises(self):
        with pytest.raises(ZeroDivisionError):
            Scalar.from_int(0).invert()

    def test_from_bytes_wide_requires_64(self):
        with pytest.raises(ValueError):
            Scalar.from_bytes_wide(b"\x00" * 32)


class TestPoint:
    def test_base_has_correct_encoding_length(self):
        g = Point.base()
        assert len(g.raw) == POINT_BYTES

    def test_base_is_nonzero(self):
        g = Point.base()
        # base point − base point = identity, encoded as all zeros in Ristretto.
        zero = g - g
        assert zero.raw != g.raw
        assert zero.raw == bytes(POINT_BYTES)

    def test_scalar_mul_distributes(self):
        g = Point.base()
        a = Scalar.from_int(3)
        b = Scalar.from_int(5)
        ab = a + b
        # g^(a+b) == g^a + g^b
        assert (base_mul(a) + base_mul(b)).raw == base_mul(ab).raw

    def test_scalar_mul_associates(self):
        # g^(a·b) == (g^a)^b
        a = Scalar.from_int(11)
        b = Scalar.from_int(13)
        lhs = base_mul(a * b)
        rhs = base_mul(a).scalar_mul(b)
        assert lhs.raw == rhs.raw

    def test_scalar_mul_by_zero_is_identity(self):
        g = Point.base()
        zero = Scalar.from_int(0)
        assert g.scalar_mul(zero).raw == bytes(POINT_BYTES)

    def test_scalar_mul_by_order_is_identity(self):
        # g^q = identity (group has order q).
        g = Point.base()
        q = Scalar.from_int(ORDER)
        # ORDER mod ORDER == 0 — Scalar.from_int reduces.
        assert g.scalar_mul(q).raw == bytes(POINT_BYTES)

    def test_invalid_encoding_rejected(self):
        with pytest.raises(ValueError):
            Point(b"\xff" * POINT_BYTES)

    def test_add_subtract_inverse(self):
        g = Point.base()
        h = base_mul(Scalar.from_int(42))
        # (g + h) - h == g
        assert ((g + h) - h).raw == g.raw

    def test_random_points_differ(self):
        p = base_mul(Scalar.random())
        q = base_mul(Scalar.random())
        assert p.raw != q.raw
