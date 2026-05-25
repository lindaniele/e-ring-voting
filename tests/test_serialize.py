"""Encoding tests."""

import pytest

from otrs.group import Scalar, base_mul
from otrs.otrs import PublicKey
from otrs.serialize import decode_signature, encode_ring, encode_signature


class TestEncodeRing:
    def test_length_prefix(self):
        ring = [base_mul(Scalar.from_int(i + 1)) for i in range(3)]
        out = encode_ring(ring)
        assert out[:4] == (3).to_bytes(4, "big")
        assert len(out) == 4 + 3 * 32

    def test_order_sensitive(self):
        r1 = [base_mul(Scalar.from_int(i + 1)) for i in range(3)]
        r2 = [r1[1], r1[0], r1[2]]
        assert encode_ring(r1) != encode_ring(r2)


class TestEncodeSignature:
    def test_round_trip(self):
        A1 = base_mul(Scalar.from_int(2))
        c = [Scalar.from_int(i + 1) for i in range(4)]
        z = [Scalar.from_int(i + 100) for i in range(4)]
        blob = encode_signature(A1, c, z)
        a1d, cd, zd = decode_signature(blob)
        assert a1d.raw == A1.raw
        for orig, dec in zip(c, cd):
            assert orig.raw == dec.raw
        for orig, dec in zip(z, zd):
            assert orig.raw == dec.raw

    def test_truncation_rejected(self):
        A1 = base_mul(Scalar.from_int(2))
        c = [Scalar.from_int(1), Scalar.from_int(2)]
        z = [Scalar.from_int(3), Scalar.from_int(4)]
        blob = encode_signature(A1, c, z)
        with pytest.raises(ValueError):
            decode_signature(blob[:-1])

    def test_extra_bytes_rejected(self):
        A1 = base_mul(Scalar.from_int(2))
        c = [Scalar.from_int(1)]
        z = [Scalar.from_int(2)]
        blob = encode_signature(A1, c, z) + b"\x00"
        with pytest.raises(ValueError):
            decode_signature(blob)
