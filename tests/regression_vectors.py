"""
Pinned regression vectors. Populated on the first successful test run via
``scripts/freeze_vectors.py``. The point of these is to catch silent regressions
in the hash-to-curve pipeline; they do not by themselves prove RFC 9380
compliance (cross-validation against RFC 9380 §K vectors is on the backlog).
"""

# Pinned on 2026-05-24, output of our expand_message_xmd(b"", DST_TEST, 32).
# DST_TEST = b"OTRS-TEST-V1-XMD:SHA-512-REGRESSION"
# This is a self-consistency vector. RFC 9380 §K cross-validation is on the
# backlog (the RFC's appendix lacks ristretto255-specific vectors in some
# normative drafts; we plan to verify against an independent reference impl).
EXPAND_XMD_EMPTY_32: str | None = (
    "f17846f192fa5d71aa3e9c5f44012e72b01653f5ea9b55a549037c5503948733"
)
