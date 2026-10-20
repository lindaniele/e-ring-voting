"""Group assignment and round tags (voting/groups.py)."""

from __future__ import annotations

import os

import pytest

from voting.groups import assign_groups, issue_for

EID = "ab" * 32


def keys(n):
    return [os.urandom(32) for _ in range(n)]


class TestAssignGroups:
    @pytest.mark.parametrize("n,k", [(2, 2), (7, 3), (10, 3), (100, 8), (101, 10)])
    def test_partition_with_min_size(self, n, k):
        members = keys(n)
        groups = assign_groups(members, k, b"beacon", issue_for(EID, 0))
        assert sorted(pk for g in groups for pk in g) == sorted(members)
        assert all(k <= len(g) < 2 * k for g in groups)

    def test_fewer_members_than_group_size_make_one_group(self):
        members = keys(3)
        assert assign_groups(members, 5, b"b", b"l") == [sorted(members)]

    def test_zero_group_size_is_a_single_ring(self):
        members = keys(20)
        assert assign_groups(members, 0, b"b", b"l") == [sorted(members)]

    def test_deterministic_and_order_independent(self):
        members = keys(30)
        a = assign_groups(members, 4, b"beacon", b"label")
        b = assign_groups(list(reversed(members)), 4, b"beacon", b"label")
        assert a == b

    def test_beacon_and_round_change_the_assignment(self):
        members = keys(60)
        base = assign_groups(members, 5, b"beacon-1", issue_for(EID, 0))
        assert assign_groups(members, 5, b"beacon-2", issue_for(EID, 0)) != base
        assert assign_groups(members, 5, b"beacon-1", issue_for(EID, 1)) != base

    def test_organiser_cannot_target_without_the_beacon(self):
        # An organiser controlling half the keys fixes them before the beacon.
        # Over many beacons, the honest target's group is on average half
        # honest, i.e. the assignment does not concentrate sybils around it.
        honest, sybils = keys(30), keys(30)
        target = honest[0]
        honest_share = []
        for i in range(200):
            groups = assign_groups(honest + sybils, 6, i.to_bytes(4, "big"), b"l")
            (mine,) = [g for g in groups if target in g]
            others = [pk for pk in mine if pk != target]
            honest_share.append(sum(pk in honest for pk in others) / len(others))
        mean = sum(honest_share) / len(honest_share)
        assert 0.4 < mean < 0.6
        # Being surrounded only by sybils is a chance event (≈ (1/2)^5 per
        # draw here), not something the organiser can arrange.
        alone = sum(share == 0 for share in honest_share) / len(honest_share)
        assert alone < 0.1

    def test_duplicates_rejected(self):
        k = os.urandom(32)
        with pytest.raises(ValueError):
            assign_groups([k, k], 2, b"b", b"l")


def test_round_zero_issue_is_the_election_id():
    assert issue_for(EID, 0) == bytes.fromhex(EID)
    assert issue_for(EID, 1) != issue_for(EID, 2)
