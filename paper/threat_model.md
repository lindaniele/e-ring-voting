# e-ring-voting v0.5 — Threat Model

What the design defends against, what it does not, and which test
exercises each claim. It complements `paper/artifact.tex`, which
describes the mechanisms and the analysis behind them.

Two system layers share the primitive (`trs/`) and the election logic
(`voting/records.py`, `groups.py`, `tally.py`):

- **The design (Architecture B, `chain/`)**: a permissionless
  proof-of-work chain with deposits, beacon-assigned groups and
  key-transfer rounds. Sections 1–4.
- **The baseline (Architecture A, `voting/`)**: a t-of-N
  threshold-signed bulletin board with a k-of-M witness federation,
  one ring, no deposits. Section 5.

## Assumptions

- DDH in Ristretto255; RFC 9380 hash-to-curve and SHA-512 modelled as
  random oracles; Ed25519 unforgeability.
- Honest voters keep their TRS secret keys secret.
- For B: an honest majority of hash power during the poll. For A: at
  least t honest cohort members (liveness) and k honest witnesses
  (equivocation evidence).

## 1. Principals (B)

- **Creator**: Ed25519 account that opens a poll and fixes its
  parameters (options, schedule, group size `k`, rounds, deposit `D`).
  Has no power after setup: no transaction closes, tallies or freezes a
  poll.
- **Sponsor**: Ed25519 account that registers a voter, paying the fee
  and locking `D`. May be the voter, the creator or anyone else.
- **Voter**: holds a TRS key; proves possession at registration; in each
  round signs once, a ballot or a key transfer.
- **Miner**: produces blocks; chooses which transactions to include and,
  within the rules, the block timestamp.
- **Anyone**: replays the chain and obtains groups, tally, culprits and
  settlement (`python3 -m chain.cli audit`).

## 2. Properties (B)

| Property | Holds? | Mechanism | Test |
|---|---|---|---|
| A single ballot hides its signer within its group | Yes | FS07 anonymity (DDH, ROM) | `test_trs.py::TestAnonymity` |
| Two different messages by a key in a round expose the key | Yes | FS07 trace, per-group tag book | `test_chain.py::TestSingleRing::test_double_vote_burns_the_deposit` |
| The deposit of a round-0 double-signer is burned, others refunded | Yes | settlement at `voting_close` | same, and `::test_full_election_tallies_and_refunds` |
| Voting and moving in one round counts as a double-sign; the move is dropped | Yes | ballots and transfers share the tag | `test_chain.py::TestKeyTransfer::test_vote_and_transfer_is_a_double_sign` |
| Nobody can be framed by replays | Yes | copies are *linked*, refused on chain | `test_chain.py::TestSingleRing::test_replayed_ballot_is_invalid`, `test_tally.py::TestClassify::test_replays_of_two_voters_do_not_frame_anyone` |
| Nobody can register a key they do not control | Yes | Schnorr proof of possession | `test_chain.py::TestRegistration::test_proof_of_possession_required` |
| The creator cannot choose the groups | Yes | groups ordered by a hash keyed with `prev_hash` of the freezing block, registrations closed before it | `test_groups.py::TestAssignGroups::test_organiser_cannot_target_without_the_beacon` |
| Every group has at least `k` members (if ≥ 2k voters) | Yes | `assign_groups` | `test_groups.py::TestAssignGroups::test_partition_with_min_size` |
| A transfer never shrinks the voter's anonymity set | Yes, for an observer that does not count | the new key hides among all origin groups of its new group | `bench/bench_groups.py --anonymity` |
| Tally recomputable by anyone | Yes | the tally is a function of the chain | `test_chain.py::TestGroups::test_ballots_are_signed_per_group_and_tallied_together` |
| Blocks at the wrong difficulty are invalid | Yes | difficulty is a consensus rule | `test_chain.py::TestDifficultyRule` |
| Heaviest valid chain wins | Yes | `Node.consider` | `test_chain.py::TestForkChoice` |

## 3. Adversaries (B)

### 3.1 Double-voter
Signs two different messages (two ballots, or a ballot and a transfer)
in one round. Both are void, the key is published as a culprit and, if
it was registered in round 0, its sponsor loses `D`. At most two
messages per signer enter the chain; a third is invalid.

A key obtained by transfer has no deposit; its double-sign is voided
but not punished. Tying a deposit to it would link it to its origin,
which is what the transfer exists to prevent. Open problem.

### 3.2 Replayer / framer
Anyone can copy a ballot or transfer from the chain and resubmit it.
The copy is *linked* to the original (same signer, same message) and is
refused at block validation, so it neither changes the tally nor makes
anyone a culprit. By FS07 exculpability, two messages traced to a key
require its secret. (The rewrite before v0.5 got this wrong: it blamed
ring position 1 for a pair of copies.)

### 3.3 Creator / organiser
Chooses parameters and which keys it sponsors, but only before
`registration_close`, before the beacon exists. It cannot place a key
next to a target, close the poll early, publish a tally, or withhold
refunds. It can pick a small `k`; voters should check `k` against the
sybil share they expect (3.5).

### 3.4 Miner
- **Beacon bias.** The miner of the block whose hash becomes the beacon
  can discard blocks with unwanted assignments, and choose its timestamp
  so as to decide which block crosses `voting_open`. Each discarded block
  costs its reward and the work to replace it. Isolating a given honest
  voter (no honest peer in its group) takes about `1/p` draws, where `p`
  is measured by `bench_groups --anonymity`: with half the keys
  adversarial, `p ≈ 0.8 %` for `k = 8` (≈ 130 discarded blocks) and
  `p ≈ 13 %` for `k = 4` (no grinding needed). Mitigation: VDF or
  commit–reveal beacon (open).
- **Censorship.** Ballots and transfers pay no fee and carry no sender;
  a miner may leave them out. Honest miners include them; a majority
  that censors until a round ends disenfranchises. Not addressed.
- **Burn, not reward.** Deposits are burned rather than paid to the
  miner, so a miner gains nothing from double-signing with keys it
  registered itself.

### 3.5 Sybil registrant
Registers many keys (paying fees and locking deposits that come back if
the keys behave). It cannot be detected: a sybil that never double-signs
looks honest. It shrinks the honest part of each group:

| k | sybil share | honest set (round 0) | isolated honest voters | honest set (round 1, half move) |
|---:|---:|---:|---:|---:|
| 4 | 0.5 | 2.5 | 12.6 % | 7.9 |
| 8 | 0.5 | 4.5 | 0.8 % | 30.8 |
| 16 | 0.5 | 8.6 | 0 | 114.5 |

The deposit prices misbehaviour, not registration; sybils are priced by
the registration fee and by the sponsor's on-chain identity.

### 3.6 Observer
Sees every ballot's group and every transfer's origin group.
- **Per-group tallies are public.** A group that votes unanimously
  reveals every member's vote. Smaller `k` leaks more; transfers mix.
- **Counting.** How many members of a group voted or moved narrows
  transfer anonymity beyond the union metric above.
- **Cross-poll.** Sponsors' Ed25519 accounts are persistent; a voter who
  sponsors itself links its registrations across polls. TRS keys should
  be fresh per poll.

### 3.7 Hash-power renter
Rents a majority for the voting window and reorganises or censors. The
design inherits this from proof of work (Park, Specter, Narula, Rivest
2021) and does not change it.

### 3.8 Coercer / vote buyer, compromised device
Not defended. A voter who reveals `x` lets the coercer recompute
`h^x` and find the ballot; malware on the voter's device signs anything.
Handing a copy of the key to a buyer is *risky* for both (if both sign,
both lose), but a voter who sells and abstains is not deterred.

## 4. Not provided (B)

Receipt-freeness and coercion resistance; slashing of transferred keys;
an unbiasable beacon; incentives to include fee-less ballots; hiding
per-group tallies; post-quantum security; a network layer; constant-time
Python glue.

## 5. Baseline (A): federated bulletin board

Principals: a cohort of N publishers (any t co-sign each entry), voters,
M witnesses (co-sign log heads), auditors.

| Property | Holds? | Test |
|---|---|---|
| Anonymity in the (single) ring | Yes | `test_trs.py::TestAnonymity` |
| Double-vote traced and both ballots excluded | Yes, no penalty | `test_election.py::TestDoubleSign::test_double_sign_excludes_both_ballots` |
| Replayed copies neither drop votes nor frame | Yes | `test_election.py::TestDoubleSign::test_replayed_copies_neither_drop_votes_nor_frame`, `::test_manager_refuses_linked_ballot` |
| Forged / tampered ballots rejected | Yes | `test_election.py::TestAdversaries` |
| Fewer than t publishers cannot append | Yes | `test_threshold.py::TestThresholdAppend` |
| Equivocation by ≥ t publishers produces evidence | Yes, with witnesses | `test_threshold.py::TestWitnesses::test_equivocation_detected` |
| Claimed tally refuted if wrong | Yes | `test_election.py::TestAdversaries::test_audit_rejects_extra_record_after_tally` |
| Liveness against a unanimous cohort | No | — |
| Who forms the ring | The cohort | — |

A suits a small, accountable authority set and fast finality. It gives
nothing that B's deposits, beacon groups and transfers give, and B gives
up A's named accountability and instant finality.
