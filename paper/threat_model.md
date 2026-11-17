# e-ring-voting v1.0 — Threat Model

What the design defends against, what it does not, and which test
exercises each claim. It complements `paper/artifact.tex`, which
describes the mechanisms and the analysis behind them.

The design is a permissionless proof-of-work chain (`chain/`) whose
ballots are one-time traceable ring signatures (Scafuro–Zhang [SZ21],
`otrs/`), with deposits, beacon-assigned groups and key-transfer rounds.
The election logic shared by the chain lives in `voting/`.

## Assumptions

- SHAKE256, in the roles of `G` and `H` of [SZ21], behaves as a random
  oracle. The proofs of [SZ21] are in the *classical* random-oracle model;
  a proof in the quantum random-oracle model is open.
- Every honest key signs **once**: honest voters keep their master secret
  secret, sign deterministically (as `otrs` does) and never reuse a key.
  The chain enforces the rest (one use per key, labels).
- Ed25519 is unforgeable for the duration of a poll (it only protects
  accounts: sponsors, creators, payments).
- An honest majority of hash power during the poll.

## 1. Principals

- **Creator**: Ed25519 account that opens a poll and fixes its
  parameters (options, schedule, group size `k`, rounds, deposit `D`,
  security parameter λ). Has no power after setup: no transaction closes,
  tallies or freezes a poll.
- **Sponsor**: Ed25519 account that registers a voter, paying the fee
  and locking `D`. May be the voter, the creator or anyone else. Decides
  who is eligible (the chain does not).
- **Voter**: makes a one-time key labelled with the poll and its handle;
  in each round spends that key's single use on a ballot or on a key
  transfer.
- **Miner**: produces blocks; chooses which transactions to include and,
  within the rules, the block timestamp.
- **Anyone**: replays the chain and obtains groups, tally, culprits and
  settlement (`python3 -m chain.cli audit`).

## 2. Properties

| Property | Holds? | Mechanism | Test |
|---|---|---|---|
| A ballot hides its signer within its group | Yes, if the key is used once | one-time anonymity [SZ21] (ROM) | proof in [SZ21]; mechanism: `test_otrs.py::TestExculpability::test_signer_reveals_exactly_one_seed_per_row` |
| A second use of a key exposes it, whatever it signs | Yes | [SZ21] trace | `test_otrs.py::TestTraceability`, `test_chain.py::TestSingleRing::test_double_vote_burns_the_deposit`, `::test_same_ballot_signed_twice_with_fresh_randomness_is_traced` |
| `t` colluding keys get at most `t` untraced ballots in a group | Yes | public traceability [SZ21] | `test_otrs.py::TestCoalition`, `test_tally.py::TestTagBookAdmission::test_never_more_untraced_signatures_than_keys` |
| Keys with a zero row (untraceable) cannot enter a ring | Yes | check added to [SZ21, Fig. 1] | `test_otrs.py::TestZeroRow` |
| The deposit of a traced round-0 key is burned, others refunded | Yes | settlement at `voting_close` | `test_chain.py::TestSingleRing::test_double_vote_burns_the_deposit`, `::test_full_election_tallies_and_refunds` |
| Voting and moving in one round is two uses; the move is dropped | Yes | ballots and transfers are both signatures of the key | `test_chain.py::TestKeyTransfer::test_vote_and_transfer_is_a_double_sign` |
| Nobody can be framed by replays or by copied seeds | Yes | copies are byte-identical and refused; one-time exculpability [SZ21] | `test_chain.py::TestSingleRing::test_replayed_ballot_is_invalid`, `test_tally.py::TestClassify::test_copies_frame_nobody`, `test_otrs.py::TestExculpability::test_copied_seeds_do_not_frame_an_honest_signer` |
| A key serves one poll and one handle (or one transfer round) | Yes | key labels | `test_chain.py::TestRegistration::test_key_must_be_made_for_this_poll_and_handle`, `TestKeyTransfer::test_transfer_target_must_be_made_for_the_next_round` |
| The creator cannot choose the groups | Yes | groups ordered by a hash keyed with `prev_hash` of the freezing block, registrations closed before it | `test_groups.py::TestAssignGroups::test_organiser_cannot_target_without_the_beacon` |
| Every group has at least `k` members (if ≥ 2k voters) | Yes | `assign_groups` | `test_groups.py::TestAssignGroups::test_partition_with_min_size` |
| A transfer never shrinks the voter's anonymity set | Yes, for an observer that does not count | the new key hides among all origin groups of its new group | `bench/bench_groups.py --anonymity` |
| Tally recomputable by anyone | Yes | the tally is a function of the chain | `test_chain.py::TestGroups::test_ballots_are_signed_per_group_and_tallied_together` |
| Blocks at the wrong difficulty are invalid | Yes | difficulty is a consensus rule | `test_chain.py::TestDifficultyRule` |
| Heaviest valid chain wins | Yes | `Node.consider` | `test_chain.py::TestForkChoice` |

## 3. Adversaries

### 3.1 Double-voter
Uses its key twice in a round: two ballots, a ballot and a transfer, or
the *same* ballot signed again with fresh randomness. Any two distinct
signatures by one key trace it [SZ21], so every message involved is void,
the key is published as a culprit together with the handle it was
registered under and, if it was registered in round 0, its sponsor loses
`D`. A signature that only traces keys already exposed is invalid, so a
key adds at most one piece of evidence to the chain.

A *coalition* of `t` keys in a group can split the rows it opens among
its keys, but public traceability bounds it to `t` untraced signatures;
the `(t+1)`-th traces one of its keys. The coalition chooses *which* of
its keys is exposed, not whether one is.

A key obtained by transfer has no deposit; its second use voids its
messages but is not punished. Tying a deposit to it would link it to its
origin, which is what the transfer exists to prevent. Open problem.

### 3.2 Replayer / framer
Anyone can copy a ballot or transfer from the chain and resubmit it. The
copy is byte-identical and refused, so it neither changes the tally nor
makes anyone a culprit. Framing needs both seeds of one of the victim's
rows; a signature reveals only one, and copying it into another
signature does not help (`test_copied_seeds_do_not_frame_an_honest_signer`).

### 3.3 Creator / organiser
Chooses parameters and which keys it sponsors, but only before
`registration_close`, before the beacon exists. It cannot place a key
next to a target, close the poll early, publish a tally, or withhold
refunds. It can pick a small `k` (voters should check `k` against the
sybil share they expect, §3.6) or λ = 128 rather than 256.

### 3.4 Sponsor / registrant
A key's label binds it to one poll and one handle, so a registration
seen in the mempool cannot be copied under another handle or into
another poll. A sponsor that registers the same key and handle first
only pays the victim's fee and deposit. Garbage keys (random rows) look
like honest keys, as the anonymity proof requires; they are sybils that
abstain (§3.6). Rows equal to zero are refused (§2).

### 3.5 Miner
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
  miner, so a miner gains nothing from tracing keys it registered itself.

### 3.6 Sybil registrant
Registers many keys (paying fees and locking deposits that come back if
the keys behave). It cannot be detected: a sybil used once looks honest.
It shrinks the honest part of each group:

| k | sybil share | honest set (round 0) | isolated honest voters | honest set (round 1, half move) |
|---:|---:|---:|---:|---:|
| 4 | 0.5 | 2.5 | 12.6 % | 7.9 |
| 8 | 0.5 | 4.5 | 0.8 % | 30.8 |
| 16 | 0.5 | 8.6 | 0 | 114.5 |

The deposit prices misbehaviour, not registration; sybils are priced by
the registration fee and by the sponsor's on-chain identity.

### 3.7 Observer
Sees every ballot's group and every transfer's origin group.
- **Per-group tallies are public.** A group that votes unanimously
  reveals every member's vote. Smaller `k` leaks more; transfers mix.
- **Counting.** How many members of a group voted or moved narrows
  transfer anonymity beyond the union metric above.
- **Cross-poll.** One-time keys cannot be reused across polls (labels).
  Sponsors' Ed25519 accounts are persistent, so a voter who sponsors
  itself links its registrations across polls.

### 3.8 Quantum adversary, now or later
- **Ballot anonymity.** Breaking it means telling which position's
  opening seeds are a key's real seeds, a preimage search on `G` over
  λ-bit seeds: about `2^{λ/2}` quantum work by Grover, `2^λ` classically.
  λ = 256 keeps a 128-bit margin. Nothing in a ballot depends on discrete
  logarithms, so ballots recorded today are not readable by a future
  quantum computer the way FS07 ballots are.
- **Accounts.** Ed25519 falls to a quantum computer. That matters only
  while a poll runs (forging a sponsor or payment); past polls are fixed
  by the chain's proof of work.
- **Proofs.** [SZ21]'s security proofs are in the classical ROM.

### 3.9 Hash-power renter
Rents a majority for the voting window and reorganises or censors. The
design inherits this from proof of work (Park, Specter, Narula, Rivest
2021) and does not change it.

### 3.10 Coercer / vote buyer, compromised device
Not defended. A voter who reveals its master secret lets the coercer
recognise its ballot (its real seeds); malware on the device signs
anything. Handing a copy of the key to a buyer is *risky* for both (if
both sign, the key is traced and the deposit burned), but a voter who
sells and abstains is not deterred.

### 3.11 Careless wallet
A wallet that signs with fresh randomness and retries, or that reuses a
key, makes a second signature: the key is traced and the deposit burned.
`otrs` signs deterministically, so a retry is a harmless copy.

## 4. Not provided

Receipt-freeness and coercion resistance; slashing of transferred keys;
an unbiasable beacon; incentives to include fee-less ballots; hiding
per-group tallies; a QROM proof of the primitive; post-quantum accounts;
a network layer; constant-time code.
