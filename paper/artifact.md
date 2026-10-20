# Making Double-Voting Expensive: Deposits, Beacon-Drawn Groups and Key Transfers for Anonymous Voting with Traceable Ring Signatures

**Authors.** Daniele Lin, Niccolò Pagano.
**Status.** Research artifact, v0.5. Not for production deployment.
**Primitive.** Eiichiro Fujisaki and Koutarou Suzuki, *Traceable Ring Signature*, PKC 2007.

This is the Markdown companion of [`artifact.tex`](artifact.tex) (PDF:
`artifact.pdf`). It summarises the design, the analysis and the numbers;
the LaTeX version is the reference.

---

## Abstract

Ring-signature voting systems usually rely on *linkable* signatures: a
second ballot from the same key is recognised and discarded, but the voter
stays anonymous, so trying costs nothing. A *traceable* ring signature
(FS07) reveals the public key of anyone who signs two different messages
under the same tag, while a single signature stays anonymous. We describe
and implement a voting design that turns this property into an incentive
on a permissionless proof-of-work chain. Registering a voter locks a
deposit, which the chain burns if that key ever signs twice; voters sign
inside fixed-size groups drawn from a block-hash beacon after
registration closes, so the organiser cannot surround a target with its
own keys; and in every round but the last a voter may, instead of voting,
transfer its right to a fresh key that is regrouped, which widens its
anonymity set. Signing twice in a round, including voting and
transferring, is a double-sign. The design was sketched by the authors in
2021–22; we complete it, state it as consensus rules of a reference
chain, analyse what it does and does not deter, and measure it.

## 1. Research question

Can traceability, an identity revealed only on misbehaviour, be turned
into an enforceable deterrent for voting on a permissionless chain, and
what do the groups this requires cost in anonymity?

## 2. The primitive

FS07 over Ristretto255 (`trs/`). Tag `L = (issue, ring)`, `h = H0(L)`,
`A0 = H1(L, m)`, signer's trace tag `σ_i = h^{x_i}`,
`A1 = (σ_i / A0)^{1/i}` (inverse mod the group order), columns
`σ_j = A0 · A1^j`, and a Fiat–Shamir Σ-OR proof that some `σ_j` has the
same discrete log as `pk_j`. Signatures are `36 + 64n` bytes. Trace: same
message and all columns equal → *linked*; different messages and one
column equal → *that key double-signed*; otherwise *independent*. FS07
prove anonymity under DDH in the ROM and *exculpability* (nobody can be
framed without their key). `H0` must be a real hash to the group: if
`log_g h` is known, every signature names its signer (see §6).

## 3. The design (`chain/`)

| Mechanism | Rule |
|---|---|
| Deposit | `register_voter` (signed by a sponsor) locks `D` per voter in escrow; at the close the deposits of round-0 double-signers are **burned**, all others refunded to their sponsors. |
| Proof of possession | Registration carries a Schnorr proof under `register-v1 ‖ election_id ‖ handle`. |
| Groups | The first block with timestamp ≥ `voting_open` freezes the keys and sorts them by `SHA-256(DST ‖ issue ‖ prev_hash ‖ pk)`; `g = ⌊n/k⌋` groups of `k`..`2k−1` members. |
| Rounds | The voting window is split into `r` rounds; issue `I_ρ` per round. |
| Vote or move | In round ρ a key signs once, under `(I_ρ, group)`: a ballot, or (not in the last round) a key transfer naming a fresh key. Both share the tag, so doing both is a double-sign. Accepted transfers form round ρ+1, regrouped with a fresh beacon. |
| Admission | Per-group tag book: fresh → recorded; second different message → recorded as evidence; copy → invalid; third message → invalid. |
| Close | At the first block ≥ `voting_close` every node computes tally, culprits and settlement. No transaction closes or tallies a poll. |
| Chain | SHA-256 PoW; required difficulty (median-of-11 rule) and heaviest-chain fork choice are consensus rules; ballots and transfers carry no sender and no fee. |

## 4. Analysis (highlights)

- **Double-voting never adds a vote** (both messages void), including
  vote-then-move. It **costs** `D` and exposes the key; the sponsor has a
  reason to vet voters, and sharing a key with a buyer is risky for both.
- **No framing**: copies are linked, never double-signs, and are refused.
- **The deposit prices misbehaviour, not registration**: behaving sybils
  get it back. Sybils are priced by fees and accountable sponsors.
- **Beacon bias**: the miner of the beacon block can discard blocks;
  isolating a given voter takes about `1/p` discarded blocks (`p ≈ 0.8 %`
  with `k = 8` and half the keys adversarial).
- **Transfers** never shrink the anonymity set (for a non-counting
  observer): a round-ρ+1 ballot hides among all origin groups of its
  new group.
- **Per-group tallies are public**, so unanimous small groups leak.
- **Not addressed**: slashing transferred keys, censorship of fee-less
  ballots, coercion, hash-power rental.

## 5. Evaluation

Intel i5-10400F, one core, Python 3.12, libsodium.

**Primitive** (`bench_trs`): sign/verify ≈ 0.33 ms per ring member,
trace ≈ 0.16 ms per member; 548 B at n = 8, 4 132 B at n = 64.

**Cost vs group size**, N = 1000 (`bench_groups --cost`):

| k | groups | mean signature | all ballots | verify all |
|---:|---:|---:|---:|---:|
| one ring | 1 | 64 036 B | 64.0 MB | 323 s |
| 4 | 250 | 292 B | 0.29 MB | 1.4 s |
| 8 | 125 | 548 B | 0.55 MB | 2.6 s |
| 16 | 62 | 1 069 B | 1.07 MB | 5.3 s |
| 32 | 31 | 2 101 B | 2.10 MB | 10.5 s |

**End to end on the chain** at difficulty 8 (`bench_chain`): with one
ring the ballot cost grows from 8 ms (N = 10) to 38 ms (N = 50) per
voter; with `k = 8` it stays at ≈ 7 ms for N = 50…200, audit grows
linearly (818 ms and 458 KB at N = 200), settlement takes ≈ 2 ms.

**Anonymity** (`bench_groups --anonymity`, N = 1000, half of the honest
voters move):

| k | sybil share | honest set r0 | isolated r0 | honest set r1 |
|---:|---:|---:|---:|---:|
| 4 | 0 | 4.0 | 0 | 16.0 |
| 4 | 0.5 | 2.5 | 12.6 % | 7.9 |
| 8 | 0.5 | 4.5 | 0.8 % | 30.8 |
| 16 | 0.5 | 8.6 | 0 | 114.5 |

## 6. From the prototype

Elements of the 2021–22 design: traceable ring signature, group size in
the poll announcement, vote (`$`) or transfer (`*`) "to another group with
another key", voter-signed registration paid by another address,
forfeits distinct from fees. In the 2022 procedure the forfeit is locked
by the manager; the per-voter deposit burned on tracing is ours.

Bugs found in the prototype, each reproduced:

- `H0` mapped to `g^t` with `t` computable from public data, so
  `pk_j^t = h^{x_j}` identifies the signer of every signature.
- `1/i` was inverted modulo `p` instead of `q`: only position 1 verified.
- Mining and validation adjusted difficulty in opposite directions;
  an `await` inside `__init__`; no connection between chain and votes.

The 2026 rewrite before this version dropped deposits, groups and
transfers, used one ring, attributed the scheme to Scafuro–Zhang
(ESORICS 2021, a different hash-based construction), blamed ring
position 1 for replayed copies, and accepted blocks at any difficulty.
It survives, fixed, as the permissioned baseline (Architecture A,
`voting/`).

## 7. Related work

Chirotonia (Russo et al., IEEE Blockchain 2021): linkable ring signatures,
one ring, no penalty. *Privacy-preserving Casper FFG using traceable ring
signatures* (ethresear.ch): slashable anonymity for validators. Buddies
(Wolinsky, Syta, Ford, CCS 2013): sybils and intersection attacks in
anonymity groups. Scafuro–Zhang (ESORICS 2021): post-quantum one-time
traceable ring signatures. Fujisaki (CT-RSA 2011): sub-linear traceable
ring signatures. To our knowledge no published system combines a
traceable ring signature, a deposit burned on tracing, beacon-assigned
voter groups and anonymity-widening transfers.

## 8. Reproducibility

```sh
python3 -m pytest -q                                      # 165 tests
python3 -m bench.bench_trs --sizes 2,4,8,16,32,64
python3 -m bench.bench_groups --cost --voters 1000 --sizes 0,4,8,16,32,64
python3 -m bench.bench_groups --anonymity --voters 1000 --sizes 4,8,16 --sybils 0,0.25,0.5 --trials 20
python3 -m bench.bench_chain --voters 10,25,50 --difficulty 8
python3 -m bench.bench_chain --voters 50,100,200 --group-size 8 --difficulty 8
```
