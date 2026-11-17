# One Key, One Use, or Lose the Deposit: Anonymous Voting on a Proof-of-Work Chain with One-time Traceable Ring Signatures

**Authors.** Daniele Lin, Niccolò Pagano.
**Status.** Research artifact, v1.0. Not for production deployment.
**Primitive.** Alessandra Scafuro and Bihan Zhang, *One-time Traceable
Ring Signatures*, ESORICS 2021 (ePrint 2021/1054).

This is the Markdown companion of [`artifact.tex`](artifact.tex) (PDF:
`artifact.pdf`). It summarises the design, the analysis and the numbers;
the LaTeX version is the reference.

---

## Abstract

Ring-signature voting systems usually rely on *linkable* signatures: a
second ballot from the same key is recognised and discarded, but the voter
stays anonymous, so trying costs nothing. The one-time traceable ring
signature of Scafuro and Zhang is built from a hash function alone and
enforces exactly the rule of a poll: a key that signs once is anonymous in
its ring, and any second, distinct signature by the key, even of the same
message, exposes it. We turn this exposure into an incentive on a
permissionless proof-of-work chain: registering a voter locks a deposit
that the chain burns if the key is traced; voters sign inside fixed-size
groups drawn from a block-hash beacon after registration closes; and a
voter may spend its key's one use on moving its right to a fresh key in a
new group, which widens its anonymity set. Keys carry a public label that
binds them to their single use. We found that Fig. 1 of the scheme accepts
keys with zero rows, which sign any number of times untraced; one check
fixes it. With groups of 8 a ballot is 16.5 kB and verifies in 1.3 ms
whatever the electorate. Against the Fujisaki–Suzuki scheme of the
authors' 2021–22 prototype, verification is twice as fast, signatures are
30 times larger, and ballots do not become readable to a future quantum
computer.

## 1. Research question

Can a one-time traceable ring signature, an identity revealed only on a
second use, be turned into an enforceable deterrent for voting on a
permissionless chain, and what do the groups it requires cost?

## 2. The primitive (`otrs/`)

`G : {0,1}^λ → {0,1}^{3λ}` and `H : {0,1}^* → {0,1}^λ` are random
oracles (SHAKE256 with domain separation), λ = 128 or 256.

* **KeyGen.** `2λ` seeds `s⁰_j, s¹_j`; public rows
  `pk_j = G(s⁰_j) ⊕ G(s¹_j)`, `j = 1..λ`: equivocal Naor commitment keys.
  6 177 B per key at λ = 128 (with header and label).
* **Sign** at position `l`. For `i ≠ l` pick `x_i` and commit bitwise,
  `c_ij = G(r_ij) ⊕ x_i[j]·pk_ij`; for the signer `c_lj = G(s⁰_lj)`.
  Target `z = H(ctx, ring, m, c)`, `x_l = z ⊕ ⊕_{i≠l} x_i`, open
  `r_lj = s^{x_l[j]}_lj`. Output all `x_i, r_ij`: `N·λ(λ+1)` bits.
* **Verify.** Recompute every `c_ij`, then `z`, check `⊕ x_i = z`.
* **Trace.** Two signatures trace member `i` if
  `G(α_ij) ⊕ G(β_ij) = pk_ij` for some row: both seeds of a row are out.
  Two signatures by one key have different targets, so this happens with
  probability `1 − 2^{-λ}`, even on the same message.
* **Security** [SZ21], classical ROM: one-time anonymity, public
  traceability (`N` keys cannot make `N + 1` untraced signatures), one-time
  exculpability.

**Our additions.** (1) Rows must be non-zero (below). (2) A context string
(poll and round) in `H`, and a `2λ`-bit ring digest. (3) A 32-byte public
label in every key. (4) Deterministic signing from the master secret and
the full input: a key that re-signs the same ballot with fresh randomness
is traced, so a retry must produce a copy. (5) Trace returns every culprit
of a coalition. (6) Trace from the openings cached at verification: one
big-integer XOR (0.04 ms for `N = 8` instead of 2 ms).

**The zero-row gap.** With `pk_j = 0` the commitment `G(r) ⊕ x·pk_j` is
`G(r)` for both bits. A key of zero rows (an honest output of KeyGen with
`s⁰_j = s¹_j`) signs any number of times with fresh seeds and is never
traced; Fig. 1 checks that keys are distinct and well formed, not this.
Every key that enters a ring here is checked
(`tests/test_otrs.py::TestZeroRow` runs the attack). For non-zero rows,
evading the trace twice on one row needs two seed pairs with the same XOR:
a 4-XOR problem on `3λ` bits, about `2^λ` by Wagner.

## 3. The design (`chain/`, `voting/`)

* **Poll parameters**, fixed by the creator: schedule, group size `k`,
  rounds `r`, deposit `D`, λ.
* **Registration**, signed and paid by a *sponsor*: a one-time key whose
  label is `SHA-256("e-ring-voting/register-v1" ‖ election_id ‖ len ‖
  handle)`; fee to the miner, `D` to escrow. The label replaces the
  voter-signed registration of 2022, which a one-time key cannot give
  without spending its signature.
* **Groups.** The first block past `voting_open` freezes the keys and
  orders their fingerprints by `SHA-256(DST ‖ issue ‖ prev_hash ‖ fp)`;
  groups of `k`..`2k−1`, each sorted, which is the ring order.
* **Vote or move.** In round `ρ` a key spends its one use on a ballot
  (`ballot-v1 ‖ choice`) or, in all rounds but the last, a key transfer
  (`key-transfer-v1 ‖ pk'`) to a fresh key labelled for round `ρ + 1`.
  Transfer targets are regrouped with a fresh beacon. Both uses are
  signatures, so doing both is traced.
* **Admission** per group: replay (identical copy, refused), fresh,
  evidence (traces a new key), saturated (traces only exposed keys,
  refused), exhausted (an `(N+1)`-th untraced signature, a guard).
* **Close.** At `voting_close` every node computes the tally, the culprits
  with their handles, burns round-0 culprits' deposits and refunds the
  rest. No transaction publishes a result.
* **Chain.** SHA-256 PoW, median-of-11 difficulty enforced at validation,
  heaviest chain wins, atomic block application.

## 4. Analysis (see [`threat_model.md`](threat_model.md))

* **Deterrence.** Any second use voids every message involved and names
  the key; a registered key's sponsor loses `D`. `t` colluding keys get at
  most `t` untraced ballots per group and choose which key is exposed, not
  whether.
* **No framing.** A key used once is never traced; copies are identical
  and refused.
* **Beacon bias.** Isolating an honest voter takes about `1/p` discarded
  blocks; with half the keys adversarial, `p ≈ 0.8 %` at `k = 8`,
  `13 %` at `k = 4`.
* **Sybils** shrink the honest part of each group and cannot be detected;
  the deposit prices misbehaviour, not registration.
* **Transfers** never shrink the anonymity set and multiply it by about
  the group size, for an observer that does not count.
* **Leakage.** Per-group tallies are public.
* **Quantum.** Ballot anonymity rests on inverting `G` (`2^{λ/2}` with
  Grover); FS07 ballots on a public chain become readable once discrete
  logarithms are cheap. Accounts (Ed25519) only matter during a poll. The
  proofs of [SZ21] are classical-ROM.
* **Limits.** Transferred keys cannot be slashed; signatures are
  `Θ(Nλ²)` bits; no coercion resistance; economic chain security.

## 5. Evaluation (i5-10400F, one core, Python 3.12)

| n | SZ21-128 sign | verify | trace (cached) | signature | FS07 verify | FS07 signature |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 0.42 ms | 0.32 ms | 0.010 ms | 4 133 B | 0.69 ms | 164 B |
| 8 | 1.42 ms | 1.27 ms | 0.041 ms | 16 517 B | 2.64 ms | 548 B |
| 64 | 10.6 ms | 9.89 ms | 0.320 ms | 132 101 B | 20.3 ms | 4 132 B |

At λ = 256 and n = 8: sign 3.2 ms, verify 2.8 ms, 65 797 B. At n = 1024,
λ = 128: verify 169 ms, 2.1 MB.

**N = 1000 voters:**

| k | mean ballot | all ballots | verify all | FS07 all ballots | FS07 verify all |
|---:|---:|---:|---:|---:|---:|
| one ring | 2.06 MB | 2 064 MB | 157 s | 64 MB | 317 s |
| 8 | 16.5 kB | 16.5 MB | 1.2 s | 0.55 MB | 2.7 s |
| 16 | 33.3 kB | 33.3 MB | 2.5 s | 1.07 MB | 5.3 s |
| 32 | 66.6 kB | 66.6 MB | 5.0 s | 2.10 MB | 10.4 s |

Keys add 6.2 MB. **Chain, end to end** (difficulty 8): with `k = 8`,
4.4 ms per ballot at N = 50, 100, 200; audit of 200 voters 0.46 s, chain
8.1 MB. With one ring, 4.9 ms (N = 10) to 26 ms (N = 50) per ballot.

**Anonymity** (N = 1000, half the honest voters move):

| k | sybils | round 0 honest set | isolated | round 1 honest set |
|---:|---:|---:|---:|---:|
| 4 | 0.5 | 2.5 | 12.6 % | 7.9 |
| 8 | 0.5 | 4.5 | 0.8 % | 30.8 |
| 16 | 0.5 | 8.6 | 0 | 114.5 |

## 6. From the prototype

The 2021–22 design meant to use a one-time traceable ring signature, and
Pagano implemented [SZ21] in C in 2022–23 (`crypto-otrs`). The prototype in
`legacy/` implemented FS07 instead, with a hash into the group of known
discrete logarithm (no anonymity) and `1/i` inverted modulo `p` instead of
`q` (only position 1 verified). The fixed FS07 lives in `fs07/` as the
comparison. Groups, vote-or-move, sponsored registration, forfeits and the
PoW chain come from the 2021–22 design; per-voter deposits triggered by the
trace and key labels are new.

## 7. Open problems

Slashing transferred keys; an unbiasable beacon; pricing deposits and
fees; hiding per-group tallies; sub-linear hash-based one-time traceable
signatures; a QROM proof of [SZ21]; formal protocol models; coercion
resistance.
