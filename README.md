# e-ring-voting

> Anonymous voting on a permissionless proof-of-work chain where
> **double-voting costs money**. Every voter signs with a *one-time*
> traceable ring signature (Scafuro–Zhang, ESORICS 2021): a key used once
> stays anonymous in its group, a key used twice is exposed, and the chain
> burns the deposit that was locked when the key was registered. The
> signature uses nothing but a hash function.

This repository is the research artifact for a design Daniele Lin and
Niccolò Pagano sketched in 2021–22 (the original prototype is preserved
under [`legacy/`](legacy/)). It contains an implementation of the
signature scheme, a reference chain that enforces the design as
consensus rules, tests, benchmarks and a tech report.
It is **not** production software; see *Security*.

| | |
|---|---|
| **Status** | research artifact, v1.0 |
| **Primitive** | Scafuro–Zhang one-time traceable ring signature, SHAKE256, λ = 128 or 256 (`otrs/`) |
| **The design** | PoW chain with deposits, beacon-assigned groups, key-transfer rounds (`chain/`, `voting/`) |
| **Comparison scheme** | Fujisaki–Suzuki traceable ring signature over Ristretto255 (`fs07/`), the scheme of the 2021–22 code |
| **Tech report** | [`paper/artifact.tex`](paper/artifact.tex) (PDF in `paper/artifact.pdf`), [`paper/artifact.md`](paper/artifact.md) |
| **Threat model** | [`paper/threat_model.md`](paper/threat_model.md) |
| **Notes** | [`docs/notes.tex`](docs/notes.tex) (onboarding), [`docs/eli5.tex`](docs/eli5.tex) (no maths) |
| **License** | MIT (the code under `legacy/` keeps its original license) |
| **Authors** | Daniele Lin, Niccolò Pagano |

## The idea

Most ring-signature voting systems use *linkable* signatures: two
ballots by the same key are recognisably linked, so the second one can
be thrown away, but nobody learns who cast them. Throwing a vote away
punishes nobody, so trying costs nothing.

A *traceable* ring signature goes further: a second signature by the
same key reveals the key. The *one-time* variant of Scafuro and Zhang
[SZ21] makes the rule absolute: **a key may sign once, ever**; any second,
distinct signature (even of the same message) exposes it. That is exactly
the rule of a poll, one voter, one ballot, and it is why the 2021–22
design wanted a one-time scheme. The design turns the exposure into an
incentive:

1. **One-time keys.** A voter makes a key for one poll. Signing is a
   handful of hash evaluations: keys are Naor bit-commitment keys in
   equivocal mode, a signature reveals one seed of each of the signer's
   λ seed pairs, and a second signature reveals the other seed of some
   pair, which names the key. No discrete logarithms, so nothing a
   quantum computer can solve to de-anonymise old ballots.
2. **Deposit, forfeited on a second use.** Registering a voter locks a
   deposit on chain, paid by a *sponsor* (the voter, the organiser or
   anyone else). If the registered key is traced, the chain **burns**
   the deposit; everybody else's is refunded at the close. No authority
   decides; the rule is part of block validation.
3. **Fixed-size groups drawn from a beacon.** Voters do not share one
   ring. When voting opens, the chain splits the registered keys into
   groups of `group_size`..`2·group_size − 1` members, ordered by a hash
   keyed with the hash of the block before (unknown when registration
   closed). The organiser cannot surround a target with its own keys,
   and a ballot's size and verification time depend on `group_size`, not
   on the electorate.
4. **Vote *or* move.** In each round a key spends its one use: either it
   casts a ballot, or it signs a *key transfer* naming a fresh key that is
   regrouped in the next round. This is the 2022 "transfer to another
   group with another key", and it is also how [SZ21] suggest using
   one-time keys on a chain. A later ballot hides among every member of
   all the groups its new group was drawn from. Voting and moving is two
   uses.
5. **Keys labelled with their use.** Each key carries a public label
   that binds it to one poll and one registration handle (or one
   transfer round). The chain refuses any other use, so a key cannot be
   registered twice, in another poll, or under someone else's handle.
   This replaces the voter-signed registration of 2022, which a one-time
   key cannot give without spending its single signature.
6. **Clock-driven lifecycle.** Registration close, group freezing,
   rounds, tally and deposit settlement all happen at block timestamps.
   No transaction closes a poll and no one publishes a tally: every node
   computes it when replaying the chain.

Groups, "vote or move", sponsored registration, forfeits distinct from
fees and the choice of a one-time traceable scheme come from the 2021–22
design (see [`legacy/README.md`](legacy/README.md)). Two things are new
here: the forfeit is a deposit *per voter*, triggered by the trace (in
2022 it was locked by the poll's manager), and the labels.

## Why the one-time scheme

The 2021–22 code implemented Fujisaki–Suzuki [FS07], whose traceability
is per *tag* and whose keys can be reused. Both schemes are implemented
here and measured on the same machine (`bench/bench_primitives.py`,
λ = 128 for SZ21):

| | FS07 (`fs07/`) | SZ21 (`otrs/`), this design |
|---|---|---|
| Assumption | DDH in a prime-order group + ROM | a hash function as a random oracle |
| Quantum computer | recovers every secret key, so it de-anonymises **every past ballot** | none known; generic speed-up only (Grover) |
| What a second signature does | different message: exposes the key; same message: only *linked* | anything distinct: exposes the key |
| Key reuse | across tags | never |
| Public key | 32 B | 6 177 B |
| Signature, group of 8 | 548 B | 16 517 B |
| Sign / verify, group of 8 | 2.6 / 2.6 ms | 1.4 / 1.3 ms |
| Verify, per member | 0.32 ms | 0.16 ms |

Ballots must stay secret for decades; their validity only matters until
the poll closes. That asymmetry is the reason to pay 30× in signature
size: a public chain is a permanent archive, and FS07 ballots on it are
readable by whoever first has a large quantum computer. With groups of
8, the cost is 16.5 KB per ballot.

## What we found on the way

* **A gap in Fig. 1 of [SZ21].** A public key row equal to zero makes the
  commitment `G(r) ⊕ x·pk` independent of the bit, so it opens either way
  with the same seed. A key made of zero rows signs any number of times,
  with fresh seeds each time, and is never traced; the verification of
  Fig. 1 accepts these signatures. The traceability argument implicitly
  assumes non-zero rows. The fix is one check, applied to every key that
  enters a ring here (`tests/test_otrs.py::TestZeroRow` runs the attack).
* **Deterministic signing is not optional.** A one-time key that
  re-signs the *same* ballot with fresh randomness is traced. A wallet
  that retries a broadcast would cost its user the deposit. Here the
  signing randomness is derived from the secret and the input, so a retry
  produces a byte-identical copy, which the chain refuses harmlessly.
* **Trace from openings.** Verification already computes `G(r)` for every
  seed; keeping those values makes tracing a new ballot against a group's
  recorded ballots a big-integer XOR per ballot (0.04 ms for a group of
  8 instead of 2 ms).

## What the system gives you

* **Anonymity inside the group** for a key used once (one-time anonymity
  of [SZ21], classical random-oracle model), with no assumption a quantum
  computer is known to break.
* **One vote per key, with a price.** All messages of a traced key are
  void, the key is named together with the handle it was registered
  under, and its deposit is burned. Replaying somebody else's ballot only
  produces a byte-identical copy, which is refused: it changes nothing and
  frames nobody (one-time exculpability).
* **No trusted tallier.** The tally is a function of the chain.
* **Bounded per-ballot cost.** A ballot is `5 + 2064·|g|` bytes at
  λ = 128 and verifies in about `0.16·|g|` ms, whatever the electorate.

## What it does **not** give you

* Receipt-freeness or coercion resistance.
* Protection against sybils that are paid for: an adversary that
  registers many keys (and locks their deposits) shrinks the honest part
  of each group. `bench/bench_groups.py` quantifies this.
* Unbiasable groups: a miner can withhold a block whose hash it does not
  like. The beacon raises the cost of choosing groups; it does not
  remove it.
* Slashing for keys that arrived by transfer: they are anonymous, so a
  second use voids their messages but there is no deposit to burn.
* Post-quantum *accounts*: sponsors and creators sign with Ed25519. That
  only protects the ledger during the poll; ballot anonymity does not
  depend on it.
* A security proof in the quantum random-oracle model (open for [SZ21]
  too), and a production network layer.

See [`paper/threat_model.md`](paper/threat_model.md).

## Install

The design needs only Python ≥ 3.10 and `cryptography` (for Ed25519
accounts). The FS07 comparison scheme also needs `libsodium` and `cffi`;
its tests are skipped when they are missing.

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # dev = pytest, hypothesis, cffi
sudo apt install -y libsodium23    # only for fs07/ (Debian / Ubuntu)
```

## Quickstart — the primitive

```python
from otrs import Ring, keygen

voters = [keygen() for _ in range(8)]
ring = Ring([v.pk for v in voters])

sig = ring.sign(voters[3], b"yes", b"poll-7")
assert ring.verify(sig, b"yes", b"poll-7")
assert ring.sign(voters[3], b"yes", b"poll-7") == sig   # deterministic

second = ring.sign(voters[3], b"no", b"poll-7")         # a second use
print(ring.trace(sig, second).culprits)                 # (3,)

again = ring.sign(voters[3], b"yes", b"poll-7", randomized=True)
print(ring.trace(sig, again).culprits)                  # (3,): same ballot, still exposed
```

## Quickstart — the chain

Every CLI call mines one block with an explicit timestamp, so the demo
runs in a couple of seconds.

```sh
EV="python3 -m chain.cli"
T=1800000000                       # any start time; blocks carry explicit timestamps
M="--chain c.bin --miner miner.json"

# accounts: Ed25519, they hold eVotes and pay fees and deposits
$EV account-keygen --out miner.json > /dev/null
$EV account-keygen --out alice.json > alice_pk.txt
$EV init-chain --chain c.bin --miner miner.json \
    --allocate "$(cat alice_pk.txt):1000" --timestamp $T --difficulty 4

# Alice opens a poll: groups of 3, two rounds (round 0 allows key
# transfers), 10 eVotes locked per registered voter.
EID=$($EV setup-poll $M --timestamp $((T+1)) \
    --creator alice.json --title "Demo" --options yes,no \
    --registration-close $((T+100)) --voting-open $((T+200)) \
    --voting-close $((T+400)) --group-size 3 --rounds 2 --deposit 10)

# Each voter makes a one-time key for this poll and its handle; Alice
# sponsors the registration (fee + deposit).
for i in 0 1 2 3 4 5; do
  $EV voter-keygen --election-id $EID --handle v$i --out v$i.json > /dev/null
  $EV register-voter $M --timestamp $((T+10+i)) \
      --sponsor alice.json --election-id $EID --voter v$i.json
done

# Round 0 (the first block past voting_open draws the groups from its
# prev_hash). v1 moves its right to a fresh key instead of voting; v2
# uses its key twice and will lose its deposit.
$EV vote     $M --timestamp $((T+200)) --voter v0.json --election-id $EID --choice yes
$EV transfer $M --timestamp $((T+201)) --voter v1.json --election-id $EID --out v1-next.json
$EV vote     $M --timestamp $((T+202)) --voter v2.json --election-id $EID --choice yes
$EV vote     $M --timestamp $((T+203)) --voter v2.json --election-id $EID --choice no
$EV vote     $M --timestamp $((T+204)) --voter v3.json --election-id $EID --choice no

# Round 1: the fresh key votes from inside a new group.
$EV vote $M --timestamp $((T+300)) --voter v1-next.json --election-id $EID --choice no

# The first block at or after voting_close tallies and settles deposits.
$EV mine-empty $M --timestamp $((T+400))
$EV audit --chain c.bin
```

```
chain: height=14  cum_weight=656  burned=10
poll 136b50a3f69d8247…  phase=closed  registered=6  groups=[[3, 3], [1]]
  tally: {'no': 2, 'yes': 1}
  key transfers per round: [1, 0]
  key used twice in round 0: handle 'v2' (key b47b7ecb9d398b36…)
  deposits: 10 burned, 50 refunded
```

(The poll id and key fingerprint change with the random accounts and
keys.) `audit` reloads the chain from genesis, which re-checks proof of
work at the prescribed difficulty, every account signature, nonce and
balance, every key label, every ballot and transfer against its group,
and recomputes groups, tally, culprits and deposit settlement. In the
demo the round-1 group has a single key, yet its ballot still hides
among the three members of the round-0 group the transfer came from.

## Measurements

Intel i5-10400F, one core, Python 3.12 (`bench/`, CSVs in `bench/`).

**Cost against group size**, N = 1000 voters (`bench_groups --cost`):

| group size | mean ballot | all ballots | verify all ballots | FS07, all ballots | FS07, verify all |
|---:|---:|---:|---:|---:|---:|
| one ring | 2.06 MB | 2.06 GB | 157 s | 64 MB | 317 s |
| 4 | 8.3 KB | 8.3 MB | 0.6 s | 0.29 MB | 1.4 s |
| 8 | 16.5 KB | 16.5 MB | 1.2 s | 0.55 MB | 2.7 s |
| 16 | 33.3 KB | 33.3 MB | 2.5 s | 1.07 MB | 5.3 s |
| 32 | 66.6 KB | 66.6 MB | 5.0 s | 2.10 MB | 10.4 s |

Registered keys add 6.2 MB (λ = 128) for 1000 voters. With one-time
signatures **groups are not an optimisation but a precondition**: one
ring of 1000 makes every ballot 2 MB.

**End to end on the chain** (`bench_chain`, difficulty 8): with groups of
8 a ballot costs ≈ 4.4 ms of client + validation time for N = 50, 100 and
200 alike; with one ring it grows from 4.9 ms (N = 10) to 26 ms (N = 50).
Replaying and auditing a 200-voter poll takes 0.46 s.

**Anonymity left to an honest voter** (N = 1000, half of the honest
voters move in round 0, 20 draws; `bench_groups --anonymity`; independent
of the signature scheme):

| group size | sybil share | round 0: honest set | round 0: no honest peer | round 1: honest set |
|---:|---:|---:|---:|---:|
| 4 | 0 | 4 | 0 | 16.0 |
| 4 | 0.5 | 2.5 | 12.6 % | 7.9 |
| 8 | 0.5 | 4.5 | 0.8 % | 30.8 |
| 16 | 0.5 | 8.6 | 0 | 114.5 |

## Repository layout

```
otrs/         one-time traceable ring signature [SZ21] — the primitive
              ├ primitives.py  parameter sets, the oracles G and H (SHAKE256), derivations
              └ scheme.py      keys, Ring, sign / verify / trace, encodings
voting/       election logic
              ├ records.py   poll records, key labels
              ├ groups.py    beacon-driven group assignment, round tags
              └ tally.py     per-group classification: counted / void / culprits
chain/        the design as consensus rules
              ├ block.py     block format + SHA-256 PoW
              ├ transactions.py  coinbase, payment, setup, registration, ballot, key transfer
              ├ state.py     ledger, deposits, poll lifecycle, validation
              ├ mining.py    miner
              ├ node.py      chain, heaviest-chain fork choice, persistence
              ├ client.py    key making and voter-side transaction builders
              ├ auditor.py   replay-based audit
              └ cli.py       `evote-chain` command line
fs07/         Fujisaki–Suzuki traceable ring signature over Ristretto255 (comparison)
tests/        pytest suite
bench/        bench_primitives (SZ21 vs FS07), bench_groups (cost and anonymity), bench_chain
paper/        tech report, threat model
docs/         onboarding notes, ELI5, references/ (text of [SZ21])
legacy/       the 2021–22 prototype, kept as it was
```

## Running tests and benchmarks

```sh
python3 -m pytest -q                                   # all tests
python3 -m pytest tests/test_otrs.py -v                # the primitive, incl. attacks
python3 -m pytest tests/test_chain.py -v               # the design, end to end
python3 -m bench.bench_primitives --sizes 2,4,8,16,32,64
python3 -m bench.bench_groups --cost --voters 1000 --sizes 0,4,8,16,32
python3 -m bench.bench_groups --cost --scheme fs07 --voters 1000 --sizes 0,4,8,16,32
python3 -m bench.bench_groups --anonymity --voters 1000 --sizes 4,8,16 --sybils 0,0.25,0.5
python3 -m bench.bench_chain --voters 50,100,200 --group-size 8
```

## From the prototype to this artifact

The 2021–22 prototype implemented FS07 over a 1024-bit DSA group and a
separate PoW node; the voting rules lived in a design document. Reading
the code back, three things stood out (each is reproduced in the tech
report):

* **`h` had a known discrete log.** `H0` mapped into the group as
  `g^k` with `k` derived from public data, so `σ_i = h^{x_i} = pk_i^k`
  could be recomputed for every ring member: signatures were not
  anonymous.
* **`1/i` was inverted modulo `p` instead of the group order `q`**, so
  only the signer at position 1 produced verifying signatures.
* The chain side had not been wired to the votes (no ledger, no deposit,
  inverted difficulty adjustment, an `await` inside `__init__`).

The fixed FS07 lives on in `fs07/` as the comparison scheme. The design
now signs with the scheme it was meant to use from the start.

## Related work

* **[SZ21]** Scafuro, Zhang. *One-time Traceable Ring Signatures.*
  ESORICS 2021, ePrint 2021/1054 — the scheme in `otrs/` (text copy in
  `docs/references/`).
* **[FS07]** Fujisaki, Suzuki. *Traceable Ring Signature.* PKC 2007 —
  the scheme in `fs07/` and in the 2021–22 code.
* **Branco, Mateus** (PQCrypto 2019) — post-quantum traceable ring
  signatures from codes, with much larger signatures.
* **Chirotonia** (Russo et al., 2021, arXiv:2111.02257) — Ethereum
  voting with linkable ring signatures, one ring, no deposits.
* **"Privacy-preserving Casper FFG using traceable ring signatures"**
  (ethresear.ch) — "anonymous if honest, slashable if not", applied to
  validators rather than voters.
* **Buddies** (Wolinsky et al., arXiv:1305.5236) — intersection attacks
  and sybils in anonymity groups.

## Security

This is research software.

* [SZ21] prove one-time anonymity, traceability and exculpability in the
  classical random-oracle model, for keys whose rows are non-zero (see
  above). This **implementation** has not been audited; it is pure Python
  and not constant-time.
* Every honest key must sign once. The chain enforces one use per key
  and labels keys with their use; a wallet must sign deterministically
  and never reuse a key across polls.
* The chain is a reference model: no peer-to-peer layer, no mempool,
  a single-process miner. Fork choice and difficulty are enforced so the
  incentive arguments can be tested, not so it can be deployed.

## Citing

```bibtex
@inproceedings{scafuro2021otrs,
  author    = {Alessandra Scafuro and Bihan Zhang},
  title     = {One-time Traceable Ring Signatures},
  booktitle = {Computer Security -- ESORICS 2021},
  series    = {LNCS},
  year      = {2021},
  note      = {IACR ePrint 2021/1054}
}

@misc{lin2026eringvoting,
  author = {Daniele Lin and Niccol{\`o} Pagano},
  title  = {e-ring-voting: Deposits, Groups and Key Transfers for
            Anonymous Voting with One-time Traceable Ring Signatures},
  year   = {2026},
  howpublished = {\url{https://github.com/lindaniele/e-ring-voting}}
}
```

## Open problems

1. **Slashing transferred keys** without breaking their anonymity.
2. **Unbiasable groups**: a VDF or commit–reveal beacon in place of
   `prev_hash`.
3. **Sybil pricing**: how large the deposit must be for a given group
   size and adversary budget.
4. **Shorter one-time signatures**: size is `N·λ²` bits; a sub-linear
   hash-based traceable scheme would allow larger groups.
5. **Security in the quantum random-oracle model**, and formal models of
   the protocol (ProVerif/Tamarin).
6. **Coercion resistance.**
