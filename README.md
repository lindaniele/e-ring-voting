# e-ring-voting

> Anonymous voting on a permissionless proof-of-work chain where
> **double-voting costs money**. Voters sign ballots with a *traceable*
> ring signature (Fujisaki–Suzuki, PKC 2007): one ballot stays
> anonymous, two ballots by the same key expose that key, and the chain
> burns the deposit that was locked when the key was registered.

This repository is the research artifact for a design Daniele Lin and
Niccolò Pagano sketched in 2021–22 (the original prototype is preserved
under [`legacy/`](legacy/)). It contains a library, a reference chain
that enforces the design as consensus rules, the permissioned baseline
it is compared against, tests, benchmarks and a tech report.
It is **not** production software; see *Security*.

| | |
|---|---|
| **Status** | research artifact, v0.5 |
| **Primitive** | Fujisaki–Suzuki traceable ring signature over Ristretto255, RFC 9380 hash-to-curve (`trs/`) |
| **The design (Architecture B)** | PoW chain with deposits, beacon-assigned groups, key-transfer rounds (`chain/`) |
| **Baseline (Architecture A)** | threshold-signed bulletin board + witness federation, one ring, no deposits (`voting/`) |
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

A *traceable* ring signature (TRS) goes one step further: two
signatures on **different** messages under the same tag reveal the
signer's public key, while one signature stays anonymous in its ring.
The design turns that property into an incentive:

1. **Deposit, forfeited on double-signing.** Registering a voter locks a
   deposit on chain (paid by a *sponsor*, who can be someone other than
   the voter). If the registered key signs two different messages in the
   same round, the chain itself traces it and **burns** the deposit;
   everybody else's deposit is refunded at the close. No authority
   decides; the rule is part of block validation.
2. **Fixed-size groups drawn from a beacon.** Voters do not all share one
   ring. When voting opens, the chain splits the registered keys into
   groups of at least `group_size` members, ordered by a hash keyed with
   the hash of the block before (unknown when registration closed). The
   organiser cannot surround a target with its own keys, and signing and
   verification cost depends on `group_size`, not on the electorate.
3. **Vote *or* move.** In each round a key spends its right once: either
   it casts a ballot, or it signs a *key transfer* to a fresh key that is
   regrouped in the next round. The observer only learns which group a
   transfer came from, so a later ballot hides among every member of all
   the groups its new group was drawn from. Voting and moving in the same
   round is a double-sign.
4. **Proof of possession.** A registration carries a Schnorr proof that
   the voter knows the secret key, so nobody can register keys they do
   not control (and so cannot frame them or dilute a group with them).
5. **Clock-driven lifecycle.** Registration close, group freezing,
   rounds, tally and deposit settlement all happen at block timestamps.
   No transaction closes a poll and no one publishes a tally: every node
   computes it when replaying the chain.

Groups, "vote or move", voter-signed registration paid by a sponsor,
and forfeits distinct from fees come from the 2021–22 design (see
[`legacy/README.md`](legacy/README.md)). There the forfeit was locked
by the poll's manager; making it a per-voter deposit triggered by
tracing is new in this version.

To our knowledge no published system combines a traceable ring
signature, an on-chain deposit forfeited on tracing, beacon-assigned
groups and anonymity-widening key transfers; see *Related work*.

## What the system gives you

* **Anonymity inside the group.** A round-0 ballot reveals nothing about
  which group member produced it (DDH + ROM, [FS07]).
* **One vote per key, with a price.** Two messages by the same key in a
  round are both voided, the key is named, and (for a registered key)
  its deposit is burned. Replaying somebody else's ballot only produces
  a byte-identical copy, which is dropped: it neither changes the tally
  nor frames anyone.
* **No trusted tallier.** The tally is a function of the chain.
* **Bounded per-ballot cost.** Signature size is `36 + 64·|g|` bytes;
  with groups of 8, a ballot is 548 bytes and verifies in about 2.7 ms
  whatever the size of the electorate.

## What it does **not** give you

* Receipt-freeness or coercion resistance.
* Protection against sybils that are paid for: an adversary that
  registers many keys (and locks their deposits) shrinks the honest part
  of each group. `bench/bench_groups.py` quantifies this.
* Unbiasable groups: a miner can withhold a block whose hash it does not
  like. The beacon raises the cost of choosing groups; it does not
  remove it.
* Slashing for keys that arrived by transfer: they are anonymous, so a
  double-sign there voids the messages but there is no deposit to burn.
* Post-quantum security; a production network layer.

See [`paper/threat_model.md`](paper/threat_model.md).

## Install

The library binds `libsodium` (≥ 1.0.18) directly via `cffi`.

```sh
# Debian / Ubuntu
sudo apt install -y libsodium23 python3-cffi python3-pytest \
    python3-hypothesis python3-cryptography

# or via pip in a virtualenv (libsodium must already be installed)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quickstart — the primitive

```python
from trs import keygen, sign, verify, trace

issue = b"poll-2026-05-24"
voters = [keygen() for _ in range(10)]
ring = [v.pk for v in voters]

sig = sign(voters[3].sk, voters[3].pk, issue, b"yes", ring)
assert verify(sig, issue, b"yes", ring)

sig2 = sign(voters[3].sk, voters[3].pk, issue, b"no", ring)
result = trace(issue, ring, b"yes", sig, b"no", sig2)
print(result.status)          # 'double-sign'
print(result.culprit_pk)      # voter #3's public key
```

## Quickstart — the chain

Every CLI call mines one block with an explicit timestamp, so the demo
runs in a second.

```sh
EV="python3 -m chain.cli"
T=1800000000                       # any start time; blocks carry explicit timestamps

# accounts (Ed25519, hold eVotes) and voter keys (TRS, sign ballots)
$EV account-keygen --out miner.json > /dev/null
$EV account-keygen --out alice.json > alice_pk.txt
for i in 0 1 2 3 4 5; do $EV voter-keygen --out v$i.json; done
$EV voter-keygen --out v1-fresh.json

$EV init-chain --chain c.bin --miner miner.json \
    --allocate "$(cat alice_pk.txt):1000" --timestamp $T --difficulty 4

# Alice opens a poll: groups of 3, two rounds (round 0 allows key
# transfers), 10 eVotes locked per registered voter.
EID=$($EV setup-poll --chain c.bin --miner miner.json --timestamp $((T+1)) \
    --creator alice.json --title "Demo" --options yes,no \
    --registration-close $((T+100)) --voting-open $((T+200)) \
    --voting-close $((T+400)) --group-size 3 --rounds 2 --deposit 10)

# Alice sponsors six voters: she pays fee + deposit, each voter proves
# possession of its key.
for i in 0 1 2 3 4 5; do
  $EV register-voter --chain c.bin --miner miner.json --timestamp $((T+10+i)) \
      --sponsor alice.json --election-id $EID --voter v$i.json --handle v$i
done

# Round 0 (the first block past voting_open draws the groups from its
# prev_hash). v1 moves its right to a fresh key instead of voting; v2
# signs twice in the same round and will lose its deposit.
$EV vote     --chain c.bin --miner miner.json --timestamp $((T+200)) --voter v0.json --election-id $EID --choice yes
$EV transfer --chain c.bin --miner miner.json --timestamp $((T+201)) --voter v1.json --new-voter v1-fresh.json --election-id $EID
$EV vote     --chain c.bin --miner miner.json --timestamp $((T+202)) --voter v2.json --election-id $EID --choice yes
$EV vote     --chain c.bin --miner miner.json --timestamp $((T+203)) --voter v2.json --election-id $EID --choice no
$EV vote     --chain c.bin --miner miner.json --timestamp $((T+204)) --voter v3.json --election-id $EID --choice no

# Round 1: the fresh key votes from inside a new group.
$EV vote --chain c.bin --miner miner.json --timestamp $((T+300)) --voter v1-fresh.json --election-id $EID --choice no

# The first block at or after voting_close tallies and settles deposits.
$EV mine-empty --chain c.bin --miner miner.json --timestamp $((T+400))
$EV audit --chain c.bin
```

```
chain: height=14  cum_weight=656  burned=10
poll 7b901e0e881b09dc…  phase=closed  registered=6  groups=[[3, 3], [1]]
  tally: {'no': 2, 'yes': 1}
  key transfers per round: [1, 0]
  double-signer in round 0: bgvZoHnUOsrG4y9ue2OVTVGdMowFqzXANyiCBq4Od2I=
  deposits: 10 burned, 50 refunded
```

`audit` reloads the chain from genesis, which re-checks proof of work at
the prescribed difficulty, every account signature, nonce and balance,
every proof of possession, every ballot and transfer against its group,
and recomputes groups, tally, culprits and deposit settlement. In the
demo the round-1 group has a single key, yet its ballot still hides
among the three members of the round-0 group the transfer came from.

## Baseline — Architecture A (federated, 2-of-3 cohort + 2-of-3 witnesses)

The permissioned point of comparison: a named publisher cohort co-signs
every entry of an append-only board, witnesses co-sign its head, all
voters share one ring and there is no deposit, so a double-vote is
voided but costs nothing.


```sh
NOW=$(date +%s)

# generate a 3-publisher cohort and a 3-witness federation
python3 -m voting.cli cohort-keygen  --size 3 --threshold 2 --out-dir cohort
python3 -m voting.cli witness-keygen --size 3                --out-dir witnesses

# publish the genesis entry — pins the cohort, threshold, and witnesses
python3 -m voting.cli setup-cohort --log log.jsonl \
    --cohort-sks cohort/cohort-0-sk.pem,cohort/cohort-1-sk.pem,cohort/cohort-2-sk.pem \
    --threshold 2 \
    --witness-pks witnesses/witness-0-pk.pem,witnesses/witness-1-pk.pem,witnesses/witness-2-pk.pem \
    --witness-threshold 2 \
    --title "Decentralised Demo" --options "yes,no" \
    --registration-close $((NOW-120)) --voting-open $((NOW-60)) --voting-close $((NOW+86400))

# voters register (any 2 cohort members can co-sign each registration)
for i in 0 1 2; do
  python3 -m voting.cli voter-keygen --out v$i.json
  PK=$(python3 -c "import json; print(json.load(open('v$i.json'))['pk_b64'])")
  python3 -m voting.cli register --log log.jsonl \
      --cohort-sks cohort/cohort-0-sk.pem,cohort/cohort-1-sk.pem \
      --voter-pk "$PK" --handle "v$i"
done
python3 -m voting.cli publish-ring --log log.jsonl \
    --cohort-sks cohort/cohort-0-sk.pem,cohort/cohort-1-sk.pem

# ballots — note the cohort subset can rotate per entry
python3 -m voting.cli vote --log log.jsonl --voter-key v0.json --choice yes \
    --manager-sk cohort/cohort-0-sk.pem \
    --cohort-sks cohort/cohort-0-sk.pem,cohort/cohort-2-sk.pem
python3 -m voting.cli vote --log log.jsonl --voter-key v1.json --choice no \
    --manager-sk cohort/cohort-1-sk.pem \
    --cohort-sks cohort/cohort-1-sk.pem,cohort/cohort-2-sk.pem

python3 -m voting.cli close --log log.jsonl \
    --cohort-sks cohort/cohort-0-sk.pem,cohort/cohort-1-sk.pem

# witnesses independently verify and co-sign the head
python3 -m voting.cli witness-checkpoint --log log.jsonl \
    --sk witnesses/witness-0-sk.pem --witness-index 0
python3 -m voting.cli witness-checkpoint --log log.jsonl \
    --sk witnesses/witness-1-sk.pem --witness-index 1

# anyone with the log can audit — cohort + witness identities live in the genesis entry
python3 -m voting.cli audit --log log.jsonl
```

The `audit` command:
- verifies the chain (indices, prev-hashes, ≥ t cohort signatures, timestamps);
- enforces the state machine (Setup → Registration\* → Ring → Ballot\* → Closed → Tally?);
- TRS-verifies every ballot against the issue, message, and ring;
- verifies all witness checkpoints, surfaces any equivocation evidence;
- recomputes the tally, flags double-voters, refutes any dishonest claimed tally.

It exits non-zero on any failure. For the simple **single-manager** case
(1-of-1 cohort, no witnesses — the v0.2 model), use `manager-keygen` +
`setup` instead of `cohort-keygen` + `setup-cohort`.

## Measurements

Intel i5-10400F, single core, Python 3.12 + libsodium (`bench/`; the CSVs are
regenerated locally and not committed).

| | one ring (N = 1000) | groups of 8 | groups of 32 |
|---|---:|---:|---:|
| signature size | 64 036 B | 548 B | ≈ 2.1 kB |
| verify, per ballot | ≈ 323 ms | ≈ 2.6 ms | ≈ 10.5 ms |
| verify all 1000 ballots | ≈ 5.4 min | ≈ 2.6 s | ≈ 10.5 s |

Anonymity left to an honest voter (N = 1000, half of the voters move in
round 0, Monte Carlo over 20 draws; `bench_groups --anonymity`):

| group size | sybil share | round 0: honest set | round 0: no honest peer | round 1: honest set |
|---:|---:|---:|---:|---:|
| 4 | 0 | 4 | 0 | 16 |
| 4 | 0.5 | 2.5 | 12.6 % | 7.9 |
| 8 | 0.5 | 4.5 | 0.8 % | 30.8 |
| 16 | 0.5 | 8.6 | 0 | 114.5 |

## Repository layout

```
trs/          traceable ring signature (shared by both architectures)
              ├ group.py     Ristretto255 wrapper (libsodium)
              ├ hash.py      RFC 9380 hash-to-curve + hash-to-scalar
              ├ trs.py       KeyGen / Sign / Verify / Trace  [FS07]
              ├ pop.py       Schnorr proof of possession
              └ serialize.py canonical encodings
voting/       election logic + Architecture A (baseline)
              ├ records.py   typed records (setup, registration, ballot, key transfer, …)
              ├ groups.py    beacon-driven group assignment
              ├ tally.py     per-group classification: accepted / replay / double-sign
              ├ log.py       threshold-signed bulletin board
              ├ manager.py / voter.py / witness.py / auditor.py / cli.py
chain/        Architecture B — the design
              ├ block.py     block format + SHA-256 PoW
              ├ transactions.py  coinbase, transfer, setup, registration, ballot, key transfer
              ├ state.py     ledger, deposits, poll lifecycle, consensus rules
              ├ mining.py    miner
              ├ node.py      chain, heaviest-chain fork choice, persistence
              ├ client.py    voter-side transaction builders
              ├ auditor.py   replay-based audit
              └ cli.py       `evote-chain` command line
tests/        pytest suite (165 tests)
bench/        bench_trs (primitive), bench_chain (end to end), bench_groups (cost and anonymity vs group size)
paper/        tech report, threat model
docs/         onboarding notes, ELI5
legacy/       the 2021–22 prototype, kept as it was
```

## Running tests and benchmarks

```sh
python3 -m pytest -q                                   # all 165 tests
python3 -m pytest tests/test_chain.py -v               # the design, end to end
python3 -m bench.bench_trs --sizes 2,4,8,16,32,64
python3 -m bench.bench_chain --voters 50,100,200 --group-size 8
python3 -m bench.bench_groups --cost --voters 1000 --sizes 0,4,8,16,32
python3 -m bench.bench_groups --anonymity --voters 1000 --sizes 4,8,16 --sybils 0,0.25,0.5
```

## From the prototype to this artifact

The 2021–22 prototype implemented the TRS over a 1024-bit DSA group and
a separate PoW node; the voting rules lived in a design document. Reading
the code back, three things stood out (each is reproduced in the tech
report):

* **`h` had a known discrete log.** `H0` mapped into the group as
  `g^k` with `k` derived from public data, so `σ_i = h^{x_i} = pk_i^k`
  could be recomputed for every ring member: signatures were not
  anonymous. Here `H0` is RFC 9380 hash-to-curve.
* **`1/i` was inverted modulo `p` instead of the group order `q`**, so
  only the signer at position 1 produced verifying signatures.
* The chain side had not been wired to the votes (no ledger, no deposit,
  inverted difficulty adjustment, an `await` inside `__init__`).

A 2026 rewrite before this version had kept the primitive but dropped
the design: it replaced the chain with a permissioned bulletin board,
used one ring, no deposits, no groups and no transfers, and attributed
the scheme to Scafuro–Zhang (ESORICS 2021), which is a different,
hash-based one-time construction. That rewrite is kept as Architecture A,
the baseline. Two of its flaws are fixed here: fully linked copies of a
ballot were counted as a double-sign by ring position 1 (so replaying two
honest ballots voided them and framed an innocent voter), and the chain
accepted blocks at any difficulty.

## Related work

* **[FS07]** Fujisaki, Suzuki. *Traceable Ring Signature.* PKC 2007 —
  the scheme implemented in `trs/`.
* **Chirotonia** (Russo et al., 2021, arXiv:2111.02257) — Ethereum
  voting with linkable ring signatures, one ring, no deposits.
* **"Privacy-preserving Casper FFG using traceable ring signatures"**
  (ethresear.ch) — the same "anonymous if honest, slashable if not"
  idea, applied to validators rather than voters.
* **Bresson, Stern, Szydlo** (CRYPTO 2002) — threshold ring
  signatures; **Buddies** (Wolinsky et al., arXiv:1305.5236) —
  intersection attacks and sybils in anonymity groups.
* **Scafuro, Zhang**, *One-time Traceable Ring Signatures*, ESORICS 2021
  — a post-quantum, hash-based relative; not the scheme used here.

## Security

This is research software.

* The TRS is proved secure in [FS07] under DDH in the random-oracle
  model; this **implementation** has not been audited.
* Group arithmetic is libsodium (constant time); the Python glue is not.
* The chain is a reference model: no peer-to-peer layer, no mempool,
  a single-process miner. Fork choice and difficulty are enforced so the
  incentive arguments can be tested, not so it can be deployed.

## Citing

```bibtex
@inproceedings{fujisaki2007trs,
  author    = {Eiichiro Fujisaki and Koutarou Suzuki},
  title     = {Traceable Ring Signature},
  booktitle = {Public Key Cryptography -- PKC 2007},
  series    = {LNCS},
  volume    = {4450},
  pages     = {181--200},
  year      = {2007}
}

@misc{lin2026eringvoting,
  author = {Daniele Lin and Niccol{\`o} Pagano},
  title  = {e-ring-voting: Deposits, Groups and Key Transfers for
            Anonymous Voting with Traceable Ring Signatures},
  year   = {2026},
  howpublished = {\url{https://github.com/NickP005/e-ring-voting}}
}
```

## Open problems

1. **Slashing transferred keys** without breaking their anonymity
   (e.g. a deposit carried along with the transfer).
2. **Unbiasable groups**: a VDF or commit–reveal beacon in place of
   `prev_hash`.
3. **Sybil pricing**: how large the deposit must be for a given group
   size and adversary budget.
4. **Logarithmic-size traceable signatures** to allow larger groups.
5. **Formal models** (ProVerif/Tamarin for the protocol, EasyCrypt for
   the primitive).
6. **Coercion resistance.**
