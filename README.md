# e-ring-voting

> A verifiable anonymous voting artifact built on **one-time traceable
> ring signatures** (Scafuro & Zhang, ESORICS 2021), instantiated over
> Ristretto255 with RFC 9380 hash-to-curve, with **two interchangeable
> system-layer architectures** sharing the same cryptographic primitive
> and record schema.

This repository is a research artifact: an auditable Python library plus
a tech-report-style write-up describing the cryptography, both system
architectures, the threat model, the test suite, and a comparison. It
is **not** production-ready; see *Security* below.

| | |
|---|---|
| **Status** | research artifact, v0.4 (two architectures) |
| **Cryptographic core** | Scafuro–Zhang OTRS over Ristretto255 (`otrs/`) |
| **Architecture A** | threshold-signed bulletin board + witness federation (`voting/`) |
| **Architecture B** | proof-of-work chain with eVote ledger and typed transactions (`chain/`) |
| **Tech report** | [`paper/artifact.md`](paper/artifact.md), [`paper/artifact.tex`](paper/artifact.tex) (16-page PDF in `paper/artifact.pdf`) |
| **Threat model** | [`paper/threat_model.md`](paper/threat_model.md) |
| **Onboarding notes** | [`docs/notes.tex`](docs/notes.tex) — 25-page colleague-onboarding walk-through (PDF in `docs/notes.pdf`) |
| **ELI5 explainer** | [`docs/eli5.tex`](docs/eli5.tex) — 9-page plain-English walk-through, no math (PDF in `docs/eli5.pdf`) |
| **License** | MIT (the legacy code under `legacy/` retains its original license) |
| **Authors** | Daniele Lin, Niccolò Pagano |

The two architectures answer different questions:

- **A (federated)** — small, named publisher cohort + witnesses,
  Certificate-Transparency-style. Cheap to operate, finality in
  seconds, no token economy. Wins when the election has a known
  accountable authority set.
- **B (PoW chain)** — permissionless miners, eVote economy, no
  cohort. Wins when permissionless validator membership is a
  non-negotiable design constraint, at the cost of probabilistic
  finality and a rentable-hashpower attack surface for
  high-stakes polls.

See [`paper/artifact.md`](paper/artifact.md) § 7 for the head-to-head
comparison.

## What the system gives you

* **Anonymity inside the ring.** A ballot reveals nothing about which
  ring member produced it (DDH + ROM).
* **One-vote-per-voter.** Anyone can publicly detect a double-vote and
  identify the responsible public key, *without* compromising the
  anonymity of single-vote voters.
* **Decentralised publication.** Every bulletin-board entry is co-signed
  by *t-of-N* cohort members. Liveness against `N − t` unavailable
  publishers; soundness against `t − 1` corrupted publishers.
* **Equivocation evidence.** An independent `k-of-M` witness federation
  co-signs log heads off-band. A malicious cohort majority that splits
  the log produces publicly verifiable equivocation evidence.
* **Public verifiability.** Any third party with the bulletin board can
  recompute the tally and refute a dishonest cohort. The cohort and
  witness identities are bootstrapped from the genesis entry itself.
* **Tamper-evidence.** The bulletin board is hash-chained and signed.

## What it does **not** give you (yet)

* Receipt-freeness / coercion resistance.
* Liveness against a *unanimously*-malicious cohort.
* FROST-aggregated signatures (v0.3 uses a vector of `t` Ed25519 sigs
  per entry; FROST would compress to 64 bytes — v0.4 work).
* Defence against compromised voter devices.
* Post-quantum security.

See [`paper/threat_model.md`](paper/threat_model.md) for the full breakdown.

## Install

The library binds ``libsodium`` (≥ 1.0.18) directly via ``cffi``.

```sh
# Debian / Ubuntu
sudo apt install -y libsodium23 python3-cffi python3-pytest \
    python3-hypothesis python3-cryptography

# or via pip in a virtualenv (libsodium must already be installed)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quickstart — cryptographic primitive

```python
from otrs import keygen, sign, verify, trace

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

## Quickstart — Architecture A (federated, 2-of-3 cohort + 2-of-3 witnesses)

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
- OTRS-verifies every ballot against the issue, message, and ring;
- verifies all witness checkpoints, surfaces any equivocation evidence;
- recomputes the tally, flags double-voters, refutes any dishonest claimed tally.

It exits non-zero on any failure. For the simple **single-manager** case
(1-of-1 cohort, no witnesses — the v0.2 model), use `manager-keygen` +
`setup` instead of `cohort-keygen` + `setup-cohort`.

## Quickstart — Architecture B (PoW chain)

Architecture B uses the same OTRS primitive and the same record schema,
but stores everything on a SHA-256 proof-of-work chain with an eVote
ledger. Every CLI call mines a new block, so the chain serialises the
full demo line-by-line.

```sh
NOW=$(date +%s)

# accounts (Ed25519, hold eVotes) + voter keypairs (OTRS, sign ballots)
python3 -m chain.cli account-keygen --out miner.json > /dev/null
python3 -m chain.cli account-keygen --out alice.json > alice_pk.txt
python3 -m chain.cli voter-keygen   --out v0.json
python3 -m chain.cli voter-keygen   --out v1.json
python3 -m chain.cli voter-keygen   --out v2.json

# genesis funds Alice with 1000 eVotes
ALICE_PK=$(cat alice_pk.txt)
python3 -m chain.cli init-chain --chain c.bin --miner miner.json \
    --allocate "${ALICE_PK}:1000" --timestamp $NOW --difficulty 4

# Alice opens a poll
EID=$(python3 -m chain.cli setup-poll --chain c.bin --miner miner.json \
    --creator alice.json --title "Demo" --options "yes,no" \
    --registration-close $((NOW+100)) --voting-open $((NOW+200)) \
    --voting-close $((NOW+86400)))

# Alice sponsors three voter registrations
for i in 0 1 2; do
  PK=$(python3 -c "import json; print(json.load(open('v$i.json'))['pk_b64'])")
  python3 -m chain.cli register-voter --chain c.bin --miner miner.json \
      --sponsor alice.json --election-id $EID \
      --voter-pk "$PK" --handle "v$i"
done

# freeze the ring, then voters cast (ballots are anonymous: no Ed25519 sender)
python3 -m chain.cli publish-ring --chain c.bin --miner miner.json \
    --creator alice.json --election-id $EID
python3 -m chain.cli vote --chain c.bin --miner miner.json \
    --voter v0.json --election-id $EID --choice yes
python3 -m chain.cli vote --chain c.bin --miner miner.json \
    --voter v1.json --election-id $EID --choice yes
python3 -m chain.cli vote --chain c.bin --miner miner.json \
    --voter v2.json --election-id $EID --choice no

# close after voting_close and audit
python3 -m chain.cli close-poll --chain c.bin --miner miner.json \
    --creator alice.json --election-id $EID \
    --timestamp $((NOW+86401))
python3 -m chain.cli audit --chain c.bin
```

The `audit` command re-loads the chain (which re-verifies PoW, every
Ed25519 signature, every nonce, every balance, the state machine, and
every OTRS signature), then runs the σ-column tally and prints
per-poll results. Any double-vote is flagged with the culprit's
public key, identical to Architecture A's behaviour.

## Repository layout

```
otrs/        ring-signature library — shared by both architectures
              ├ group.py     Ristretto255 wrapper
              ├ hash.py      RFC 9380 hash-to-curve + hash-to-scalar
              ├ otrs.py      KeyGen / Sign / Verify / Trace
              └ serialize.py canonical encodings
voting/       Architecture A — federated bulletin board
              ├ log.py       threshold-signed bulletin board + pending-entry protocol
              ├ records.py   election lifecycle records (reused by chain/ too)
              ├ manager.py   publisher-cohort API
              ├ voter.py     voter API
              ├ witness.py   witness federation (head-co-signing checkpoints)
              ├ auditor.py   public auditor
              └ cli.py       `evote` command line
chain/        Architecture B — proof-of-work blockchain
              ├ block.py     block format + SHA-256 PoW puzzle
              ├ transactions.py typed transactions (coinbase, transfer, + 6 voting kinds)
              ├ state.py     account ledger + per-poll state machine
              ├ mining.py    single-process miner + difficulty adjustment
              ├ node.py      chain head, append, persist, replay
              ├ auditor.py   chain auditor (replay + σ-column tally)
              └ cli.py       `evote-chain` command line
tests/        pytest suite (127 tests across both architectures)
bench/        microbenchmarks
paper/        tech report (Markdown + LaTeX + PDF), threat model, comparison
legacy/       prior implementation, preserved for reference and critique
```

## Running tests and benchmarks

```sh
python3 -m pytest -v                                  # all 127 tests
python3 -m pytest tests/test_election.py -v           # Architecture A integration
python3 -m pytest tests/test_chain.py -v              # Architecture B integration
python3 -m pytest tests/test_otrs.py -v               # cryptography only
python3 -m bench.bench_otrs --sizes 2,4,8,16,32,64,128
```

## Security

This is research software.

* The OTRS construction is proved secure in [Scafuro–Zhang 2021] under
  DDH + ROM, but the **implementation** has not been independently
  audited.
* Field and group arithmetic delegate to libsodium (constant-time);
  Python-level glue is not. Full caveat list lives in
  [`paper/artifact.md` §5.1](paper/artifact.md#51-known-limitations).
* The voting system v0.2 is single-publisher: a malicious manager can
  censor (the affected voter can publicly *prove* censorship, but the
  protocol does not currently provide a fallback publisher). It does
  not yet provide receipt-freeness or distributed availability.

Do **not** deploy this in a real election without a code audit, a full
deployment threat model, and the v0.3 work items addressed.

## Citing

```bibtex
@inproceedings{scafuro2021otrs,
  author    = {Alessandra Scafuro and Bihan Zhang},
  title     = {One-time Traceable Ring Signatures},
  booktitle = {ESORICS 2021},
  year      = {2021}
}

@misc{lin2026eringvoting,
  author = {Daniele Lin and Niccol{\`o} Pagano},
  title  = {A Decentralised Verifiable Anonymous Voting System on Top of
            One-Time Traceable Ring Signatures},
  year   = {2026},
  howpublished = {\url{https://github.com/NickP005/e-ring-voting}}
}
```

## Open problems

See the paper §10 and the threat-model document. Headlines:

1. **Logarithmic-size traceable rings** (Triptych-style with a trace
   tag).
2. **EasyCrypt machine-checked proofs** of OTRS security.
3. **ProVerif / Tamarin model** of the election protocol (cohort +
   witnesses + state machine).
4. **Post-quantum (lattice-based)** OTRS variants.
5. **Coercion resistance** via JCJ / Civitas-style designated-verifier
   re-encryption.
6. **FROST threshold Ed25519**: replace the per-entry vector of t
   signatures with a single 64-byte aggregated FROST signature.
7. **Escrowed secondary cohort** for liveness against a unanimously
   malicious primary cohort.
8. **Gossip protocol** for log / checkpoint replication across cohort
   nodes, witnesses, and independent mirrors.
