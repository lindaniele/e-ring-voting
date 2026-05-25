# e-ring-voting v0.4 — Threat Model

This document is the canonical statement of *what we defend against* and
*what we explicitly do not*. It complements `paper/artifact.md` (which
describes the cryptography and the system architectures) by specifying
the system-level assumptions.

## Architecture coverage

The artifact ships **two** system-layer architectures with the same
cryptographic primitive and record schema:

- **Architecture A** — federated bulletin board (`voting/`).
  t-of-N publisher cohort co-signs entries; k-of-M witness federation
  checkpoints heads.
- **Architecture B** — proof-of-work chain (`chain/`).
  Permissionless mining; eVote ledger; typed voting transactions; same
  per-record validation as A.

The bulk of this document (cryptographic primitive, voter adversary,
network adversary, coercer, compromised device) applies to **both**
architectures unchanged: the cryptographic core is shared. Sections
that name the cohort or witnesses describe Architecture A specifically.
The final section (§7) is the addendum for Architecture B.

## Principals

- **Publisher cohort** (N members): the writers to the bulletin board.
  Each holds one Ed25519 secret key. Any subset of size ≥ t must
  co-sign every entry for it to be valid.
- **Voter**: holds an OTRS (Ristretto255) secret key. Submits one
  ballot.
- **Witness** (M members): an independent third party with an Ed25519
  keypair. Witnesses cannot append to the main log; they emit
  *checkpoints* — signed attestations of the log head — to a sidecar.
- **Auditor** (anyone): reads the bulletin board and the witness
  sidecar, recovers the cohort and witness identities from the genesis
  entry, and verifies the entire election.
- **Adversary**: depending on the property, may control the network, a
  subset of voters, a subset of cohort members, a subset of witnesses,
  or any combination.

## Assets

| Asset | Defended? | Mechanism |
|---|---|---|
| Voter anonymity inside the ring | Yes | OTRS unconditional anonymity under DDH + ROM |
| One-vote-per-voter | Yes | OTRS one-time traceability — double-signing is publicly detectable |
| Public verifiability of the tally | Yes | Auditor recomputes from the log; tally is a deterministic function |
| Tamper-evident history | Yes | Hash-chained, Ed25519-signed log entries |
| Eligibility (only registered voters) | Yes | Ed25519 attestation per voter, verified at audit |
| Liveness against (N − t) cohort members offline | Yes | Threshold publisher cohort: any t members suffice to append |
| Soundness against (t − 1) corrupted cohort members | Yes | A minority faction cannot append on its own |
| Equivocation evidence when ≥ t cohort members collude | Yes (with witnesses) | Honest witnesses sign divergent heads → public proof |
| Censorship-evidence | Yes | Voter can prove ballot non-inclusion from the public log |
| Censorship-resistance against the cohort | Partial | A unanimous-cohort refusal stalls the election; mitigation is gossip + escrowed secondary cohort (v0.4) |
| Receipt-freeness / coercion resistance | **No** | A voter can prove how they voted by revealing their secret; v0.4 work |
| Side-channel resistance of the local client | Partial | libsodium scalar ops are constant-time; Python glue is not |

## Adversary models

### 1. Malicious voter
*Capability:* generates arbitrary OTRS keys; may register multiple times if
the manager attests them; controls their own private key.

Defences:
- **Double-vote:** OTRS `Trace` publicly identifies the public key that
  signed two distinct messages on the same `issue`. The auditor rejects
  both ballots and emits the culprit pk in the report. Verified by
  `tests/test_election.py::TestDoubleSign::test_double_sign_excludes_both_ballots`.
- **Forged ballot from a non-member:** `verify` rejects signatures whose
  ring doesn't match the published ring. The client API also pre-rejects
  at `cast_ballot` time
  (`tests/test_election.py::TestAdversaries::test_voter_outside_ring_cannot_sign_passing_ballot`).
- **Invalid choice:** auditor rejects ballots whose `choice` is not in
  the option set
  (`tests/test_election.py::TestAdversaries::test_invalid_choice_rejected_at_cast`).

Out of scope:
- Selling a vote: a voter who reveals their secret key to a third party
  enables that party to confirm the voter's ballot. Mitigated only by
  receipt-freeness, which OTRS does not provide.

### 2. Malicious cohort minority (size < t)
*Capability:* up to t − 1 publishers collude. They can refuse to
co-sign entries proposed by honest cohort members (slowing things
down) but cannot append on their own — the log requires t distinct
signatures.

Defences:
- **Forging entries:** impossible. The honest majority must co-sign,
  and OTRS unforgeability prevents the minority from minting a
  registration or a ballot they don't have keys for.
- **Censoring individual ballots:** if at least t honest cohort members
  remain, the election proceeds. The minority's refusal is observable
  (the pending-entry sidecar shows who has and has not signed).
- **Lying about the tally:** even a unanimous cohort can publish a
  dishonest `TallyPublication`; auditors recompute and refute.
  Verified in
  `tests/test_election.py::TestAdversaries::test_audit_rejects_extra_record_after_tally`
  and the structural test
  `tests/test_threshold.py::TestThresholdAppend::test_audit_rejects_log_under_higher_threshold`.

### 3. Malicious cohort majority (size ≥ t)
*Capability:* at least t cohort members collude. They control entry
content: they can forge registrations, append fake ballots, equivocate
(show divergent logs to different observers), or refuse to publish.

Defences:
- **Lying about the tally:** still rejected by auditors who recompute.
- **Stuffing fake voters:** the cohort can attest arbitrary pks but
  this is detectable as a discrepancy between the cohort's attested set
  and the policy-level eligibility list (which is enforced
  out-of-band — see §1 above). **Eligibility-of-attestation is a policy
  question** outside the cryptographic system.
- **Equivocation:** mitigated by the witness federation. Witnesses
  who see different cohort outputs will emit checkpoints with
  conflicting `head_hash` values at the same `log_index`; the auditor
  surfaces this as `EQUIVOCATION` evidence and rejects the election.
  Verified in
  `tests/test_threshold.py::TestWitnesses::test_equivocation_detected`.
- **Reordering or rewriting history:** the chain is hash-linked;
  rewriting forks the head and any retained earlier hash refutes the
  rewrite. With witnesses, an old checkpoint stands as a notarised
  pin on the head at that index.
- **Censorship of all ballots:** a unanimous cohort that refuses to
  publish stalls the election entirely. Residual risk; mitigation is
  an escrowed secondary cohort that activates after a timeout (v0.4
  engineering work).

### 4. Malicious witness minority (size < k)
*Capability:* up to k − 1 witnesses collude, possibly with the cohort.

Defences:
- **Fake equivocation evidence:** a witness can only sign with their
  own key; their fake checkpoint adds at most one bogus equivocation
  data point, which the auditor will surface but cannot refute
  on-chain. **A real deployment should require multiple independent
  witnesses to sign equivocation evidence** before treating it as
  definitive (k′-of-M with k′ > 1). The artifact's checkpoint format
  supports this trivially.
- **Refusing to checkpoint:** if fewer than k witnesses sign, the
  audit fails the `witness_threshold` check. The fix is to provision
  enough honest witnesses (k of M honest is the security assumption).

### 5. Network adversary
*Capability:* reads, drops, delays, and reorders messages between the
manager, voters, and auditors. Cannot break TLS / Ed25519 / OTRS.

Defences:
- The bulletin board is the single source of truth; any party who
  eventually fetches it can verify it. Delivery delays do not affect
  correctness.
- Replay of a ballot bytes-for-bytes by the network has the same effect
  as an honest replay: the OTRS trace classifies it as "linked" and the
  auditor counts it once.

Out of scope:
- A partition that prevents the voter from ever reaching the bulletin
  board is indistinguishable from manager censorship; same v0.3 mitigation.

### 6. Coercer / vote-buyer
*Capability:* approaches a voter after the fact and demands proof of how
they voted.

Defences:
- The OTRS signature does *not* by itself identify the signer.
- However, a voter who *reveals their secret key* to the coercer enables
  the coercer to recompute the trace tag $\sigma_i = h^{x_i}$ and match
  it against the bulletin board, confirming the vote.

**This is the receipt-freeness gap.** It is the single most important
known limitation of v0.2. Standard mitigations include JCJ-style
designated-verifier re-encryption or Civitas's coercion-resistance proofs,
both of which require additional cryptographic infrastructure (mixnets,
threshold tally authorities). Treating this as a v0.4 research line.

### 7. Compromised voter device
*Capability:* the malware running on a voter's laptop sees the secret key
and can sign anything.

Defences:
- None at this layer. A compromised client trivially impersonates the
  voter. Mitigation requires a hardware trust anchor (smartcard, HSM,
  secure enclave) — out of scope for a Python reference artifact, but
  flagged as a v0.3 deliverable for any real deployment.

## Properties summary

Under the stated assumptions (DDH in Ristretto255, ROM for SHA-512-based
hash-to-curve, Ed25519 unforgeability, honest voters keep their secret
keys, the publisher cohort publishes monotonically, at least t cohort
members are honest, at least k witnesses are honest), v0.3 provides:

1. **Anonymity inside the ring** for any single ballot.
2. **Public, deterministic detection** of any voter who casts two
   ballots on distinct messages within one election (issue).
3. **Public, deterministic tallying** that anyone can recompute and
   refute.
4. **Tamper-evident history** of the entire election.
5. **Eligibility enforcement** against the cohort's attestation set.
6. **Liveness against N − t unavailable cohort members.**
7. **Soundness against t − 1 corrupted cohort members.**
8. **Equivocation evidence** when the cohort itself splits, surfaced by
   the witness federation.

What it **does not** provide:

- Receipt-freeness / coercion resistance.
- Liveness against a unanimously-malicious cohort (engineering
  mitigation: escrowed secondary cohort, v0.4).
- Sybil resistance at the eligibility layer (identity-proofing policy
  concern).
- Defence against compromised voter devices.
- Post-quantum security.
- FROST-aggregated signatures (v0.3 uses a vector of t Ed25519 sigs
  per entry; FROST would compress this to 64 bytes total, v0.4 work).

These are the open research problems carried over to v0.4.

## 7. Architecture B addendum: PoW chain specifics

Under Architecture B (`chain/`), the cohort/witness model is replaced by
permissionless mining. The OTRS-level guarantees (anonymity, traceability)
are unchanged because the cryptographic primitive is identical. What
changes is the storage-layer adversary model.

### B.1 Replacement adversaries

- **Malicious miner.** Equivalent to a malicious cohort member in A
  but with permissionless entry: anyone can join. Single malicious
  miners cannot censor — a tx the attacker refuses to include is
  picked up by the next honest miner. Multiple malicious miners
  controlling a majority of hashpower can reorganise the chain
  (drop ballots, swap blocks); finality is probabilistic.
- **Hashpower-rental attacker.** Specific to PoW. An adversary with
  sufficient external funds can rent majority hashrate on services
  like NiceHash for the duration of the voting window and reorganise
  the chain to drop unfavoured ballots. The cost is bounded by
  market rate × voting-window length; the payoff is bounded by the
  political stakes of the largest poll on the chain. For meaningful
  elections, payoff routinely exceeds cost (Park & Specter, 2021).
- **Poll-creator-as-SPOF.** The chain has no cohort, but each poll
  still has a single creator (the Ed25519 address that issued the
  `setup_poll` transaction). That creator alone may publish the
  ring / close / tally for their own poll. A malicious creator can
  refuse to publish the ring (stalling the poll) or front-run a
  voter's ballot with a poll-close tx (truncating the voting
  window). Mitigation: pin the schedule in the setup record and let
  the auditor reject out-of-schedule close/tally; this is enforced
  in `chain.state` (`block_timestamp < setup.voting_close` rejects
  premature close).

### B.2 New properties (vs A)

Architecture B gains:

- **Permissionless validator membership.** Anyone with hashpower can
  produce blocks; no genesis-pinned trust set beyond the protocol
  rules.
- **Censorship resistance against any minority of miners.** A tx
  included in any block produced by an honest miner becomes part of
  the canonical history.

### B.3 Properties weakened (vs A)

Architecture B weakens:

- **Finality.** A is total-order from genesis (no forks); B is
  probabilistic (the heaviest chain is canonical but reorgs of
  recent blocks are possible).
- **Equivocation defence.** Without a witness federation, the only
  defence against a 51% miner rewriting history is the heaviest-chain
  rule. A long-range reorg is a successful attack iff it goes
  undetected; there is no out-of-band cross-check analogous to
  witness checkpoints.
- **Cross-poll anonymity.** Multi-poll deployments expose persistent
  Ed25519 identities at the chain layer (poll creators, sponsors).
  Voters' OTRS keys are not persistent across polls by default, but
  if a voter sponsors their own registration with a personal Ed25519
  address, that address links their participation across polls. The
  recommended deployment binds each voter to a one-shot Ed25519
  address used only for that poll's registration.
- **Disenfranchisement risk.** Voters in A do not transact;
  registration happens via cohort signing. In B, registration costs
  fees, paid either by the voter (needs eVotes) or by a sponsor (the
  sponsor learns which key they registered for whom).

### B.4 Properties unchanged (vs A)

The following are identical between architectures because they live
entirely in the OTRS primitive:

- Ballot anonymity inside the ring.
- One-time traceability for double-voting.
- Public tally recomputability.
- Receipt-freeness (lack of) — `Trace` exposes the signer if a coerced
  voter reveals their secret in either architecture.
- Defence against compromised voter devices (lack of) — same in both.
- Post-quantum security (lack of) — same in both.
