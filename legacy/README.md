# Legacy code — original e-ring-voting prototype

This directory preserves the original prototype as it existed before the
2026 rewrite. It is kept for reference, not for use. The new code in the
repository root (`otrs/`, `voting/`, `tests/`, `paper/`) is a re-take on
the same ideas with different system-layer choices; see the bottom of
this file for the relationship between the two.

About **1560 LOC** of Python 3 + asyncio. Authors: Daniele Lin,
Niccolò Pagano.

## What this prototype is

A peer-to-peer voting node that combines two pieces:

1. **One-time traceable ring signatures** (Scafuro–Zhang 2021) as the
   anonymity + double-vote-detection primitive.
2. **A SHA-256 proof-of-work blockchain** as the storage / consensus
   layer — every node runs a miner, blocks are gossiped over
   websockets, the heaviest chain wins.

The intended end-to-end flow was: voters register their public keys on
chain → a poll manager reserves a poll (committed-to via chunk hashes
inside a special transaction) → voters cast OTRS-signed ballots as
transactions → at close time anyone can trace the ring to spot
double-votes and count the result. The crypto for that flow is
implemented; the on-chain glue is only partially wired up (see *What is
not implemented* below).

## Status

This is a **research prototype from \~2021–2022**. It demonstrates the
ring-signature scheme and the blockchain mechanics in isolation, but
the procedure described in the original
[`README` of the project](../README.md#repository-layout) (see also the
old procedure document — registration, "reserve the blocks", L2 voting
chain, eVote forfeit, etc.) is not fully realised in code. Specifically:

* the ring signature primitive **works** — sign, verify, and trace are
  all there and have a small driver in `cryptography/ring.py`;
* the blockchain layer **works in isolation** — mining, difficulty
  adjustment, block validation, heaviest-chain selection, websocket
  gossip;
* but the two layers are **not bound together**. There is no special
  "poll-reservation" transaction type, no L2 voting chain, no eVote
  ledger, no slashing, and the topic/tag encoder for the ring is
  commented out (`cryptography/ring.py:60–91`).

Treat the procedure document as a design sketch and this code as a
working demo of the building blocks.

## Layout

```
main.py                       entry point: starts websocket server +
                              mining loop + periodic file flush

cryptography/
  ring.py                     Scafuro–Zhang OTRS over a 1024-bit
                              DSA-style subgroup (p, q, g from RFC
                              5114-ish parameters). sign_message,
                              check_signature, trace_signatures, plus
                              a self-test at the bottom of the file.
  utils.py                    modular inverse, gcd, modexp
  randomic.py                 SHA-256-seeded deterministic Rng (used
                              inside the three hash oracles H0, H1, H2)
  crypto_tests.py             scratch tests

mining/
  block.py                    in-memory chain state: load tree of
                              known blocks, pick heaviest, verify each
                              block, compute median block time
  mining.py                   PoW miner: SHA-256, target 60 s,
                              multi-process via multiprocessing.Pool,
                              difficulty bumped/dropped based on
                              median of last 11 blocks
  hash.py                     block serialisation (json -> packed
                              bytes), leading-zero-bits difficulty
                              counter

handlers/
  server.py                   websocket server on port 25570
  client.py                   websocket client / dial
  connections.py              "stay not alone" peer-discovery loop
  message.py                  message router with aims:
                                new_block, message, discover_nodes,
                                new_node
                              + 8-digit numeric nonce dedup
  file.py                     async JSON load/save + block file IO

interface/
  console.py                  coloured logging helper
  keylistener.py              keyboard hook scaffold

exceptions/
  exceptions.py               UnknownError / InvalidNonce /
                              InvalidFormat with id codes
  throw_error.py              send-and-raise helper

data/
  settings.json               miner_address (sha256 hex), genesis
                              block hash, file flush interval
  block_index.json            map of block_hash -> {prev, difficulty}
  known_nodes.json            seed peer list, with per-peer attempts
                              counter (5 = healthy, 0 = forget)
  blocks/*.voteblock          packed block bytes, name = block hash
```

## Cryptography (`cryptography/`)

Group: a 1024-bit safe-prime DSA subgroup. `PUBLIC_p` is 1024 bits,
`PUBLIC_order` is 160 bits, `PUBLIC_gen` generates the order-q subgroup.
This is **2010s** parameter choice — modern recommendations would put
this around 80-bit security. The new code (`/otrs/`) replaces this with
Ristretto255 for the same scheme.

The three hash oracles `hash_zero`, `hash_one`, `hash_two`
(`ring.py:111–120`) are domain-separated by appending one byte
(`0x00`, `0x01`, `0x02`) and run through the SHA-256-seeded `Rng`. The
first two land in the group via `g^k mod p`; the third in `[1, q)`.
This is not RFC 9380 hash-to-curve — it is a classic
hash-then-reduce-then-exponentiate, fine for a DSA subgroup but biased
in the upper bits.

`sign_message(sk, issue, msg, pub_keys, position)` produces a
Scafuro–Zhang OTRS:

* commits to a trace tag `σ_i = h^{x_i}` with `h = H0(issue || ring)`,
* extends to a per-member tag column `σ_j = A0 · A1^j` for all j,
* builds a Sigma-OR across the n members, Fiat-Shamir-transformed,
* returns `(A1, c_1..c_n, z_1..z_n)`.

`check_signature` re-derives the column and checks the OR.

`trace_signatures` takes a list of `(msg, sig)` from the same ring +
issue, rebuilds each signer's column, and looks for column collisions:

* exactly one column collides → **double-sign**, returns the colliding
  member's index (the public key at that index is the culprit);
* all columns collide → **linked** (same signer, same msg, same
  randomness; effectively a replay);
* otherwise → independent.

This is the version of the trace logic that ends up in the new code as
`otrs/otrs.py::trace`.

### What's missing on the crypto side

* The topic/message encoder (`encode_tag`, `encode_topic`) is commented
  out — see `ring.py:60–107`. So the prototype signs raw byte strings;
  there is no canonical text-to-bytes mapping for poll metadata yet.
* Constant-time discipline: arithmetic uses Python `pow` and `%`, which
  do not promise constant-time behaviour. Fine for a demo, not for a
  deployment.
* `randomic.Rng` is **deterministic SHA-256-seeded** — appropriate for
  the three hash oracles (which is what it is used for inside Sign),
  but the `gen_private()` helper at `ring.py:124` calls
  `random.randrange` rather than `secrets`, so private keys produced
  this way are not cryptographically random.

## Blockchain layer (`mining/`)

A Bitcoin-shaped PoW chain, simplified:

* **Block format** (`mining/hash.py:13`): 32-byte prev-hash + 32-byte
  block number + 1-byte difficulty + 32-byte cumulative weight +
  transaction blob + 32-byte miner address + 8-byte epoch + 8-byte
  nonce. Block hash is SHA-256 over everything-except-the-nonce; the
  PoW puzzle is `SHA-256(block-without-nonce || nonce)` having at least
  `difficulty` leading zero **bits**.
* **Difficulty target**: 60 s block time. Adjusted ±1 per block when
  the median interval over the last 11 blocks falls outside
  [30 s, 90 s] (`block.py:75-78`, `mining.py:75-78`).
* **Chain selection** (`block.py:127–165`): heaviest chain by sum of
  `2^difficulty` — i.e. GHOST-flavoured cumulative work, not just
  longest-chain.
* **Validation** (`block.py:40–65`): re-hash, check PoW threshold,
  check previous-hash linkage. Tx semantics are **not** validated
  inside the chain — `txs_json_to_bytes` is a serialiser, not a
  verifier.
* **Mining loop** (`mining/mining.py`): a thread spawns
  `cpu_count - 1` processes via `multiprocessing.Pool`, each scans a
  random nonce window of 100 000 hashes per attempt, posts winners
  back into a `Manager().dict()`. The async outer loop polls the dict
  every 5 s to commit the found nonce.

### What's missing on the chain side

* **No transaction validation.** The block serialiser packs
  `{sender, [{receiver, amount}...], signature}` records, but nothing
  checks signatures, balances, or replay. There is no account or UTXO
  model.
* **No eVote currency.** The procedure document refers to fees and
  forfeits in eVotes; there is no balance ledger in the code, so the
  economics described in the doc are not enforced.
* **No L2 voting chain.** The "reserve a poll, generate a layer-2
  identified by the reservation tx hash" mechanism from the procedure
  document has no code behind it.
* **No slashing oracle.** The forfeit concept in the procedure has no
  on-chain trigger condition or destination.
* **`Block.__init__` is buggy:** it `await`s inside `__init__`, which
  Python forbids. `mining/block.py:15–21` would raise in practice — it
  appears to be unfinished refactor of the original `init()` async
  method. Run order in `main.py` is also fragile (`Mining().init()`
  and `Block().init()` are scheduled as bare tasks without sequencing).

## Networking (`handlers/`)

Plain websockets, port `25570`. Each node:

* listens for incoming peers (`server.py`),
* dials known peers from `data/known_nodes.json` (`client.py`,
  `connections.py`),
* re-broadcasts messages with an 8-digit numeric nonce; the dedup keeps
  the last 100 nonces and the IPs that already saw each
  (`message.py:9–73`),
* understands four message aims: `new_block`, `message`,
  `discover_nodes`, `new_node`.

The `new_block` aim is recognised but **does not yet apply the
received block** — `message.py:30` just prints "new block to check".

## Data files (`data/`)

`settings.json` pins the miner address (a 32-byte hex blob, intended
to be sha256 of the operator's pubkey) and the genesis block hash.
`block_index.json` is a flat map of block-hash → `{prev, difficulty}`.
Two example blocks (genesis + one) sit in `data/blocks/`.

## How to run (best-effort, 2021-era)

The prototype expects a Python 3.8+ environment with these deps:

```sh
pip install websockets aiofile psutil keyboard
```

Then from inside `legacy/`:

```sh
python3 main.py
```

It will print `starting voting blockchain node v0.1`, bind a websocket
server on port 25570, attempt to dial peers from `known_nodes.json`,
and start a mining loop with difficulty 23 on the example genesis.

Note: `Block.__init__` issue described above will likely require a
small patch (move the async work into the `init()` coroutine) before
the first run completes cleanly. The crypto driver at the bottom of
`cryptography/ring.py` runs standalone:

```sh
cd cryptography && python3 ring.py
```

It generates 12 keypairs, signs `b"pasta"` with key 1, verifies, signs
`b"pastaa"` with the same key, and prints the trace result —
demonstrating double-sign detection.

## Relationship to the new code (`/otrs/`, `/voting/`)

The 2026 rewrite splits the prototype into two layers and replaces the
PoW chain with a hash-chained signed log:

| Concern | Legacy | New code |
|---|---|---|
| Ring signature | 1024-bit DSA subgroup, custom hashes (`cryptography/ring.py`) | Ristretto255, RFC 9380 hash-to-curve, `secrets`-based RNG (`otrs/`) |
| Storage / order | PoW chain, websocket gossip (`mining/`, `handlers/`) | Hash-chained signed JSON-lines log (`voting/log.py`) |
| Authority on a poll | Implicit "manager" who reserves a poll, posts forfeit | Explicit t-of-N publisher cohort named in genesis entry (`voting/manager.py`) |
| Verification cross-check | Heaviest-chain consensus | k-of-M witness federation that co-signs log heads, makes equivocation publicly detectable (`voting/witness.py`) |
| Poll metadata encoding | TODO (`encode_tag` commented out) | Typed records: `ElectionSetup`, `VoterRegistration`, `RingPublication`, `Ballot`, `VotingClosed`, `TallyPublication` (`voting/records.py`) |
| Audit | Trace function exists, not wired to chain | End-to-end audit pipeline: chain integrity, state machine, per-record validity, witness checks, tally with σ-column bucketing (`voting/auditor.py`) |

The two approaches are not equivalent in their decentralisation story
— the legacy chain is permissionless (anyone can mine), the new log is
permissioned to a named cohort. Both are public-verifiable; only the
legacy one tries to be Sybil-resistant via PoW. The trade-offs there
are discussed in `paper/threat_model.md` and `docs/notes.tex`.

If you want to revive the blockchain approach, the pieces that are
directly reusable from the new code are: `otrs/` (the ring-signature
primitive itself), `voting/records.py` (the typed record / state-machine
definitions), and `voting/auditor.py` (most of the audit logic). The
log-vs-chain choice is local to `voting/log.py` and could be swapped
without touching the other modules.
