# Legacy code — the original e-ring-voting prototype (2021–22)

This directory preserves the prototype by Daniele Lin and Niccolò Pagano
as it was, for reference. Nothing here is imported by the rest of the
repository. About 1 560 lines of Python 3 + asyncio.

This README was written in 2026, from the code and from the project's
git history (the 2021 and 2022 versions of the top-level README, which
described the procedure). An earlier 2026 version of this file got
several things wrong (it called the signature Scafuro–Zhang, said it
worked, and called the chain rule "GHOST"); they are corrected below.

## What the prototype was for

A permissionless voting chain where anonymity is guaranteed by a
**traceable ring signature** and cheating is made costly. From the
procedure in the old README and from the code:

| Idea | Source |
|---|---|
| Ring signature with `issue` and a tag `issue ‖ ring`; trace outputs `"linked"`, `"indep"` or the culprit's key | `cryptography/ring.py` — this is Fujisaki–Suzuki, *Traceable Ring Signature*, PKC 2007 |
| Voters split into groups of fixed size ("members per group", "group size") declared when the poll is reserved | README, Nov 2021 and Apr 2022 |
| Two kinds of signed message: a vote (`$`) or a transfer (`*`) "to another group with another key" | comment above `encode_tag`, `cryptography/ring.py:59` |
| The voter signs its own registration with its key; another address may pay the 1-eVote fee ("could be the same voter or the organisation") | README, Apr 2022 |
| A *forfeit*, distinct from a fee: eVotes locked (by the manager) that are not paid to the miner | README, Apr 2022 |
| Poll timing in block numbers; poll data split into chunks committed by hash in a reservation transaction | README, Nov 2021 and Apr 2022 |
| SHA-256 PoW, heaviest chain by Σ 2^difficulty, difficulty adjusted on the median of the last 11 blocks | `mining/` |

The current code in `chain/` completes this design. The one element
that is new there is a deposit per *voter*, burned when that voter's key
is traced, rather than a forfeit locked by the manager.

## What the code actually did

### Cryptography (`cryptography/`)

`ring.py` implements Fujisaki–Suzuki over a 1024-bit DSA-style group
(`PUBLIC_p` 1024 bits, subgroup order `PUBLIC_order` 160 bits, roughly
80-bit security). Signing computes `h = H0(issue ‖ ring)`,
`σ_i = h^{x_i}`, `A0 = H1(issue ‖ ring ‖ m)`, `A1 = (σ_i / A0)^{1/i}` and a
Fiat–Shamir Σ-OR proof. Three defects, each reproduced by running the
code:

1. **Anonymity is broken.** `hash_zero` and `hash_one`
   (`ring.py:111–120`) return `g^t` with `t` drawn from a deterministic
   SHA-256-based generator seeded with the input. Anyone can therefore
   compute `t` for `h`, then `pk_j^t = h^{x_j}` for every ring member,
   and compare with the columns `A0 · A1^j` of a single signature: the
   signer's position follows from public data. Verify and trace still
   work, so a demo shows nothing wrong. A hash into the group must not
   reveal a discrete logarithm (RFC 9380 hash-to-curve does not).
2. **Only position 1 verifies.** `ring.py:147` computes `1/position`
   with `utils.getFractionModulo`, which inverts modulo `p`; the exponent
   must be inverted modulo the group order `q`. At position 1 the inverse
   is 1 either way, so the built-in demo (which signs at position 1)
   works; positions 2 and up produce signatures that do not verify.
3. **The generator crashes as called.** `randomic.Rng.__init__` calls
   `seed.encode('utf-8')` (`randomic.py:16`) but `hash_zero`/`hash_one`
   pass bytes, so `python3 ring.py` raises before signing.

Also: `gen_private()` uses `random.randrange`, not a cryptographic
generator; `encode_tag` / `encode_topic` (the message and poll-metadata
encoders) are commented out.

### Chain (`mining/`, `handlers/`)

* Block hash: SHA-256 over the block without the nonce; PoW is
  `SHA-256(block_hash ‖ nonce)` with `difficulty` leading zero bits, so
  mining cost does not depend on block size.
* Chain selection: the chain with the largest Σ 2^difficulty — the
  ordinary heaviest-chain rule.
* Difficulty: ±1 when the median interval of the last 11 blocks leaves
  [30 s, 90 s]. **The miner and the validator adjust in opposite
  directions**: `mining.py:75–78` lowers difficulty when blocks are slow,
  `block.py:118–121` raises it, so honest blocks would be rejected after
  any adjustment.
* `Block.__init__` uses `await` (`block.py:15–21`), which Python does not
  allow in a constructor; the node does not start as written.
* Transactions are serialised but never validated (no signatures,
  balances or replay checks), there is no eVote ledger, and nothing
  connects votes to the chain. `handlers/message.py` receives
  `new_block` messages but only prints them.
* Networking: websockets on port 25570, peer discovery from
  `data/known_nodes.json`, message de-duplication by an 8-digit nonce.

## Layout

```
main.py                 entry point: websocket server + mining loop + file flush
cryptography/ring.py    the traceable ring signature, encoders (commented out), demo
cryptography/utils.py   modular arithmetic helpers
cryptography/randomic.py  SHA-256-seeded deterministic generator used by the hashes
mining/block.py         chain state, validation, heaviest-chain selection
mining/mining.py        multi-process PoW miner, difficulty adjustment
mining/hash.py          block serialisation, leading-zero counter
handlers/               websocket server/client, peer discovery, message routing
interface/, exceptions/ logging, keyboard hook, error codes
data/                   settings, block index, known peers, example blocks
```

## Where each piece went

| Prototype | Now |
|---|---|
| `cryptography/ring.py` | `trs/` — the same scheme over Ristretto255, RFC 9380 hash-to-curve (no known discrete log), inverse modulo `q`, `os.urandom` |
| group size | `voting/groups.py` — groups drawn from a block-hash beacon after registration closes |
| `$` vote / `*` transfer | `KeyTransfer` records and rounds in `chain/state.py` |
| voter-signed registration, paying benefactor | proof of possession (`trs/pop.py`) and sponsor in `register_voter` |
| forfeit vs fee | per-voter deposit, burned on tracing, refunded otherwise |
| `mining/` | `chain/` — required difficulty and heaviest-chain fork choice enforced at validation |
| block-number timing | block timestamps drive every phase |

See `paper/artifact.tex`, section "From the prototype to this artifact".

## Running it (2021-era, best effort)

```sh
pip install websockets aiofile psutil keyboard
python3 main.py          # from inside legacy/; fails in Block.__init__ (see above)
```

The signature demo at the bottom of `cryptography/ring.py` needs the
`Rng` fix (accept bytes) before it runs, and then only verifies because
it signs at position 1.
