# A Reference Implementation of One-Time Traceable Ring Signatures over Ristretto255

**Authors.** Daniele Lin, Niccolò Pagano.
**Status.** Research artifact, v0.1. Not for production deployment.
**Reference scheme.** Alessandra Scafuro and Bihan Zhang, *One-time Traceable Ring Signatures*, ESORICS 2021.

---

## Abstract

We give a clean reference implementation of Scafuro and Zhang's one-time
traceable ring signature scheme (OTRS), instantiated over the prime-order
Ristretto255 group with RFC 9380 hash-to-curve. The scheme provides
anonymity inside a ring of public keys together with public, deterministic
tracing of any signer who produces two signatures on the same issue, making
it a natural primitive for ballot anonymity with double-vote detection.
Our artifact replaces the original 160-bit DSA-style instantiation with a
modern 128-bit-security elliptic-curve instantiation, derives all challenges
through domain-separated XMD:SHA-512 expansion, and ships a property-based
test suite together with a microbenchmark of sign/verify/trace cost against
ring size. We discuss the gap to a fully-verified construction and the next
steps toward a ProVerif / EasyCrypt model and a logarithmic-size variant.

## 1. Introduction

Verifiable anonymous voting has become a recurring research theme because
nation-scale deployments (notably Brazil and Estonia) still rely on
trust-the-server architectures whose properties are not publicly checkable
[Halderman 2018, Springall et al. 2014]. The cryptographic literature has
long offered alternatives — Helios [Adida 2008], Civitas [Clarkson, Chong &
Myers 2008], end-to-end verifiable schemes such as Scantegrity [Chaum et
al. 2008] and, more recently, ElectionGuard [Benaloh et al. 2021] — but
each makes architectural commitments that constrain the kinds of elections
they fit.

Ring signatures, introduced by Rivest, Shamir and Tauman [RST01], offer a
particularly appealing primitive for ballot anonymity: a signer proves
membership in a ring of public keys without revealing which member they
are. The challenge for voting is that a *plain* ring signature lets a
voter sign repeatedly. Two parallel literatures address this: *linkable*
ring signatures [LWW04, CLSAG, MLSAG] which expose a tag identifying
re-use of the same key, and *traceable* ring signatures
[FS07, Scafuro-Zhang 2021] which expose the actual public key on misuse.

This artifact implements Scafuro and Zhang's 2021 scheme. We chose it
because (i) its trace algorithm is *deterministic and one-time-tag-based*,
not interactive; (ii) it requires no trusted setup; (iii) the algebra is a
clean Sigma-OR proof over a single prime-order group, which makes it a
realistic target for both implementation and future formal verification.

### 1.1. Contributions

1. **Reference implementation** (`otrs/`, ~500 LOC Python) of Setup,
   KeyGen, Sign, Verify, Trace over Ristretto255, with all randomness
   drawn from `secrets`/`os.urandom` and all hashing routed through a
   domain-separated RFC 9380 hash-to-curve.
2. **Test suite** (`tests/`) covering algebraic invariants of the group
   wrapper, hash-to-curve determinism and domain separation, sign/verify
   correctness across positions and ring sizes, six negative cases, and
   property-based tests under Hypothesis exercising the trace algorithm
   on randomised inputs.
3. **Microbenchmark** (`bench/bench_otrs.py`) measuring sign, verify and
   trace cost in milliseconds and signature size in bytes against ring
   sizes 2 through 64, with a table reproduced in §6.
4. **Critique** of the prior implementation in `legacy/` — a 160-bit
   DSA-style subgroup with `random.randrange` randomness, no test suite,
   ad-hoc hashing — and a documented migration path.

### 1.2. Non-goals

We do not claim a side-channel-hardened implementation: Python's `int`
arithmetic is not constant-time, and our wrapper around libsodium has a
small number of branches on potentially derived scalars (always negligible
collision probability). We also do not deliver a formal proof in
EasyCrypt or ProVerif; both are flagged as next steps (§8).

## 2. Preliminaries

We work in a prime-order cyclic group $\mathbb{G}$ of prime order $q$ with
generator $g$, in which the Decisional Diffie-Hellman (DDH) problem is
assumed hard. We instantiate $\mathbb{G}$ as Ristretto255 [dV20], a
prime-order group of order $q = 2^{252} + 27742317777372353535851937790883648493$
built on top of Curve25519. Ristretto eliminates the small-subgroup and
cofactor pitfalls of raw Edwards25519, which removes a class of
implementation bugs at no cost.

We require three hash functions modelled as random oracles:

- $H_0 : \{0,1\}^* \to \mathbb{G}$
- $H_1 : \{0,1\}^* \to \mathbb{G}$
- $H_2 : \{0,1\}^* \to \mathbb{Z}_q$

Both $H_0, H_1$ are instantiated as the RFC 9380 random-oracle hash-to-curve
for ristretto255 with the suite identifier
`ristretto255_XMD:SHA-512_R255MAP_RO_`. $H_2$ uses the same XMD expander
followed by `crypto_core_ristretto255_scalar_reduce` (uniform on $\mathbb{Z}_q$
within statistical distance $2^{-126}$).

Per RFC 9380 best practice we tag each oracle with a distinct
domain-separation string fixed in `otrs/otrs.py`:

```
DST_H0 = b"OTRS-v1-RISTRETTO255-XMD:SHA-512-H0"
DST_H1 = b"OTRS-v1-RISTRETTO255-XMD:SHA-512-H1"
DST_H2 = b"OTRS-v1-RISTRETTO255-XMD:SHA-512-H2"
```

Any change to the algebraic structure (curve, hash, transcript format)
**must** bump the version prefix.

## 3. The Scafuro–Zhang construction

Fix an *issue* $I$ — in the voting application, the election identifier —
and a ring $R = (\mathit{pk}_1, \ldots, \mathit{pk}_n)$ of $n$ public keys.
We use 1-indexed positions so we can take modular inverses; $i \in \{1, \ldots, n\}$
is invertible in $\mathbb{Z}_q$ since $n \ll q$.

### KeyGen

$x \xleftarrow{\$} \mathbb{Z}_q^*$, $\mathit{pk} = g^x$.

### Sign$(x_i, I, m, R, i)$

1. Compute $h \gets H_0(I \,\|\, R)$ and $A_0 \gets H_1(I \,\|\, R \,\|\, m)$.
2. Compute the trace tag $\sigma_i \gets h^{x_i}$ (this is what makes
   the scheme one-time-traceable: $\sigma_i$ depends only on $(I, R, x_i)$,
   not on $m$).
3. Set $A_1 \gets (\sigma_i / A_0)^{1/i}$. For $j \ne i$, define
   $\sigma_j \gets A_0 \cdot A_1^{\,j}$; observe $\sigma_i$ also satisfies
   the recurrence by construction.
4. For $j \ne i$ sample $c_j, z_j \xleftarrow{\$} \mathbb{Z}_q$ and set
   $a_j \gets g^{z_j} \cdot \mathit{pk}_j^{c_j}$,
   $b_j \gets h^{z_j} \cdot \sigma_j^{c_j}$.
5. For $j = i$ sample $w \xleftarrow{\$} \mathbb{Z}_q$ and set
   $a_i \gets g^w$, $b_i \gets h^w$.
6. Compute $c^* \gets H_2(I \,\|\, R \,\|\, A_0 \,\|\, A_1 \,\|\, a_1 \,\|\, \cdots \,\|\, a_n \,\|\, b_1 \,\|\, \cdots \,\|\, b_n)$.
7. Set $c_i \gets c^* - \sum_{j \ne i} c_j$ and $z_i \gets w - c_i x_i$.
8. Output $\sigma \gets (A_1, c_1, \ldots, c_n, z_1, \ldots, z_n)$.

### Verify$(\sigma, I, m, R)$

Recompute $h, A_0$, $\sigma_j = A_0 \cdot A_1^j$,
$a_j = g^{z_j} \cdot \mathit{pk}_j^{c_j}$,
$b_j = h^{z_j} \cdot \sigma_j^{c_j}$ for all $j$, and the challenge $c^*$ as
above. Accept iff $\sum_j c_j \equiv c^* \pmod{q}$.

### Trace$(R, I, (m_1, \sigma^{(1)}), (m_2, \sigma^{(2)}))$

Recompute $h$, then $A_0^{(k)} = H_1(I \,\|\, R \,\|\, m_k)$ for $k \in \{1,2\}$,
and $\sigma_j^{(k)} = A_0^{(k)} \cdot (A_1^{(k)})^j$ for $j = 1, \ldots, n$.
For the *real* signer at position $i^*$ we have
$\sigma_{i^*}^{(k)} = h^{x_{i^*}}$ for both $k$ (the trace tag is
$m_k$-independent), so column $i^*$ matches. For $j \ne i^*$ the tag
depends on $m_k$, so columns generically differ.

Outcome:

- **exactly one** column matches $\Rightarrow$ that column is the double-signer;
- **all** columns match $\Rightarrow$ the two signatures are identical
  (replay or signature on the same message twice — we label this "linked");
- **no** columns match $\Rightarrow$ independent signers.

This is implemented in `otrs.otrs.trace`.

## 4. Implementation

### 4.1. Layout

```
otrs/
  group.py        # Ristretto255 wrapper: Scalar, Point, base_mul, ORDER
  hash.py         # RFC 9380 XMD:SHA-512 expand + hash-to-curve, hash-to-scalar
  otrs.py         # keygen / sign / verify / trace
  serialize.py    # canonical ring + signature encodings
tests/            # unit, property, serialization tests
bench/            # microbenchmarks
paper/            # this document
legacy/           # the prior implementation, preserved for reference
```

### 4.2. Group wrapper

`otrs.group` exposes Ristretto255 through `Scalar` and `Point` frozen
dataclasses with byte-level canonical encodings (32 bytes each). All
operations delegate to libsodium via pynacl. The `Point` constructor
calls `crypto_core_ristretto255_is_valid_point` so caller-supplied
encodings cannot bypass group-membership checks.

### 4.3. Hash-to-curve

We implement `expand_message_xmd` (RFC 9380 §5.3.1) over SHA-512 in pure
Python (~25 lines) and compose it with `crypto_core_ristretto255_from_hash`
to obtain the random-oracle hash-to-curve. The same expander, followed by
`crypto_core_ristretto255_scalar_reduce`, gives a uniform-by-statistical-distance
hash-to-scalar. The DST-oversize path (`H2C-OVERSIZE-DST-` prefix, §5.3.3)
is implemented and tested.

### 4.4. Randomness

All secret randomness flows from `os.urandom` via `Scalar.random()`,
which pulls 64 bytes and reduces mod $q$. This is the only RNG path in
the artifact — there is no rejection-sampled custom PRG, no `random.randrange`,
no seedable fallback. The legacy implementation, by contrast, sampled keys
with `random.randrange` (predictable from a Mersenne-Twister state) and
implemented a hash-based PRG that is incompatible with the
random-oracle assumption.

### 4.5. Canonical encoding

The transcript hashed into $H_2$ depends bit-for-bit on the encoding of
the ring and the auxiliary points $(a_j, b_j)$. We commit to the encoding
in `otrs/serialize.py`: 4-byte length prefix, then concatenated 32-byte
Ristretto encodings. Order is significant, so permuting the ring changes
the signature; this is required for the OR-proof structure.

## 5. Security

The scheme is proved unforgeable, anonymous, and traceable in the random
oracle model under DDH in [SZ21]. We do not reproduce the proofs here; we
restate the security claims as the implementation enforces them and flag
where our instantiation deviates from the paper's abstract model.

- **Unforgeability** follows from the soundness of the Sigma-OR proof:
  producing a valid $(\{c_j\}, \{z_j\})$ tuple with $\sum_j c_j \equiv H_2(\cdot)$
  without knowing any $x_j$ requires inverting $H_2$ or solving discrete
  logarithm.
- **Anonymity** follows from honest-verifier zero-knowledge of each
  individual Sigma proof, plus DDH for the trace tag $\sigma_i$.
- **Traceability** follows because $\sigma_{i^*} = h^{x_{i^*}}$ is fully
  determined by $(I, R, x_{i^*})$ and independent of $m$.

Our instantiation matches the abstract assumptions modulo two choices:
the hash-to-curve is *modelled* as a random oracle (XMD:SHA-512 RO is
the cryptographic-community-standard instantiation), and the group is
prime-order Ristretto255 rather than an abstract prime-order group (a
strictly safer instantiation than the original DSA subgroup, ruling out
small-subgroup and cofactor attacks by construction).

### 5.1. Known limitations

- **Constant-time.** Python integer arithmetic is not constant-time; the
  point-scalar product delegates to libsodium which *is* constant-time.
  The remaining timing channel is the `is_zero` branch in
  `Point.scalar_mul`, which is reached only with probability $\approx 2^{-252}$
  for random scalars derived in our protocol — negligible.
- **Equality of group elements** uses Python `bytes` equality, which is
  not constant-time. Group-element equality is *not* secret-dependent in
  our verification path (both sides are derived from public inputs), so
  this is acceptable.
- **No HSM-style binding** between a signer's secret and the host: a
  compromised client trivially signs anything.

## 6. Evaluation

Microbenchmarks were collected on a single core (no parallelism) on a
Linux laptop, with five repetitions per operation, median reported.
Reproduce with:

```sh
python3 -m bench.bench_otrs --sizes 2,4,8,16,32,64,128 --output bench/results.csv
```

| Ring size $n$ | Sign (ms) | Verify (ms) | Trace (ms) | Sig size (bytes) |
|---:|---:|---:|---:|---:|
| 2   | 0.67  | 0.72  | 0.42  | 164  |
| 4   | 1.77  | 1.72  | 0.68  | 292  |
| 8   | 2.62  | 3.14  | 1.32  | 548  |
| 16  | 5.20  | 5.79  | 2.57  | 1060 |
| 32  | 10.42 | 10.51 | 5.27  | 2084 |
| 64  | 20.77 | 20.89 | 10.77 | 4132 |
| 128 | 45.02 | 42.70 | 20.37 | 8228 |

Cost is linear in $n$ — empirically about **0.34 ms** of sign time and
**0.33 ms** of verify time per ring member at this configuration, with the
constant dominated by the $2n + 1$ scalar multiplications each side
performs. Trace runs in $\approx 0.16$ ms/member because it computes only
$n$ scalar multiplications per signature rather than $2n + 1$ exponentiations
plus group additions.

Signature size is $|A_1| + 4 + 2n \cdot |\mathrm{scalar}| = 32 + 4 + 64n$ bytes,
matching the measured column to the byte. At $n = 128$ a signature is
~8 kB — well within a single TCP packet for the practical voting ring
sizes ($n \le 64$) we envision in §1.

## 7. Comparison to related work

A spectrum of ring-signature constructions exists, parametrised by
signature size, signer/verifier cost, trust assumptions, and traceability
properties:

| Scheme | Sig size | Trace | Setup | Assumption |
|---|---|---|---|---|
| RST01 (original) | $O(n)$ | none | none | RSA-like |
| LSAG / CLSAG [Noether 2015, Goodell et al. 2020] | $O(n)$ | linkable (per-key tag) | none | DDH (Monero-style) |
| MLSAG [Noether 2015] | $O(n)$ | linkable | none | DDH |
| Triptych [Noether 2020] | $O(\log n)$ | linkable | none | DDH |
| Bulletproofs-ring / Lelantus [Jivanyan 2019] | $O(\log n)$ | linkable | none | DDH |
| Raptor / Falafl [LZS+2018, ESZ+2022] | $O(\log n)$ | linkable | none | Lattice (PQ) |
| **Scafuro–Zhang (this work)** | $O(n)$ | **traceable (one-time)** | none | DDH, ROM |

The relevant axis for our use case (one ballot per voter, public auditability,
no trusted authority) is *traceability*, which is rarer than linkability.
Most linkable schemes only reveal that two signatures share a signer
without identifying them; OTRS additionally identifies the misbehaving
public key. The cost is signature size: $O(n)$ versus $O(\log n)$ for
state-of-the-art linkable schemes.

A natural research direction (§8) is to combine the trace tag with a
log-size set-membership proof à la Groth–Kohlweiss [GK15] or Triptych.

## 8. Open problems and future work

1. **Logarithmic-size traceable rings.** Replace the linear Sigma-OR with
   a Groth–Kohlweiss-style membership proof while keeping the trace tag
   $\sigma_i = h^{x_i}$. The challenge is binding the per-position $A_1$
   reconstruction to the index that the membership proof commits to.
2. **Formal verification.**
   - *EasyCrypt*: model the three games (unforgeability, anonymity,
     traceability) and machine-check the reductions to DDH and ROM.
     The scheme's small algebraic surface makes this tractable.
   - *ProVerif/Tamarin*: model the *protocol layer* of the e-voting
     application — registration, ballot submission, tracing — and verify
     ballot anonymity and double-vote detection as observational
     equivalence properties.
3. **Post-quantum variants.** The DDH reduction breaks under Shor's
   algorithm. Lattice-based linkable rings (Raptor, Calamari, Falafl)
   exist; constructing a *traceable* lattice ring with one-time tags is,
   to our knowledge, open. A literature survey + barrier analysis is a
   tractable Master's thesis topic.
4. **Coercion resistance.** OTRS prevents *vote duplication* but not
   *vote selling* — a coerced voter could prove to a coercer which
   signature is theirs by revealing $x_i$. A receipt-free extension à la
   JCJ [Juels, Catalano & Jakobsson 2005] or Civitas is needed for
   coercion resistance.
5. **Bulletin-board layer.** The `legacy/` ledger is a stub; a proper
   integration would re-target the artifact at, e.g., the *Civitas*
   bulletin board model or a public append-only log such as Trillian.
6. **Cross-validation against RFC 9380 test vectors** for ristretto255
   hash-to-curve; we ship regression vectors but not (yet) the official
   ones, since RFC 9380's appendix omits ristretto255 vectors in some
   normative drafts.

## 9. Reproducibility

This artifact is released under the MIT license at
`github.com/NickP005/e-ring-voting`. To reproduce:

```sh
# system deps (Debian/Ubuntu)
sudo apt install -y python3-nacl python3-pytest python3-hypothesis

# tests
python3 -m pytest -v

# benchmarks
python3 -m bench.bench_otrs --sizes 2,4,8,16,32,64 --output bench/results.csv
```

## References

- [Adida 2008] Ben Adida. "Helios: Web-based Open-Audit Voting." USENIX Security 2008.
- [Benaloh et al. 2021] Josh Benaloh et al. "ElectionGuard: a Cryptographic Toolkit to Enable Verifiable Elections." 2021.
- [Chaum et al. 2008] David Chaum et al. "Scantegrity II." EVT 2008.
- [Clarkson, Chong & Myers 2008] Michael Clarkson, Stephen Chong, Andrew Myers. "Civitas: Toward a Secure Voting System." S&P 2008.
- [dV20] Henry de Valence et al. "Ristretto." 2020.
- [FS07] Eiichiro Fujisaki, Koutarou Suzuki. "Traceable Ring Signature." PKC 2007.
- [GK15] Jens Groth, Markulf Kohlweiss. "One-Out-of-Many Proofs." EUROCRYPT 2015.
- [Halderman 2018] J. Alex Halderman et al. "Security analysis of the Estonian Internet voting system." CCS 2014.
- [Juels, Catalano & Jakobsson 2005] Ari Juels, Dario Catalano, Markus Jakobsson. "Coercion-resistant electronic elections." WPES 2005.
- [LWW04] Joseph K. Liu, Victor K. Wei, Duncan S. Wong. "Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups." ACISP 2004.
- [Noether 2015] Shen Noether. "Ring Signature Confidential Transactions for Monero." 2015.
- [Noether 2020] Sarang Noether et al. "Triptych: Logarithmic-sized linkable ring signatures." 2020.
- [Goodell et al. 2020] Brandon Goodell et al. "Concise Linkable Ring Signatures and Forgery Against Adversarial Keys." 2020.
- [RFC 9380] Sam Scott et al. "Hashing to Elliptic Curves." 2023.
- [RST01] Ron Rivest, Adi Shamir, Yael Tauman. "How to Leak a Secret." ASIACRYPT 2001.
- [Springall et al. 2014] Drew Springall et al. "Security analysis of the Estonian Internet voting system." CCS 2014.
- [SZ21] Alessandra Scafuro, Bihan Zhang. "One-time Traceable Ring Signatures." ESORICS 2021.
