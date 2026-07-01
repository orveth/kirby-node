# Kirby FROST-Unified Identity — Design Spec (next-iteration reshape)

**Date:** 2026-07-01 · **Author:** worker:npub-unify · **Status:** SPEC / costed input for gudnuf's final decision. NOT a build order. **This is a design doc only; no code changes.**

**Direction (gudnuf's GO):** make the agent's identity *entirely FROST-based* — ONE stable threshold key (the FROST group key **Q**) that does everything (posts, presence, lifecycle, DMs, AND the money wallet), where the key is **never reconstructed on any single machine** (pure threshold; every operation is a quorum ceremony over distributed shares). gudnuf: *"everything FROST based so we can have one stable identity and the key never has to live on the same machine,"* latency *"not an issue right now."*

> **Read this first — HONESTY CONTRACT.** gudnuf has GO'd the *direction*. This spec exists to price it, not to sell it. The headline (§A) is genuinely exciting and, I believe, correct as a north star. But the costs (§D) are real and one of them — the audit bar for money — is a hard, months-scale, third-party-dependent gate that is outside our control. Where the honest answer is "we don't know the exact number," I say so and give a bounded estimate with its assumptions. Do not read past §D to the recommendation without reading §D.

---

## BOUNDARY (state this up front)

**This is NEXT-iteration. Nothing here pauses shipping.** The current builds ship UNCHANGED on the present premise:

- **P1 canonical social npub (#106) is MERGED** (`7b2fba0` on main; `da4c20d` follow-up). One social npub = promoted plain `dm_keys` signs posts + kind:0 profile + DM; Q keeps presence/lifecycle/lease + the 31000→canonical binding tag. Ships as-is.
- **Money NIP-60 P2 (reconstruct-on-lease keyring)** proceeds on its *present* separate-key premise. This spec proposes RETIRING reconstruct-on-lease in a later iteration (§E), but that is a future reshape — the money-build lane is not blocked or redirected by this doc.
- **The zero-config bake** (run-just-works) proceeds unchanged.

The reshape described here is a deliberate, phased *future* replacement of the identity substrate. It informs gudnuf's decision about where the architecture goes *next*; it does not stop the train that is moving now.

---

## A. Thesis — this fulfills Kirby's core custody claim

Kirby's founding promise, from the repo's own `CLAUDE.md`:

> "It holds its own Nostr identity under a 2-of-3 FROST threshold key Q … The rules are enforced by the machine, not trusted to an operator."

And the honest boundary that same file records today:

> "**FROST custody is structural, not yet distributed.** Q is a real 2-of-3 key and signs everything, but the three shares are co-located on the host today — an operator could still collude. **Do not claim 'a key no human holds' until cross-machine holder distribution lands.**"

There are **two** gaps between the promise and today, not one:

1. **Shares are co-located.** Even Q — which only *signs* — has all three shares on one host today. Cross-machine holder distribution (the crossmachine-frost lane) closes this for signing.
2. **The money key is not even threshold.** The money wallet uses an **L1 bearer key** — a plain ECDH key that a single machine holds and can drain — a compromise the money-continuity design made *explicitly* because **"NIP-60 needs an ECDH key but FROST can't ECDH"** (money-continuity design doc, §"L1 key model"; the tradeoff is documented there as "while a node is authorized and running, the reconstructed key lives in its memory and could drain the wallet"). So the *money* — the thing custody is actually about — is today the LEAST protected identity plane, guarded by a single-point-of-theft key, by design.

**The thesis of this reshape:** with threshold-ECDH (FROSTR/Bifrost's collaborative ECDH — `node.req.ecdh(pubkey)` derives the NIP-44 shared secret *from the shares, without reconstructing the key*), the "FROST can't ECDH" compromise **dissolves**. NIP-60 ecash can be both *encrypted to* and *spend-authorized by* the quorum, never reassembled on any machine. Combined with cross-machine share distribution, this is the first time Kirby can *truthfully* make its founding claim about the part that matters most:

> **Bitcoin under a threshold key no human holds.**

Not "the presence beacon is threshold-signed." The *money*. That is the headline. Everything below is the cost of earning the right to say it.

---

## B. Architecture — one Q does everything, never reconstructed

Today an agent presents **three identity planes with three different keys**:

| Plane | Key today | Type | Signs / does | Where the key lives |
|---|---|---|---|---|
| **SOCIAL** | canonical `dm_keys` (promoted, #106) | plain (ECDH-capable) | kind:1 posts, kind:0 profile, NIP-17 DM (kind:1059/10050) | plaintext keyfile on the node |
| **MONEY** | L1 bearer wallet key (#92) | plain (ECDH-capable) | NIP-60 wallet self-encrypt (NIP-44), spend authorization | plaintext keyfile on the node; reconstruct-on-lease keyring being built (P2) reassembles it on the leaseholder |
| **CONTROL** | FROST **Q** (`frost-secp256k1-tr`) | threshold Schnorr | kind:31000 presence, kind:9100 lifecycle, the kind:31002 failover lease, kind:1 fallback for non-DM agents | shares (co-located today; cross-machine = roadmap) |

**The target: collapse all three onto Q. One key. One npub. Never reconstructed.**

| Plane | Key after reshape | Primitive used | Ceremony type |
|---|---|---|---|
| **SOCIAL** | **Q** | threshold Schnorr (have it) + threshold-ECDH (net-new) | sign posts/profile = quorum Schnorr; DM encrypt/decrypt = quorum ECDH |
| **MONEY** | **Q** | threshold-ECDH (net-new) | NIP-60 self-encrypt/decrypt = quorum ECDH; spend authorization = quorum event (the ceremony IS the authorization) |
| **CONTROL** | **Q** | threshold Schnorr (have it) | presence/lifecycle/lease = quorum Schnorr (unchanged) |

Every current key **retires into Q**:

```
  canonical dm_keys (SOCIAL) ─┐
  L1 bearer wallet key (MONEY)├──▶  Q  (one FROST group key, one npub)
  FROST Q (CONTROL) ──────────┘        │
  reconstruct-on-lease keyring ──▶  DROPPED  (§E — "never on one machine" rejects reassembly)
                                       │
                              ┌────────┼─────────────────────────┐
                       threshold        threshold-ECDH      threshold-ECDH
                        Schnorr         (NIP-44 secret)     (NIP-44 secret)
                          │                  │                    │
                    posts/profile/       NIP-17 DMs         NIP-60 wallet
                    presence/lifecycle/  (encrypt+decrypt)  (self-encrypt + spend-auth)
                    lease
```

**Invariant that makes the headline true:** Q is *never* materialized as a scalar on any single machine — not for signing (already true: FROST partial-sig aggregation), and, after this reshape, not for ECDH either (threshold-ECDH derives the shared *point* by Lagrange-combining per-holder point contributions; see §C). One stable npub answers "who is this agent" for posts, DMs, presence, AND owns the money. The #106 "which of 3 npubs do I DM" problem doesn't just get patched — it becomes *structurally impossible*, because there is exactly one key.

---

## C. Mechanism — how threshold-ECDH wires into kirby-node

### C.1 The crypto construction (what "threshold ECDH" actually is)

NIP-44 (hence NIP-17 DMs and NIP-60 wallet encryption) needs the ECDH shared secret: given our secret scalar `s` (= Q) and a peer pubkey `B`, compute the point `s·B` and take its x-coordinate into HKDF ("nip44-v2") to get the conversation key ([NIP-44 spec](https://nips.nostr.com/44)).

The threshold trick (linearly-homomorphic, standard Shamir/FROST algebra): Q is Shamir-shared as `s = Σ λ_i · s_i` over the signing set (λ_i = Lagrange coefficients). Each holder `i` computes its **point contribution** `P_i = λ_i · s_i · B` from its *own* share and the *public* peer key `B`. The coordinator sums: `Σ P_i = (Σ λ_i · s_i)·B = s·B` = the shared secret point. **The scalar `s` is never formed; no holder learns another's share; the output is exactly the same point vanilla ECDH would produce, so it is byte-compatible with NIP-44.** ([threshold secret-sharing on curve points is linearly homomorphic — CertiK / Aumasson survey](https://eprint.iacr.org/2020/1390.pdf))

**Crucial simplification vs threshold ECDSA:** threshold *ECDSA* is famously heavy (Binance tss-lib is 9 rounds; needs multiplicative-to-additive/MtA conversion, [CertiK](https://www.certik.com/blog/threshold-cryptography-iii-binance-tss-libs-9-round-threshold-ecdsa)). Threshold *ECDH* is NOT that — the shared secret is a single linear combination of points, so it is **one request/response round** (coordinator asks each holder for `P_i`; holders reply; coordinator sums). No MtA, no multi-round MPC. This is why FROSTR can offer it at all, and why the latency story (§D-i) is "one relay round-trip," not "nine."

### C.2 What is REUSED (already on main / in the lanes)

- **kirby-custody FROST shares + keyset** (`frost-secp256k1-tr 3.0.0`, `coordinator.rs`/`guardian.rs`/`persist.rs`). Same shares that sign today are the shares that ECDH tomorrow — same `KeyPackage`, same Q, same 2-of-3.
- **The distributed-holder transport rail** (crossmachine-frost lane): `HolderTransportFactory`, the `RelayConn`/`ShareSink` seams (`relay_transport.rs:216`), NIP-44 share sealing, `CoordinatorAuthorizer` + fresh-lease + `ReplayGuard`. Threshold-ECDH is *the same shape of ceremony* as distributed signing (coordinator → holders → aggregate over a relay), so it rides this rail. **This is the single biggest reuse: the transport/auth/liveness plumbing for a quorum ceremony already exists or is being built for signing.**
- **The lease/quorum model** — a ceremony is authorized by the same fresh-lease gate that authorizes signing today. No new authorization concept.
- **The co-located-holders-today model** — in the near term the shares are on one host, so a "ceremony" is in-process/localhost (near-zero latency). Cross-machine is the same code with the live `NostrRelayConn` (crossmachine-frost step-6).

### C.3 What is NET-NEW

- **The threshold-ECDH ceremony itself.** kirby-custody is **signing-only today** — grep confirms zero `ecdh`/`encrypt`/`decrypt`/`nip44`/`shared-secret` in `crates/kirby-custody/src/`. `frost-secp256k1-tr` / `frost-core` 3.0.0 are FROST *signing* crates (RFC 9591 Schnorr); **they do not expose ECDH.** So the `P_i = λ_i·s_i·B` compute + aggregate is code we do not have. (See §D-ii/§F for build-vs-adopt.)
- **A `QuorumEcdh` provider** that the three call-sites below can call *instead of* `keys.secret_key()`-based NIP-44:

  1. **DM outbound** — `rail.rs::build_dm_reply_event` today = `EventBuilder::private_msg(dm_keys, to, text, [])`, and inbound `nerve.rs::run_dm_inbound` → `UnwrappedGift::from_gift_wrap(dm_keys, event)`. Both call nostr-sdk's NIP-17/NIP-44, which internally does ECDH with `dm_keys.secret_key()`. **Net-new:** a NIP-44 path that takes the conversation key from `QuorumEcdh::derive(peer)` instead of from a local secret. (nostr-sdk's `nip44` uses a `SecretKey`; we'd need a lower-level entry that accepts a precomputed conversation key, or a small local NIP-44 v2 impl over the quorum-derived point. The `engram.rs`/`relay_transport.rs` `nip44::decrypt_to_bytes(secret_key, pubkey, ct)` sites confirm the shape.)
  2. **NIP-60 wallet encrypt/decrypt** — the wallet self-encrypts its Cashu proofs to its own npub (NIP-44 to self) and decrypts on read. **Net-new:** self-directed `QuorumEcdh::derive(own_Q_pubkey)` → NIP-44. (Self-ECDH under a threshold key is still a quorum ceremony — the "peer" is Q's own pubkey.)
  3. **Spend authorization** — for P2PK-locked ecash, redeeming a proof needs a Schnorr signature under Q (we HAVE this via FROST signing) and/or the wallet-decrypt above. **The spend ceremony = the authorization** (§D-i treats this as a feature).
- **The beacon signer needs no change** — presence(31000)/lifecycle(9100)/lease are already Q-Schnorr-signed. This reshape *adds* ECDH to Q; it does not touch what Q already signs. (Non-DM agents' kind:1 fallback also unchanged.)

**Summary:** the *ceremony transport, auth, liveness, and the FROST shares* are reused; the *ECDH compute + a NIP-44-over-quorum-secret shim at 3 call-sites* is net-new. The beacon path is untouched.

---

## D. Costs — honest, with researched numbers (the keeper's 3 money lenses)

### (i) Per-operation quorum ceremony: FEATURE for spends, TAX for DM reads

**Ceremony shape (researched):** FROSTR/Bifrost's ECDH is a 3-phase RPC over nostr: request → peers respond with their contribution (`/ecdh/…/res`) → coordinator derives (`/ecdh/…/ret`) ([Bifrost README](https://github.com/frostr-org/bifrost); [bifrost-rs](https://github.com/FROSTR-ORG/bifrost-rs) exposes `EcdhPackage`/`initiate_ecdh`). That is **one round-trip** (coordinator↔holders), then a local Lagrange combine. Same shape as a FROST 2-round sign, and *lighter* than threshold ECDSA (§C.1). FROST signing itself is 2-round (commit + sign) or 1-round with preprocessed nonces ([RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)).

**Latency estimate (be explicit about assumptions):**

- **Co-located shares (today's model):** the "ceremony" is in-process or localhost loopback. Overhead is compute (a handful of secp256k1 point-mults) + local IPC = **sub-millisecond to low single-digit ms**. Negligible. As long as shares stay co-located, threshold-ECDH is effectively free — the DM-read tax below does not bite yet.
- **Cross-machine shares over nostr relays (the north star):** one round-trip = coordinator publishes request event → each holder subscribes/receives, computes, publishes response → coordinator receives. Each leg is a relay publish+propagate. A healthy relay round-trip is **"under 500ms is excellent, 500–1000ms good, 1000–2000ms acceptable"** ([NostrDeck relay-tester](https://www.nostrdeck.com/relay-tester.php)). A ceremony is ~2 relay legs (request out, responses back) plus holder compute, so a **realistic per-operation estimate is ~0.5–2s cross-machine, dominated entirely by relay propagation**, wider tail if a holder is on a slow/distant relay or momentarily offline (then you wait for it or re-request). Call it **~1s typical, multi-second tail** cross-machine.

**Why this is a FEATURE for spends:** a spend that requires a quorum ceremony *is* threshold authorization — a compromised single host cannot spend alone; it must convince the quorum. A ~1s latency on a Bitcoin spend is a non-issue (gudnuf: latency "not an issue right now") and buys exactly the property the custody thesis is about. **The ceremony-per-spend is the point.**

**Why this is a real TAX for DM reads:** every inbound DM must be **decrypted**, and decryption needs the conversation key = an ECDH derivation. If shares are cross-machine, *reading one DM* = one ~1s ceremony. A multi-turn conversation, or the backfill sweep (`run_dm_inbound` re-fetches stored gift wraps, #103), becomes N ceremonies. Reading 10 backfilled DMs on a fresh connection = ~10s of ceremonies if serialized (batchable — Bifrost has `ecdh_batch` — which helps a lot: one round-trip for many peers). **This is the sharpest cost of unification: DMs go from a local decrypt (~0ms) to a quorum ceremony.** It is tolerable now (co-located = free; low DM volume) but it is the thing that scales badly if/when shares are cross-machine and DM volume rises.

**Mitigations for the DM tax:** (a) keep shares co-located while DM volume is low (the ceremony is free until you distribute); (b) `ecdh_batch` the backfill (one ceremony for many senders); (c) **cache the conversation key per peer** after first derivation for the life of a conversation (the key is stable per (Q, peer) pair — derive once, reuse for the session; this collapses a multi-turn chat to ONE ceremony). Caching the *conversation key* (not the share) preserves the never-reconstruct property.

### (ii) FROSTR / threshold-ECDH maturity + the AUDIT BAR (hard gate for money)

**Maturity of the primitive we'd depend on:**

- **Bifrost (TS/JS)** is v2.0.2 (released 2026-01-25), actively developed, real usage via the frost2x browser extension and igloo clients ([FROSTR org](https://github.com/FROSTR-ORG/)). It has a documented threat model / SECURITY.md.
- **bifrost-rs (Rust)** is explicitly **"Beta … signer/router/bridge architecture only"** ([bifrost-rs README](https://github.com/FROSTR-ORG/bifrost-rs)). It *does* implement collaborative threshold ECDH (`EcdhPackage`, `initiate_ecdh`). Beta = pre-1.0, API-unstable, self-described.
- **Threshold-ECDH-on-secp256k1 in general** is well-understood algebra (§C.1), but the *specific* FROSTR construction + implementation is young.

**Audit status — this is the hard finding:**

- **There is NO completed independent third-party security audit of Bifrost or FROSTR.** Bifrost's SECURITY.md notes the *underlying* Noble libraries are "well-audited" (constant-time secp256k1) but makes **no claim of an audit of Bifrost itself** ([Bifrost SECURITY.md, as fetched](https://github.com/FROSTR-ORG/bifrost)).
- An audit is **on the roadmap, funded but not done.** OpenSats' twelfth wave of nostr grants funds FROSTR to, over the coming year, *"complete a security audit"* alongside `sign_psbt` and a NIP-46 bridge ([OpenSats twelfth wave](https://opensats.org/blog/twelfth-wave-of-nostr-grants)). "Will complete" = not complete.

**The audit bar we would need before real Bitcoin rides this:**

> Threshold custody of real Bitcoin requires the threshold-ECDH (and threshold-sign) implementation we ride — whether adopted Bifrost or our own kirby-custody code — to have a **completed independent third-party cryptography audit** (the class of firm that audits wallet/MPC code — e.g. Trail of Bits, Cure53, NCC, Kudelski, or equivalent), covering specifically the ECDH ceremony (contribution correctness, no share leakage across the ceremony, Lagrange-coefficient handling, nonce/domain separation, and the NIP-44 boundary). **No real Bitcoin custody should ride un-audited threshold-ECDH — ours or theirs.**

This bar is **outside our control and months-scale.** If we adopt Bifrost, we wait on *their* audit timeline (roadmapped, unspecified date). If we implement in kirby-custody, we own the audit — we must *commission and pay for* one before money rides it, and any bug we write is our Bitcoin at risk. **Either way, the money plane of this reshape is gated on a completed audit that does not exist today.** This is the single biggest schedule/risk item in the whole spec, and it is the reason §F phases money LAST.

Note the asymmetry the audit bar creates: **DMs and social do not carry the same bar.** A bug in DM threshold-ECDH leaks/breaks *messages*, not *money*. So threshold-ECDH-for-DMs can ship on a lighter bar (careful internal review + test vectors against NIP-44 known-answers) while the *same primitive for money* waits for the full audit. §F exploits this.

### (iii) Availability coupling: one key gates DM + spend + presence

Today the three planes **fail independently**: a wallet-key problem doesn't stop presence; a DM issue doesn't stop spending. **Unifying onto Q couples them: a quorum-availability failure = a fully-dark agent** — it cannot sign presence, cannot read/reply DMs, cannot spend or read its wallet balance. Everything routes through Q, so Q's quorum is a **single point of *liveness* failure** (note: not a single point of *theft* — that's the whole win — but the tradeoff is liveness for theft-resistance).

**Why this specifically bites Kirby:** the agent is **die-when-broke**, and the meter debits against wallet balance. If reading the wallet balance now requires a quorum ECDH ceremony and the quorum is unreachable (a holder machine down, a relay partition — and recall the memory: the fleet relay *is* a single strfry on turtle; a turtle outage already partitions the fleet), the agent may be unable to (a) prove it still has funds, (b) authorize the spend for its own compute, or (c) even sign a lifecycle event to say it's alive. A quorum outage could push a solvent agent into a *false* dark/dead state, or freeze a spend it needs to keep living. **Coupling money-liveness to quorum-liveness is a genuine new failure mode for a system whose core rule is "keep paying or die."**

**Cost + mitigations:**

- **Threshold tolerance is the first-line mitigation:** 2-of-3 already tolerates ONE holder down. The exposure is ≥2 holders unreachable, or a relay partition isolating the coordinator. So this is a "2 simultaneous failures" risk, not a "1 failure" risk — meaningfully better than a single bearer key's "1 machine dies = key gone."
- **Cache-forward for reads (as §D-i):** cache the wallet conversation key and last-known balance so a *read* doesn't need a live ceremony every tick; only *spends* (rarer, and where the ceremony is a feature) need a live quorum. This decouples routine liveness from the quorum.
- **Local sealed cache of wallet state** (already in the money-continuity plan: "publish to N relays + a local sealed cache + reconcile-on-boot") means balance is readable offline; only spend/re-encrypt needs the quorum.
- **Grace on the lease/meter:** widen the die-when-broke and lease-expiry grace windows so a transient quorum outage doesn't kill a solvent agent (the failover lease already has TTL/grace knobs).
- **Multi-relay for the ceremony transport** (money-continuity open decision #3): don't run the quorum's nostr transport over a single relay. A single-strfry-on-turtle transport for a money-gating ceremony is unacceptable; ceremony transport needs relay redundancy *before* money rides it.

**Net:** availability coupling is real and it is worst for die-when-broke liveness, but it is mitigable to "tolerates 1 holder + 1 relay down" with caching + local cache + grace + multi-relay. It must be **costed as a hard requirement, not an afterthought**: multi-relay ceremony transport + read-caching + grace windows are *prerequisites* for the money phase, not nice-to-haves.

---

## E. Migration — from 3 planes → unified threshold-Q

| Component | Today | After reshape | Disposition |
|---|---|---|---|
| SOCIAL key | canonical `dm_keys` (plain, #106) | Q (threshold Schnorr + threshold-ECDH) | **REPLACED** — posts/profile move to Q-Schnorr; DM encrypt/decrypt move to Q-ECDH |
| MONEY key | L1 bearer wallet key (#92) | Q (threshold-ECDH) | **REPLACED** — the single-point-of-theft key is eliminated; this is the thesis |
| reconstruct-on-lease keyring (money P2) | being built (Shamir seed, reassembled on leaseholder) | — | **DROPPED / RETIRED** — gudnuf's "never on one machine" explicitly rejects reassembly. Reconstruct-on-lease *does* reassemble the plain key on the authorized host at use-time (money-continuity design §"Security model": "reconstruct-on-lease by design REASSEMBLES the plain key on the authorized lease-holder"). Threshold-Q supersedes it: never reassembled, ever. |
| CONTROL key Q | FROST Q (Schnorr, co-located shares) | Q (Schnorr + ECDH, cross-machine shares) | **KEPT + EXTENDED** — gains ECDH; shares distributed via the crossmachine-frost rail |
| 31000→canonical binding tag (#106) | binds beacon → the separate canonical npub | binds beacon → Q (= the one npub) | **SIMPLIFIED** — the binding becomes trivial/self-referential; there is only one npub. Discovery still works; the `["social", hex]` tag now points at Q's pubkey. |
| DM actuator (`rail.rs` dm_keys path) | NIP-44 via local `dm_keys.secret_key()` | NIP-44 via `QuorumEcdh::derive` | **REWIRED** at the 3 call-sites (§C.3) |
| NIP-60 wallet crypto | NIP-44 self-encrypt via bearer key | NIP-44 self-encrypt via Q-ECDH | **REWIRED** |
| distributed-holder rail (crossmachine-frost) | being built for signing | carries ECDH ceremonies too | **REUSED / EXTENDED** |
| lease/quorum/fence | authorizes signing | authorizes every ceremony (sign + ECDH) | **REUSED** |

**What's reused:** FROST shares, the whole ceremony transport/auth/liveness rail, the lease model, the beacon-signing path. **What's retired:** two whole plain keys (social + money bearer) AND the reconstruct-on-lease keyring — a *net reduction* in key material and custody surface, not an addition. **What changes:** the DM + wallet crypto call-sites swap a local-secret NIP-44 for a quorum-ECDH NIP-44.

**Identity continuity during migration:** promoting an *existing* agent from 3 keys to Q means Q's npub becomes the agent's canonical npub. If the agent already posted under the #106 canonical key, that history is under a *different* key. Options: (a) new agents are born Q-unified (clean); existing agents keep their #106 canonical key until they choose to migrate (a kind:0 profile update + a signed statement linking old→Q, i.e. an NIP-05-style or a signed migration event). **Recommendation: born-unified for new agents; existing agents are grandfathered on #106 and migrate opportunistically.** Do NOT force-migrate live agents (churns npubs — the exact #106 pain).

---

## F. Build path — phased, do NOT big-bang money

The guiding rule: **DMs first (low blast radius, lighter audit bar), money last (behind the completed audit).** Each phase is independently valuable and independently shippable.

**Phase 0 — de-risk the primitive (spike, no production wiring).**
- Prototype threshold-ECDH in kirby-custody: implement `P_i = λ_i·s_i·B` + aggregate over the *existing* 2-of-3 keyset; prove the derived point/conversation-key **matches vanilla NIP-44** against known-answer vectors ([paulmillr/nip44 test vectors](https://github.com/paulmillr/nip44)). In-process only (co-located shares). Simultaneously evaluate **bifrost-rs** as an adopt candidate (build it, run its ECDH, measure). *Deliverable:* a go/no-go on Rust-reimpl vs Bifrost, and a working threshold-ECDH that produces NIP-44-correct secrets. **Gate:** correctness vs NIP-44 vectors.

**Phase 1 — threshold-ECDH for DMs (low-risk, ships on the lighter bar).**
- Wire `QuorumEcdh` into the DM call-sites (`build_dm_reply_event`, `run_dm_inbound`/`from_gift_wrap`). Add the conversation-key cache (§D-i mitigation). Keep shares co-located → ceremony is free → no DM-read tax yet.
- **Bar:** careful internal review + NIP-44 vectors + red-on-revert teeth (a DM still round-trips; the wrap is quorum-derived, not local-secret). **No money touched → no full audit needed to ship this.**
- *Delivers:* DMs under Q. Now SOCIAL is fully unified (posts+profile already Q-Schnorr-able; DM now Q-ECDH). Two of three planes on Q.

**Phase 2 — cross-machine share distribution (the "no human holds" enabler, non-money).**
- Land the crossmachine-frost live transport (`NostrRelayConn`, step-6) so signing AND DM-ECDH run over distributed holders. Add **multi-relay ceremony transport** (§D-iii) and measure real cross-machine ceremony latency (validate the ~1s estimate). Tune the DM cache + batch.
- **Bar:** live 2-machine proof (already the crossmachine-frost gate) + the availability mitigations (grace windows, multi-relay). **Still no money → the audit bar hasn't bound yet.**
- *Delivers:* the honest right to say "a key no human holds" for *identity + DMs* (money still on the old key at this point — be precise in claims).

**Phase 3 — NIP-60 wallet under Q (GATED on the completed audit).**
- Only after a **completed independent third-party audit** of the threshold-ECDH+sign implementation we ride (§D-ii). Then: rewire NIP-60 encrypt/decrypt + spend authorization to Q-ECDH/Q-sign; retire the L1 bearer key AND reconstruct-on-lease; the meter/treasury read via cached balance, spends via the quorum ceremony.
- **Bar:** completed audit + the §D-iii money-liveness prerequisites (multi-relay transport, read-caching, grace) proven. **This is the phase that fulfills the thesis** — and the phase that must not be rushed.
- *Delivers:* Bitcoin (ecash today; the thesis generalizes to on-chain later) under a threshold key no human holds.

**Sequencing note:** Phases 0–2 have *no dependency on the audit* and deliver real value (unified social identity, distributed DMs). They also *de-risk the exact primitive* money will later ride — by the time Phase 3's audit completes, threshold-ECDH will have been in production for DMs for a while, which is itself evidence for the auditors and for us. **This is the strongest argument for the phasing: DMs are the paid-for, low-stakes proving ground for the money primitive.**

---

## G. Recommendation + open decisions for gudnuf

### Build recommendation: implement threshold-ECDH in kirby-custody (Rust), do NOT adopt Bifrost

**Reasoning (honest, both sides):**

- **Against adopting Bifrost:** it is **TypeScript/JS**. A Rust node adopting it means either (a) a **JS sidecar** the kirby-node daemon talks to (a second runtime, a second process to supervise/secure, an IPC boundary carrying key-ceremony traffic — operational and attack surface), or (b) **FFI**, which for a JS lib is impractical. bifrost-rs (the Rust port) exists but is **self-described Beta, "signer/router/bridge only,"** pre-1.0, API-unstable — adopting it coupled our money custody to an external Beta crate's release + audit timeline we don't control.
- **For implementing in kirby-custody:** the ECDH construction is **small and well-understood** (§C.1 — one linear combination of points; far simpler than the FROST *signing* we already ship, and *far* simpler than threshold ECDSA). We already own the shares, the keyset, and the ceremony transport. It's additive to a crate we control. The net-new surface is genuinely modest: the point-contribution compute + a NIP-44-over-quorum-secret shim.
- **The catch (state it):** implementing our own crypto means **we own the audit and the bugs**. That is the price of control. But we would need an audit *anyway* to put real money on Bifrost too (its audit isn't done either), so "adopt to avoid the audit" is a false economy — there is no un-audited path to real-money threshold custody, from anyone.
- **Hedge:** use Phase 0 to *evaluate bifrost-rs head-to-head* (build it, run its ECDH, read its code). If bifrost-rs turns out clean, mature-fast, and gets audited on a timeline that beats ours, revisit. But **plan for Rust-reimpl in kirby-custody**; treat Bifrost/bifrost-rs as the reference implementation + test-oracle + adopt-fallback, not the default dependency.

**Overall recommendation:** **GREEN to pursue the direction, on the phased plan, with money strictly gated behind a completed audit.** The thesis is real and worth it. Phases 0–2 (threshold-ECDH for DMs + distributed shares) are low-risk, high-value, and de-risk the money primitive — start there. Do NOT let the excitement of the headline pull money forward of its audit. And keep the current train (P1 #106, money P2, zero-config) running unchanged in the meantime.

### Top open decisions for gudnuf

1. **Money's audit gate — accept it, and whose audit?** Phase 3 (money under Q) *cannot* ship without a completed third-party audit — that's months and money, on our timeline if we reimpl, on FROSTR's if we adopt. **Decision:** commit to commissioning our own audit of kirby-custody's threshold-ECDH (control + our own schedule), OR wait on FROSTR's roadmapped audit (no control, unknown date) and adopt bifrost-rs? (Recommend: our own audit, our own Rust code — but only when Phases 0–2 have de-risked it.) *This is the decision that sets the money timeline.*

2. **The DM-read tax vs distribution — how soon do shares go cross-machine?** Co-located shares make threshold-ECDH free; distribution is what earns "no human holds" but imposes the ~1s-per-DM-read tax (mitigable via cache/batch, §D-i). **Decision:** distribute shares as soon as Phase 2 is ready (accept the DM tax + build the caching), or keep shares co-located longer (thesis stays partially unfulfilled, DMs stay free) and distribute only when a real second machine + multi-relay are ready? (Recommend: build the cache in Phase 1 so distribution in Phase 2 is painless; then distribute.)

3. **Availability coupling — is die-when-broke OK depending on quorum liveness?** Unifying onto Q means a quorum/relay outage can dark a solvent agent (§D-iii). Mitigable to "tolerates 1 holder + 1 relay down" with caching + local cache + grace + multi-relay — but those become *hard prerequisites* for the money phase. **Decision:** accept money-liveness ⟵ quorum-liveness coupling (with the mitigations as required infra), or keep a break-glass local fallback for the wallet (which would reintroduce a single-point key and dent the thesis)? (Recommend: accept the coupling, fund the mitigations, no break-glass single-key — the thesis is the point.)

*(Secondary, lower-stakes: migration policy for existing agents — recommend born-unified + grandfather #106, §E; and whether to retire reconstruct-on-lease now-in-plan or let money-build finish it as a stopgap that Phase 3 later removes — recommend let it finish only if it ships before Phase 3 starts, else skip the throwaway.)*

---

## Research sources

- FROSTR org + Bifrost (TS, v2.0.2, threshold ECDH `node.req.ecdh`, threat model): https://github.com/FROSTR-ORG/ · https://github.com/frostr-org/bifrost
- bifrost-rs (Rust, **Beta**, `EcdhPackage`/`initiate_ecdh`, collaborative threshold ECDH): https://github.com/FROSTR-ORG/bifrost-rs
- FROSTR security audit = roadmapped-not-done (OpenSats grant, "will complete a security audit"): https://opensats.org/blog/twelfth-wave-of-nostr-grants
- NIP-44 (ECDH → conversation key construction) + test vectors: https://nips.nostr.com/44 · https://github.com/paulmillr/nip44
- FROST round structure (2-round / 1-round-preprocessed), RFC 9591: https://www.rfc-editor.org/rfc/rfc9591.html · https://eprint.iacr.org/2020/852.pdf
- Threshold ECDH vs ECDSA weight (linearly-homomorphic point combine vs 9-round MtA): https://www.certik.com/blog/threshold-cryptography-iii-binance-tss-libs-9-round-threshold-ecdsa · https://eprint.iacr.org/2020/1390.pdf
- Nostr relay round-trip latency benchmarks (<500ms excellent … <2000ms acceptable): https://www.nostrdeck.com/relay-tester.php
- Kirby ground truth: `crates/kirby-custody/*` (signing-only; `frost-secp256k1-tr`/`frost-core` 3.0.0), `crates/kirby-node/src/rail.rs` (DM `private_msg`/`dm_keys`), `crates/kirby-node/src/nerve.rs` (`from_gift_wrap`/`run_dm_inbound`), `plans/kirby-npub-canonical-p1-20260701.md` (#106), `/srv/forge/plans/kirby-money-continuity-design-and-build-plan-20260630.md` (L1 bearer + reconstruct-on-lease), `CLAUDE.md` honest boundary.
