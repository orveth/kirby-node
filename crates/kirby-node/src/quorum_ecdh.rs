//! `QuorumEcdh` — the DM/wallet-side threshold-ECDH provider (P1).
//!
//! Wraps the agent's co-located FROST keyset and derives NIP-44 conversation keys under
//! the group taproot key **Q** via the kirby-custody threshold-ECDH primitive
//! ([`kirby_custody::threshold_ecdh_tweaked_q`] + [`kirby_custody::nip44_conversation_key`]),
//! **without ever reconstructing the group secret** on any machine. The output is a
//! `nostr_sdk` [`ConversationKey`], which the NIP-17 seal/wrap (and later the NIP-60
//! wallet) feed straight into `nip44` — so the DM identity becomes Q, not a separate
//! plain `dm_keys`.
//!
//! Co-located shares (P1): the "ceremony" is in-process (sub-millisecond). The
//! cross-machine transport is P2; this provider's method surface is the seam it drops
//! into (a real ceremony makes `conversation_key` an async round-trip — the callers
//! already `.await` their DM work).
//!
//! ## Caching
//!
//! The (Q, target) ECDH is deterministic, so for a STABLE target — a DM peer's real key
//! (the NIP-17 seal layer) or Q's own key (the NIP-60 wallet self-encrypt) — the derived
//! conversation key can be cached to a single derivation ([`conversation_key`]). An
//! EPHEMERAL target — the per-message NIP-17 gift-wrap (kind:1059) key, which is unique
//! per message — must NOT be cached ([`conversation_key_uncached`]); caching it would
//! grow unbounded and buys nothing (it is never reused). Caching the conversation key (a
//! derived secret) — never a share — preserves the never-reconstruct property.
//!
//! [`conversation_key`]: QuorumEcdh::conversation_key
//! [`conversation_key_uncached`]: QuorumEcdh::conversation_key_uncached

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;
use nostr_sdk::nips::nip44::v2::ConversationKey;
use nostr_sdk::PublicKey;
use zeroize::Zeroizing;

use crate::quorum_signer::{CeremonyGate, MIN_SIGNERS};
use crate::remote_holder::{HolderTransportFactory, RemoteEcdhHolder};
use kirby_custody::guardian::{EcdhPurpose, EcdhRequest};

/// The threshold-ECDH provider for one agent's FROST group key Q. CO-LOCATED (P1, in-process
/// combine) or DISTRIBUTED (the self-decrypt round over remote holders via the co-sign hub).
pub struct QuorumEcdh {
    /// The share backend: co-located (all shares in-process) or distributed (remote holders).
    backend: EcdhBackend,
    /// The group verifying material — drives the BIP-341 tweak fold + the Q derivation, and (in
    /// the distributed path) the CANONICAL verifying shares each holder's DLEQ is checked against.
    pubkeys: PublicKeyPackage,
    /// The group threshold (min signers); the combine uses exactly this many shares.
    min_signers: usize,
    /// The agent's taproot Nostr identity Q (32-byte x-only) — the npub peers DM and the
    /// key the wallet self-encrypts to.
    q_xonly: [u8; 32],
    /// Per-target conversation-key cache for STABLE targets only (see the module docs). Holds
    /// derived conversation keys (never shares), each wrapped in [`Zeroizing`] so the memory root
    /// `K_self` is WIPED on drop — with distributed shares no single disk/RAM snapshot then holds
    /// enough to re-derive it. Only reached via [`Self::conversation_key`]; the ephemeral path never
    /// inserts, so this stays bounded by the number of distinct stable correspondents.
    cache: Mutex<HashMap<[u8; 32], Zeroizing<[u8; 32]>>>,
}

/// Where an agent's FROST shares live for the ECDH combine.
enum EcdhBackend {
    /// CO-LOCATED (P1): all 2-of-3 shares in-process. The Lagrange point-combine reads these; the
    /// group secret scalar is never formed. Byte-identical to the pre-distributed path.
    Colocated {
        /// The 2-of-3 secret shares held on this host.
        key_packages: Vec<KeyPackage>,
    },
    /// DISTRIBUTED: shares live on REMOTE holders reached through the co-sign hub factory. The
    /// self-decrypt round (B == Q) sends each holder a typed [`EcdhRequest`], receives its RAW
    /// `D_i` + DLEQ, verifies + aggregates — NO share is ever co-located. This is what makes the
    /// memory root cross-machine sovereign (1-of-2-of-3, not node-local).
    Distributed {
        /// The per-agent co-sign hub (also the ceremony-gate authority + the ECDH transport seam).
        factory: Arc<dyn HolderTransportFactory + Send + Sync>,
        /// `(FROST identifier u16, placement address)` for each holder; the coordinator applies λ
        /// over whichever responds (any-available), exactly like the distributed signer.
        holders: Vec<(u16, String)>,
        /// The PER-AGENT ceremony serializer (shared with signing): the boot self-ECDH ceremony and
        /// the startup signing burst run ONE AT A TIME over the shared holder transports.
        gate: CeremonyGate,
        /// A monotonic per-ceremony session id (distinct ECDH ceremonies never collide on the wire).
        next_session: AtomicU64,
    },
}

impl QuorumEcdh {
    /// Build a provider over the co-located keyset. Derives Q up front (and validates the
    /// keyset is coherent enough to do so).
    pub fn new(key_packages: Vec<KeyPackage>, pubkeys: PublicKeyPackage) -> anyhow::Result<Self> {
        let first = key_packages
            .first()
            .context("QuorumEcdh needs at least the threshold of shares")?;
        let min_signers = *first.min_signers() as usize;
        anyhow::ensure!(
            key_packages.len() >= min_signers,
            "QuorumEcdh has {} shares, below the threshold {}",
            key_packages.len(),
            min_signers
        );
        let q_xonly =
            kirby_custody::group_xonly_q(&pubkeys).map_err(|e| anyhow::anyhow!("derive group Q: {e}"))?;
        Ok(Self {
            backend: EcdhBackend::Colocated { key_packages },
            pubkeys,
            min_signers,
            q_xonly,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Build a DISTRIBUTED provider over REMOTE holders reached through the co-sign hub `factory`.
    /// `holders` is `(FROST identifier u16, placement address)` for each holder (the full roster;
    /// any-available selection picks a reachable `>=`-threshold subset per ceremony). The 2-of-3
    /// scheme fixes `min_signers` = [`MIN_SIGNERS`]. Derives Q from `pubkeys` and takes the agent's
    /// ONE ceremony gate from the factory so ECDH serializes against signing. NO share is held here.
    pub fn new_distributed(
        factory: Arc<dyn HolderTransportFactory + Send + Sync>,
        holders: Vec<(u16, String)>,
        pubkeys: PublicKeyPackage,
    ) -> anyhow::Result<Self> {
        let min_signers = MIN_SIGNERS as usize;
        anyhow::ensure!(
            holders.len() >= min_signers,
            "distributed QuorumEcdh has {} holders, below the threshold {}",
            holders.len(),
            min_signers
        );
        let q_xonly =
            kirby_custody::group_xonly_q(&pubkeys).map_err(|e| anyhow::anyhow!("derive group Q: {e}"))?;
        let gate = factory.ceremony_gate();
        Ok(Self {
            backend: EcdhBackend::Distributed {
                factory,
                holders,
                gate,
                // SEED the session counter with a random base (NOT 0): two independently-constructed
                // distributed providers over the SAME coordinator key must not both start at session
                // 0, or the holder's anti-replay guard would reject the second provider's first
                // ceremony as a duplicate (coordinator, session, round). Random 64-bit bases collide
                // with negligible probability; each provider still increments monotonically.
                next_session: AtomicU64::new(rand::random::<u64>()),
            },
            pubkeys,
            min_signers,
            q_xonly,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The agent's taproot Nostr identity Q as 32-byte x-only (the npub peers DM; the
    /// `#p` value the inbound subscription filters on).
    pub fn q_xonly(&self) -> [u8; 32] {
        self.q_xonly
    }

    /// Q as a `nostr_sdk::PublicKey`.
    pub fn q_public_key(&self) -> anyhow::Result<PublicKey> {
        PublicKey::from_slice(&self.q_xonly).context("group Q x-only -> nostr PublicKey")
    }

    /// Derive the raw 32-byte NIP-44 conversation key for (Q, target) via a single-round threshold
    /// ECDH under Q — CO-LOCATED (in-process combine) or DISTRIBUTED (the round over remote holders).
    /// The group secret is never reconstructed. Returned in [`Zeroizing`] (wiped on drop). No caching.
    fn derive_bytes(&self, target_xonly: &[u8; 32]) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        match &self.backend {
            EcdhBackend::Colocated { key_packages } => {
                // Exactly the threshold of shares — the well-tested combine path; any ≥-threshold
                // subset of ONE group reconstructs the same secret point.
                let refs: Vec<&KeyPackage> =
                    key_packages.iter().take(self.min_signers).collect();
                let shared =
                    kirby_custody::threshold_ecdh_tweaked_q(&refs, &self.pubkeys, target_xonly)
                        .map_err(|e| anyhow::anyhow!("threshold ECDH under Q: {e}"))?;
                let k = kirby_custody::nip44_conversation_key(&shared)
                    .map_err(|e| anyhow::anyhow!("NIP-44 conversation key: {e}"))?;
                Ok(Zeroizing::new(k))
            }
            EcdhBackend::Distributed { factory, holders, gate, next_session } => {
                self.derive_bytes_distributed(factory.as_ref(), holders, gate, next_session, target_xonly)
            }
        }
    }

    /// The DISTRIBUTED single-round ECDH ceremony: serialize against signing (the shared
    /// [`CeremonyGate`]), take a fresh session id, and drive the remote holders (any-available: try
    /// each until a `>=`-threshold set of contributions is collected). Each holder runs the ECDH
    /// membrane (self-decrypt only) and returns its RAW `D_i` + DLEQ; the coordinator verifies every
    /// DLEQ against the canonical `V_i` and aggregates ([`kirby_custody::aggregate_raw_contributions_tweaked_q`],
    /// fail-closed). NO share is ever co-located. Returns the NIP-44 conversation key in [`Zeroizing`].
    fn derive_bytes_distributed(
        &self,
        factory: &dyn HolderTransportFactory,
        holders: &[(u16, String)],
        gate: &CeremonyGate,
        next_session: &AtomicU64,
        target_xonly: &[u8; 32],
    ) -> anyhow::Result<Zeroizing<[u8; 32]>> {
        // SELF-DECRYPT ONLY: the distributed path (and its holder membrane) authorize ONLY B == Q.
        // A peer target (e.g. a DM correspondent's key) has NO distributed ECDH authorization yet
        // (the §6.1 open problem), so refuse it here with a clear error rather than emit a request
        // every holder will reject — fail-closed. Self-decrypt is all the memory plane needs, and
        // this keeps a distributed DM path (which needs peer keys) from silently booting-then-failing.
        if *target_xonly != self.q_xonly {
            anyhow::bail!(
                "distributed threshold-ECDH supports ONLY self-decrypt (target must be the agent's \
                 own Q); a peer target is not authorized on a distributed keystore (peer-DM ECDH is \
                 the deferred §6.1 design problem). Refusing (fail closed)."
            );
        }
        // Serialize this ceremony against signing (and any other ECDH) over the shared transports.
        let _guard = gate.enter();
        let session_id = next_session.fetch_add(1, Ordering::SeqCst);
        // The self-decrypt request. `signer_set` is the full attempted roster (the membrane checks
        // the holder is in it + it is >= threshold; the RAW contribution does not depend on it).
        let signer_set: BTreeSet<u16> = holders.iter().map(|(id, _)| *id).collect();
        let req = EcdhRequest {
            session_id,
            purpose: EcdhPurpose::SelfDecrypt,
            target_xonly: *target_xonly,
            signer_set,
        };
        // Any-available: collect verified contributions until we reach the threshold; a slow/down
        // holder is skipped (its Err), not fatal, exactly like the signer's any-available-2-of-3.
        let mut contributions: Vec<(Identifier, kirby_custody::EcdhContribution)> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        for (id_u16, address) in holders {
            if contributions.len() >= self.min_signers {
                break;
            }
            let transport = match factory.connect_ecdh(address, session_id) {
                Ok(t) => t,
                Err(e) => {
                    errors.push(format!("connect holder {id_u16}: {e}"));
                    continue;
                }
            };
            let proxy = RemoteEcdhHolder::new(*id_u16, transport);
            match proxy.contribute(session_id, &req) {
                Ok(c) => {
                    let id = Identifier::try_from(*id_u16)
                        .map_err(|e| anyhow::anyhow!("holder u16 {id_u16} -> Identifier: {e}"))?;
                    // VERIFY the DLEQ against the canonical V_i BEFORE counting this responder toward
                    // the threshold: a byzantine holder's bad D_i is skipped (like an unreachable
                    // one) so an honest-majority round still completes, instead of one bad share
                    // aborting it. (`aggregate_raw_contributions_tweaked_q` re-verifies as
                    // defense-in-depth, so a bad share can never be folded even if this is bypassed.)
                    match kirby_custody::verify_contribution(&self.pubkeys, &id, target_xonly, &c) {
                        Ok(()) => contributions.push((id, c)),
                        Err(e) => errors.push(format!("holder {id_u16} bad contribution: {e}")),
                    }
                }
                Err(e) => errors.push(format!("holder {id_u16}: {e}")),
            }
        }
        if contributions.len() < self.min_signers {
            anyhow::bail!(
                "distributed self-ECDH could not reach a quorum ({}/{} holders): {}",
                contributions.len(),
                self.min_signers,
                errors.join("; ")
            );
        }
        // The coordinator verifies each DLEQ against the canonical V_i + folds parity/tweak.
        let shared = kirby_custody::aggregate_raw_contributions_tweaked_q(
            &contributions,
            &self.pubkeys,
            self.min_signers as u16,
            target_xonly,
        )
        .map_err(|e| anyhow::anyhow!("aggregate distributed ECDH contributions: {e}"))?;
        let k = kirby_custody::nip44_conversation_key(&shared)
            .map_err(|e| anyhow::anyhow!("NIP-44 conversation key: {e}"))?;
        Ok(Zeroizing::new(k))
    }

    /// The NIP-44 `ConversationKey` for (Q, target), NOT cached. Use for an EPHEMERAL
    /// target — the per-message NIP-17 gift-wrap (kind:1059) key — which must never be
    /// cached (unique per message).
    pub fn conversation_key_uncached(&self, target: &PublicKey) -> anyhow::Result<ConversationKey> {
        // `*` copies the [u8; 32] out of the Zeroizing wrapper (the wrapper is dropped + wiped here);
        // the returned ConversationKey is nostr-sdk's own type (the live-host residual, irreducible).
        Ok(ConversationKey::new(*self.derive_bytes(&target.to_bytes())?))
    }

    /// The NIP-44 `ConversationKey` for (Q, target), CACHED per target. Use for a STABLE
    /// target — a DM peer's real key (the seal layer) or Q's own key (the wallet). The
    /// cached value is the derived conversation key, never a share, so caching preserves
    /// the never-reconstruct property.
    pub fn conversation_key(&self, target: &PublicKey) -> anyhow::Result<ConversationKey> {
        let t = target.to_bytes();
        if let Some(k) = self.cache.lock().expect("QuorumEcdh cache poisoned").get(&t) {
            // `**k`: &Zeroizing<[u8; 32]> -> [u8; 32] (Copy); the cached bytes stay Zeroizing-wrapped.
            return Ok(ConversationKey::new(**k));
        }
        let k = self.derive_bytes(&t)?;
        let ck = ConversationKey::new(*k);
        self.cache.lock().expect("QuorumEcdh cache poisoned").insert(t, k);
        Ok(ck)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::nips::nip44::v2::{decrypt_to_bytes, encrypt_to_bytes};
    use nostr_sdk::Keys;

    fn provider() -> QuorumEcdh {
        // A fresh co-located 2-of-3 keyset (OsRng — the provider is target-agnostic, so a
        // random keyset exercises it fully).
        let keyset = kirby_custody::generate_dealer_keyset(2, 3).expect("keygen");
        let kps: Vec<KeyPackage> = kirby_custody::key_packages(&keyset)
            .expect("key packages")
            .into_values()
            .collect();
        QuorumEcdh::new(kps, keyset.pubkeys).expect("provider")
    }

    /// The provider derives the SAME NIP-44 conversation key a real nostr peer computes
    /// against the agent's npub Q — and a NIP-44 payload round-trips between the two sides.
    /// This is the end-to-end proof that a peer DMing Q and the agent (via threshold ECDH)
    /// share one conversation key.
    #[test]
    fn provider_conv_key_matches_peer_and_roundtrips() {
        let qe = provider();
        let q_pub = qe.q_public_key().expect("Q pubkey");

        let peer = Keys::generate();
        // Agent side: threshold ECDH under Q against the peer's key.
        let ck_agent = qe.conversation_key(&peer.public_key()).expect("agent ck");
        // Peer side: ordinary NIP-44 ECDH against the agent's npub Q.
        let ck_peer = ConversationKey::derive(peer.secret_key(), &q_pub).expect("peer ck");
        assert_eq!(
            ck_agent.as_bytes(),
            ck_peer.as_bytes(),
            "agent (threshold ECDH under Q) and peer must derive the same conversation key"
        );

        // NIP-44 payload round-trips both directions under the shared key.
        let msg = b"kirby dm under Q";
        let ct = encrypt_to_bytes(&ck_agent, msg).expect("encrypt");
        assert_eq!(decrypt_to_bytes(&ck_peer, &ct).expect("peer decrypt"), msg);
        let ct2 = encrypt_to_bytes(&ck_peer, msg).expect("encrypt2");
        assert_eq!(decrypt_to_bytes(&ck_agent, &ct2).expect("agent decrypt"), msg);
    }

    /// The self-encrypt case (the NIP-60 wallet target = Q's own key) derives a valid
    /// conversation key and round-trips — the wallet can encrypt to itself under Q.
    #[test]
    fn self_encrypt_under_q_roundtrips() {
        let qe = provider();
        let q_pub = qe.q_public_key().expect("Q pubkey");
        let ck = qe.conversation_key(&q_pub).expect("self ck");
        let msg = b"wallet state under Q";
        let ct = encrypt_to_bytes(&ck, msg).expect("encrypt");
        assert_eq!(decrypt_to_bytes(&ck, &ct).expect("decrypt"), msg);
    }

    /// The cache is transparent: the cached and uncached derivations agree for a stable
    /// target, and a second (cache-hit) call returns the same key.
    #[test]
    fn cache_is_transparent() {
        let qe = provider();
        let peer = Keys::generate().public_key();
        let cached = qe.conversation_key(&peer).expect("cached");
        let again = qe.conversation_key(&peer).expect("cache hit");
        let uncached = qe.conversation_key_uncached(&peer).expect("uncached");
        assert_eq!(cached.as_bytes(), again.as_bytes(), "cache hit must match");
        assert_eq!(cached.as_bytes(), uncached.as_bytes(), "cached must match uncached derivation");
    }

    /// THE DISTRIBUTED-PROVIDER TOOTH: a `QuorumEcdh` in DISTRIBUTED mode (self-decrypt over three
    /// in-process `RemoteHolderServer`s via the fleet factory) derives the SAME `K_self` conversation
    /// key as the CO-LOCATED provider over the same keyset — proving the cross-machine ceremony
    /// (request → DLEQ-verified aggregate) is byte-equivalent to the in-process combine. A second
    /// call hits the Zeroizing cache.
    #[test]
    fn distributed_self_decrypt_matches_colocated() {
        let keyset = kirby_custody::generate_dealer_keyset(2, 3).expect("keygen");
        let kps: Vec<KeyPackage> = kirby_custody::key_packages(&keyset)
            .expect("key packages")
            .into_values()
            .collect();
        let colocated = QuorumEcdh::new(kps.clone(), keyset.pubkeys.clone()).expect("co-located");

        // Three in-process holder servers ("on other machines"), registered by placement address.
        let mut fleet = crate::remote_holder::InProcessHolderFleet::new();
        let mut roster: Vec<(u16, String)> = Vec::new();
        for kp in &kps {
            let server = Arc::new(crate::remote_holder::RemoteHolderServer::new(
                kp.clone(),
                keyset.pubkeys.clone(),
            ));
            let id = server.id();
            let address = format!("holder-{id}");
            fleet.register(address.clone(), server);
            roster.push((id, address));
        }
        let factory: Arc<dyn HolderTransportFactory + Send + Sync> = Arc::new(fleet);
        let distributed = QuorumEcdh::new_distributed(factory, roster, keyset.pubkeys.clone())
            .expect("distributed provider");

        // Self-decrypt (target == Q): both providers derive the same K_self.
        let q = colocated.q_public_key().expect("Q");
        let ck_co = colocated.conversation_key(&q).expect("co-located K_self");
        let ck_dist = distributed.conversation_key(&q).expect("distributed K_self");
        assert_eq!(
            ck_co.as_bytes(),
            ck_dist.as_bytes(),
            "distributed self-decrypt must derive the same K_self as co-located"
        );
        // Cache hit returns the same key (the Zeroizing cache is transparent).
        let again = distributed.conversation_key(&q).expect("cache hit");
        assert_eq!(again.as_bytes(), ck_dist.as_bytes(), "distributed cache hit must match");
        println!("DISTRIBUTED-QECDH PASS: distributed self-decrypt derives the same K_self as co-located (Zeroizing cache)");
    }

    // ---- codex adjudication teeth ----

    /// Build a distributed provider over 3 HONEST in-process holders.
    fn distributed_over_honest_fleet() -> QuorumEcdh {
        let keyset = kirby_custody::generate_dealer_keyset(2, 3).expect("keygen");
        let kps: Vec<KeyPackage> = kirby_custody::key_packages(&keyset)
            .expect("kps")
            .into_values()
            .collect();
        let mut fleet = crate::remote_holder::InProcessHolderFleet::new();
        let mut roster: Vec<(u16, String)> = Vec::new();
        for kp in &kps {
            let server = Arc::new(crate::remote_holder::RemoteHolderServer::new(
                kp.clone(),
                keyset.pubkeys.clone(),
            ));
            let id = server.id();
            let addr = format!("holder-{id}");
            fleet.register(addr.clone(), server);
            roster.push((id, addr));
        }
        let factory: Arc<dyn HolderTransportFactory + Send + Sync> = Arc::new(fleet);
        QuorumEcdh::new_distributed(factory, roster, keyset.pubkeys).expect("distributed")
    }

    /// codex HIGH adjudication: distributed threshold-ECDH is SELF-DECRYPT-ONLY. A PEER target (not
    /// Q) is refused fail-closed (naming self-decrypt), so a distributed DM path can never silently
    /// use it; the agent's own Q still derives. (Paired with the boot-time refusal of distributed
    /// dm_under_q in boot.rs.)
    #[test]
    fn distributed_ecdh_is_self_decrypt_only() {
        let provider = distributed_over_honest_fleet();
        let peer = Keys::generate().public_key();
        let res = provider.conversation_key(&peer);
        assert!(res.is_err(), "a peer target must be refused on a distributed provider, got Ok");
        let msg = format!("{:#}", res.unwrap_err());
        assert!(msg.contains("self-decrypt"), "the refusal must name self-decrypt-only: {msg}");
        // Self (Q) still derives.
        let q = provider.q_public_key().expect("Q");
        provider.conversation_key(&q).expect("self-decrypt (Q) must still work");
        println!("DISTRIBUTED-SELF-DECRYPT-ONLY PASS: a peer target is refused fail-closed; Q self-decrypt works");
    }

    /// A holder link that TAMPERS its ECDH contribution: replaces d_i with a valid-but-wrong point
    /// (keeping the original proof), so the coordinator's per-contribution DLEQ verify rejects it —
    /// modelling a byzantine holder the round must SKIP (not abort on).
    struct TamperingEcdhLink {
        inner: crate::remote_holder::InProcessHolderLink,
        wrong_d_i: kirby_custody::WirePoint,
    }
    impl crate::remote_holder::HolderTransport for TamperingEcdhLink {
        fn send(&self, event: kirby_custody::seam::CoSignEvent) -> anyhow::Result<()> {
            self.inner.send(event)
        }
        fn recv(&self) -> anyhow::Result<kirby_custody::seam::CoSignEvent> {
            let mut e = self.inner.recv()?;
            if e.round == crate::remote_holder::ROUND_ECDH_CONTRIBUTION {
                let mut c: kirby_custody::EcdhContribution = serde_json::from_slice(&e.payload)?;
                c.d_i = self.wrong_d_i; // a valid point, wrong for this holder's V -> DLEQ fails
                e.payload = serde_json::to_vec(&c)?;
            }
            Ok(e)
        }
    }

    /// A fleet where the holder at `byzantine_addr` is served over a [`TamperingEcdhLink`].
    struct ByzantineFleet {
        servers: HashMap<String, Arc<crate::remote_holder::RemoteHolderServer>>,
        byzantine_addr: String,
        wrong_d_i: kirby_custody::WirePoint,
        gate: CeremonyGate,
    }
    impl HolderTransportFactory for ByzantineFleet {
        fn connect(
            &self,
            address: &str,
        ) -> anyhow::Result<Box<dyn crate::remote_holder::HolderTransport + Send + Sync>> {
            let server = self
                .servers
                .get(address)
                .ok_or_else(|| anyhow::anyhow!("no holder at {address}"))?;
            let inner = crate::remote_holder::InProcessHolderLink::new(Arc::clone(server));
            if address == self.byzantine_addr {
                Ok(Box::new(TamperingEcdhLink { inner, wrong_d_i: self.wrong_d_i }))
            } else {
                Ok(Box::new(inner))
            }
        }
        fn ceremony_gate(&self) -> CeremonyGate {
            self.gate.clone()
        }
    }

    /// codex MED adjudication (any-available): a byzantine holder returning a bad D_i is SKIPPED (the
    /// coordinator's per-contribution DLEQ verify) so an honest-majority round still derives the
    /// CORRECT K_self — one bad share does not abort a round two honest holders can complete.
    #[test]
    fn distributed_self_decrypt_survives_one_byzantine_holder() {
        let keyset = kirby_custody::generate_dealer_keyset(2, 3).expect("keygen");
        let kps: Vec<KeyPackage> = kirby_custody::key_packages(&keyset)
            .expect("kps")
            .into_values()
            .collect();
        let q_xonly = kirby_custody::group_xonly_q(&keyset.pubkeys).expect("Q");
        let peer_q = kirby_custody::peer_point_from_xonly(&q_xonly).expect("peer Q");
        // A valid-but-wrong D for holder-1: holder-2's D (s_2·Q), which fails against V_1.
        let wrong = kirby_custody::holder_ecdh_raw_contribution(&kps[1], &peer_q)
            .expect("raw")
            .d_i;

        let mut servers = HashMap::new();
        let mut roster: Vec<(u16, String)> = Vec::new();
        let mut byzantine_addr = String::new();
        for (i, kp) in kps.iter().enumerate() {
            let server = Arc::new(crate::remote_holder::RemoteHolderServer::new(
                kp.clone(),
                keyset.pubkeys.clone(),
            ));
            let id = server.id();
            let addr = format!("holder-{id}");
            if i == 0 {
                byzantine_addr = addr.clone(); // holder-1 (tried first) is byzantine
            }
            servers.insert(addr.clone(), server);
            roster.push((id, addr));
        }
        let fleet = ByzantineFleet {
            servers,
            byzantine_addr,
            wrong_d_i: wrong,
            gate: CeremonyGate::new(),
        };
        let factory: Arc<dyn HolderTransportFactory + Send + Sync> = Arc::new(fleet);
        let distributed =
            QuorumEcdh::new_distributed(factory, roster, keyset.pubkeys.clone()).expect("distributed");

        // The co-located reference K_self.
        let colocated = QuorumEcdh::new(kps, keyset.pubkeys.clone()).expect("co-located");
        let q = colocated.q_public_key().expect("Q");
        let reference = colocated.conversation_key(&q).expect("ref");

        // Byzantine holder-1 is skipped; holders 2+3 carry the round -> the correct K_self.
        let derived = distributed
            .conversation_key(&q)
            .expect("round survives one byzantine holder");
        assert_eq!(
            derived.as_bytes(),
            reference.as_bytes(),
            "the surviving quorum must derive the correct K_self"
        );
        println!("DISTRIBUTED-BYZANTINE-SURVIVE PASS: a bad contribution is skipped; the honest majority derives K_self");
    }
}
