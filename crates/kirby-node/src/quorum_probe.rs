//! #49 (failover step 2, half 2): the BOUNDED QUORUM-PROBE admission gate.
//!
//! The pre-#49 takeover gate (`admit_takeover` gate (a)) asks "does THIS node hold ALL of the
//! agent's FROST shares locally?" ([`crate::keyset_provisioning::keystore_loadable_at`]). For a
//! CO-LOCATED keystore that is correct and stays UNCHANGED. But it is exactly why an identity has
//! never moved machines: a DISTRIBUTED survivor holds only ITS OWN share (one of three), so the
//! all-shares-local gate SKIPS it (`KeystoreNotLoadable`) even though it plus one reachable holder
//! could form the 2-of-3 quorum and sign the `term + 1` lease + voice.
//!
//! This module answers the RIGHT question for a distributed keystore: CAN THIS NODE ASSEMBLE A
//! QUORUM RIGHT NOW? -- this node's own share PLUS a bounded, authenticated liveness probe of the
//! other placement holders. It is consulted by the CALLER, which passes the resulting
//! [`QuorumReadiness`] into the (still pure, still I/O-free) [`crate::spawn::SpawnConsumer::admit_takeover`].
//!
//! FENCING (unchanged): the probe is READ-ONLY and runs BEFORE any claim. The 31002 lease CAS stays
//! the ONE single-writer fence (`admit_takeover` gate (d) + the read-after-write launch fence); a
//! slow probe only delays the admission DECISION -- it never holds or extends a fence, so it opens
//! no split-brain window.
//!
//! BOUNDED, FAIL-CLOSED: every holder gets its OWN short deadline and the probe as a whole gets an
//! overall deadline (both in SECONDS). It NEVER inherits the transport's ~110s half-open floor (2x
//! the 55s co-sign PING_INTERVAL; see the `#[ignore]`d `half_open` tooth in `relay_transport`): a
//! silently-dead holder socket surfaces at the probe's own [`tokio::time::timeout`], not at socket
//! death. Any ambiguity -- unreachable, timed out, or an unauthenticated / wrong-identifier reply --
//! is NOT counted toward the quorum. If the probe cannot PROVE >= MIN_SIGNERS live holders it fails
//! CLOSED (Skip), never adopts.
//!
//! HOLDER-AUTH ("for THIS Q", not just "something answered"): a holder answers a [`ROUND_PROBE`]
//! ping with a [`ROUND_PROBE_ACK`] whose reply-sender identity is the holder's FROST identifier. The
//! probe binds that to the EXACT placement entry it dialed (identifier + address), so only an
//! authenticated response from a holder in THIS agent's placement roster (which is Q-specific -- the
//! manifest sits beside this agent's group anchor) counts. NOTE on "same placement version": today a
//! keyset has ONE placement generation (no rotation yet), so the current roster IS the version and
//! sender-auth against it is the enforcement; a numeric, holder-ATTESTED placement version lands
//! with versioned provisioning (step 3), at which point the ack carries it and a stale-generation
//! holder is excluded. An absent/malformed local placement is [`QuorumReadiness::StalePlacement`].

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kirby_custody::seam::CoSignEvent;

use crate::quorum_signer::{identifier_to_u16, MIN_SIGNERS};
use crate::remote_holder::{
    coordinator_id, HolderTransportFactory, ROUND_PROBE, ROUND_PROBE_ACK,
};

/// The gate-(a) readiness verdict [`crate::spawn::SpawnConsumer::admit_takeover`] consumes. The
/// CALLER computes it -- co-located via the local-shares check, distributed via
/// [`can_assemble_quorum`] -- so the consumer stays a pure decision, free of keystore-path / relay
/// knowledge and unit-testable with no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumReadiness {
    /// This node can FROST-sign as the agent NOW: either it holds the full CO-LOCATED quorum, or a
    /// distributed probe proved >= [`MIN_SIGNERS`] live authenticated holders for this agent's Q
    /// (this node holding one of them). Gate (a) passes.
    CanSign,
    /// CO-LOCATED: the local keystore is absent/partial -- the existing `KeystoreNotLoadable` case
    /// (this node holds fewer than all shares and there is no placement to reach the rest).
    LocalNotLoadable,
    /// DISTRIBUTED: a placement is present but the bounded probe could NOT prove a live quorum
    /// (fewer than [`MIN_SIGNERS`] holders answered, authenticated, within the deadline). Fail-closed.
    QuorumUnreachable,
    /// DISTRIBUTED: the local placement is absent or malformed -- the holder roster cannot be
    /// trusted, so no probe is attempted. Fail-closed with a distinct reason.
    StalePlacement,
}

/// The outcome of probing ONE holder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The holder answered LIVE and authenticated as `identifier` (its reply-sender identity matched
    /// the placement entry the probe dialed).
    Live { identifier: u16 },
    /// The holder did not answer within its deadline (unreachable / silently-dead socket), or its
    /// reply failed the sender / round bind. Fail-closed: never counted toward the quorum.
    Unreachable,
}

/// The two deadlines that bound the probe. Both are in SECONDS -- never the ~110s half-open floor.
#[derive(Debug, Clone, Copy)]
pub struct ProbeDeadlines {
    /// The most time ANY single holder probe may take before it is abandoned as unreachable.
    pub per_holder: Duration,
    /// The most time the WHOLE probe (all holders) may take before it fails closed with whatever it
    /// has proven so far.
    pub overall: Duration,
}

impl ProbeDeadlines {
    /// A sane default: 3s per holder, 8s overall -- both far under the ~110s socket-death floor.
    pub fn seconds_scale() -> Self {
        Self { per_holder: Duration::from_secs(3), overall: Duration::from_secs(8) }
    }
}

/// The seam a [`can_assemble_quorum`] probe drives: a bounded, authenticated liveness query to ONE
/// holder. The production impl is [`RelayHolderProbe`] (over the co-sign transport factory); the
/// teeth drive scripted doubles. Generic (not `dyn`) so the future stays unboxed.
pub trait HolderQuorumProbe {
    /// Probe the holder the placement lists at `address` with FROST identifier `expected_identifier`
    /// for `agent_id`'s Q. Return [`ProbeOutcome::Live`] ONLY for an authenticated live response from
    /// THAT holder; anything else (unreachable, timeout, wrong sender) is [`ProbeOutcome::Unreachable`].
    /// `deadline` is this holder's OWN budget -- the impl must not wait on the ~110s half-open floor.
    fn probe(
        &self,
        address: &str,
        expected_identifier: u16,
        agent_id: &str,
        deadline: Duration,
    ) -> impl Future<Output = ProbeOutcome> + Send;
}

/// CAN THIS NODE ASSEMBLE THE AGENT'S QUORUM RIGHT NOW? -- this node's own share plus a bounded,
/// authenticated probe of the other placement holders. Returns [`QuorumReadiness::CanSign`] iff this
/// node holds its own share AND >= [`MIN_SIGNERS`] distinct holders (this node included) are proven
/// live+authenticated within the deadlines; otherwise [`QuorumReadiness::QuorumUnreachable`]
/// (fail-closed). `roster` is the FULL placement holder set (identifier, address); `self_identifier`
/// is the share THIS node holds and is skipped (never self-probed).
pub async fn can_assemble_quorum<P: HolderQuorumProbe>(
    agent_id: &str,
    self_identifier: u16,
    self_share_loadable: bool,
    roster: &[(u16, String)],
    deadlines: ProbeDeadlines,
    probe: &P,
) -> QuorumReadiness {
    // This node must hold ITS OWN share to be one of the quorum. If it cannot even load its own
    // share it cannot contribute a signature -- fail closed (never claim a takeover it cannot sign).
    if !self_share_loadable {
        return QuorumReadiness::QuorumUnreachable;
    }
    let need = MIN_SIGNERS as usize;
    // This node is one proven, authenticated holder (its own loadable share).
    let mut live = 1usize;
    let started = tokio::time::Instant::now();
    for (identifier, address) in roster {
        if *identifier == self_identifier {
            continue; // never probe self; the local share is already counted.
        }
        if live >= need {
            break; // quorum already provable -- stop (bounded work, no needless wire round-trips).
        }
        // OVERALL budget: never let the probe as a whole exceed `overall`. Fail-closed on whatever
        // has answered so far once the budget is spent.
        let elapsed = started.elapsed();
        if elapsed >= deadlines.overall {
            break;
        }
        // Each holder gets the SMALLER of its per-holder budget and the overall budget remaining --
        // its OWN bounded deadline, never the transport's ~110s half-open floor.
        let per = deadlines.per_holder.min(deadlines.overall - elapsed);
        match tokio::time::timeout(per, probe.probe(address, *identifier, agent_id, per)).await {
            // Counted ONLY for an authenticated live response from the EXACT holder we dialed.
            Ok(ProbeOutcome::Live { identifier: answered }) if answered == *identifier => {
                live += 1;
            }
            // Unreachable / half-open timeout / wrong-identifier / any transport error: NOT counted.
            // Fail-closed -- ambiguity never counts toward the quorum.
            _ => {}
        }
    }
    if live >= need {
        QuorumReadiness::CanSign
    } else {
        QuorumReadiness::QuorumUnreachable
    }
}

/// A monotonic probe session id (routing/echo correlation only -- a probe generates no nonce and is
/// not security-load-bearing; the sender-identity bind is).
fn next_probe_session() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// The PRODUCTION [`HolderQuorumProbe`]: it dials each holder through the SAME co-sign transport
/// factory the sign path uses (the per-agent hub) and does ONE bounded [`ROUND_PROBE`] round-trip.
/// The transport `send`/`recv` are synchronous, so the round-trip runs on a blocking thread; the
/// caller's [`tokio::time::timeout`] enforces the deadline (a stuck round-trip is abandoned, and its
/// blocking recv self-bounds at the transport's own wire timeout, never the ~110s socket floor).
///
/// The probe binds the reply to the expected holder: `round == ROUND_PROBE_ACK`, the echoed session
/// id, AND the reply-sender FROST identifier equals the dialed placement entry -- an authenticated
/// live response for THIS agent's Q, not merely "something on the relay answered".
pub struct RelayHolderProbe<'a> {
    factory: &'a dyn HolderTransportFactory,
}

impl<'a> RelayHolderProbe<'a> {
    pub fn new(factory: &'a dyn HolderTransportFactory) -> Self {
        Self { factory }
    }
}

impl HolderQuorumProbe for RelayHolderProbe<'_> {
    fn probe(
        &self,
        address: &str,
        expected_identifier: u16,
        _agent_id: &str,
        _deadline: Duration,
    ) -> impl Future<Output = ProbeOutcome> + Send {
        // Connect SYNCHRONOUSLY (borrowing the factory) BEFORE the async block, so the returned
        // future owns only its transport + Copy data and does not borrow `self` -- keeping it Send.
        // A connect failure (unreachable/unknown address) is fail-closed Unreachable.
        let connected = self.factory.connect(address);
        async move {
            let transport = match connected {
                Ok(t) => t,
                Err(_) => return ProbeOutcome::Unreachable,
            };
            let session_id = next_probe_session();
            let req = CoSignEvent {
                session_id,
                from: coordinator_id(),
                round: ROUND_PROBE,
                payload: Vec::new(),
            };
            // The blocking round-trip: send the ping, block for the ack. The caller's timeout bounds
            // how long we AWAIT this; the transport's own recv timeout bounds the detached thread.
            let join = tokio::task::spawn_blocking(move || {
                transport.send(req)?;
                let reply = transport.recv()?;
                anyhow::Ok(reply)
            });
            match join.await {
                Ok(Ok(reply))
                    if reply.round == ROUND_PROBE_ACK
                        && reply.session_id == session_id
                        && identifier_to_u16(&reply.from) == expected_identifier =>
                {
                    ProbeOutcome::Live { identifier: expected_identifier }
                }
                // Timeout-drop, join error, transport error, wrong round/session/sender: fail-closed.
                _ => ProbeOutcome::Unreachable,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;

    use kirby_custody::{generate_dealer_keyset, key_packages};
    use frost_secp256k1_tr::keys::KeyPackage;

    use crate::quorum_signer::CeremonyGate;
    use crate::remote_holder::{
        HolderTransport, InProcessHolderLink, RemoteHolderServer,
    };

    const AGENT: &str = "kirby-probe-test";

    // ---- Scripted probe double: models each holder's behavior WITHOUT any wire ----------------

    #[derive(Clone)]
    enum Behavior {
        Live,
        Unreachable,
        /// A silently-dead socket: never answers. Modeled by a sleep LONGER than any test deadline,
        /// so `can_assemble_quorum`'s own `timeout` is what returns (proving the deadline, not the
        /// socket, bounds the probe).
        HalfOpen,
    }

    struct ScriptedProbe {
        by_address: HashMap<String, Behavior>,
    }

    impl HolderQuorumProbe for ScriptedProbe {
        fn probe(
            &self,
            address: &str,
            expected_identifier: u16,
            _agent_id: &str,
            _deadline: Duration,
        ) -> impl Future<Output = ProbeOutcome> + Send {
            let behavior = self.by_address.get(address).cloned();
            async move {
                match behavior {
                    Some(Behavior::Live) => ProbeOutcome::Live { identifier: expected_identifier },
                    Some(Behavior::HalfOpen) => {
                        // Never answer within any test deadline; the caller's timeout must fire.
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        ProbeOutcome::Live { identifier: expected_identifier }
                    }
                    _ => ProbeOutcome::Unreachable,
                }
            }
        }
    }

    fn roster(entries: &[(u16, &str)]) -> Vec<(u16, String)> {
        entries.iter().map(|(id, a)| (*id, a.to_string())).collect()
    }

    fn generous() -> ProbeDeadlines {
        ProbeDeadlines { per_holder: Duration::from_secs(2), overall: Duration::from_secs(5) }
    }

    // ---- TOOTH 3: holder-down-quorum -----------------------------------------------------------

    /// 3-holder placement, ONE holder down: the probe proves the quorum with the live 2 (this node +
    /// one reachable holder) -> `CanSign`. The down holder is probed first (Unreachable, not counted)
    /// to exercise the fail-closed skip of an unreachable holder before the live one completes quorum.
    #[tokio::test]
    async fn tooth3_holder_down_still_assembles_quorum() {
        let probe = ScriptedProbe {
            by_address: HashMap::from([
                ("h2-down".to_string(), Behavior::Unreachable),
                ("h3-live".to_string(), Behavior::Live),
            ]),
        };
        // This node holds identifier 1; the roster lists the down holder before the live one.
        let roster = roster(&[(1, "h1-self"), (2, "h2-down"), (3, "h3-live")]);
        let readiness = can_assemble_quorum(AGENT, 1, true, &roster, generous(), &probe).await;
        assert_eq!(
            readiness,
            QuorumReadiness::CanSign,
            "self + one live holder (of 3, one down) must prove the 2-of-3 quorum"
        );
        println!("TOOTH-3 PASS: 3-holder placement with 1 down -> quorum proven with the live 2 (CanSign)");
    }

    /// The unreachable-quorum leg of the #49 fix at the PROBE layer: a survivor (1 local share) whose
    /// other holders are ALL unreachable cannot prove a second holder -> `QuorumUnreachable`
    /// (fail-closed). The admit_takeover mapping of this to `Skip` is proven in `spawn.rs` (Tooth-4).
    #[tokio::test]
    async fn one_local_share_with_unreachable_others_is_quorum_unreachable() {
        let probe = ScriptedProbe {
            by_address: HashMap::from([
                ("h2".to_string(), Behavior::Unreachable),
                ("h3".to_string(), Behavior::Unreachable),
            ]),
        };
        let roster = roster(&[(1, "self"), (2, "h2"), (3, "h3")]);
        let readiness = can_assemble_quorum(AGENT, 1, true, &roster, generous(), &probe).await;
        assert_eq!(
            readiness,
            QuorumReadiness::QuorumUnreachable,
            "1 local share + no reachable holder must fail closed"
        );

        // And a node that cannot even load its OWN share cannot contribute -> fail closed too.
        let readiness_no_self =
            can_assemble_quorum(AGENT, 1, false, &roster, generous(), &probe).await;
        assert_eq!(readiness_no_self, QuorumReadiness::QuorumUnreachable);
        println!("PROBE-UNREACHABLE PASS: 1 local share with unreachable others -> QuorumUnreachable (fail-closed)");
    }

    // ---- TOOTH 2: half-open-probe-deadline -----------------------------------------------------

    /// A probe against a holder behind a silently-dead socket returns within ITS OWN deadline (far
    /// under the ~110s half-open floor) and admission fails closed. Proves the probe does not inherit
    /// the transport's socket-death floor.
    #[tokio::test]
    async fn tooth2_half_open_holder_probe_is_deadline_bounded_fail_closed() {
        // Both other holders are silently dead; this node cannot prove a second live holder.
        let probe = ScriptedProbe {
            by_address: HashMap::from([
                ("h2".to_string(), Behavior::HalfOpen),
                ("h3".to_string(), Behavior::HalfOpen),
            ]),
        };
        let roster = roster(&[(1, "self"), (2, "h2"), (3, "h3")]);
        // Tight deadlines: 300ms per holder, 1s overall. The half-open holders each sleep 30s.
        let deadlines =
            ProbeDeadlines { per_holder: Duration::from_millis(300), overall: Duration::from_secs(1) };

        let start = Instant::now();
        let readiness = can_assemble_quorum(AGENT, 1, true, &roster, deadlines, &probe).await;
        let elapsed = start.elapsed();

        assert_eq!(
            readiness,
            QuorumReadiness::QuorumUnreachable,
            "a half-open holder must not be counted; admission fails closed"
        );
        // Well under the ~110s socket-death floor: bounded by the deadlines (<= ~2s with slack), not
        // by the 30s the double sleeps and nowhere near 110s.
        assert!(
            elapsed < Duration::from_secs(5),
            "the probe must return at its own deadline (got {elapsed:?}), never the ~110s floor"
        );
        println!(
            "TOOTH-2 PASS: half-open holder probe returned fail-closed in {elapsed:?} (<<110s socket floor)"
        );
    }

    // ---- WIRE teeth: the REAL RelayHolderProbe over real holder servers ------------------------

    fn three_kps() -> (Vec<KeyPackage>, kirby_custody::DealerKeyset) {
        let ks = generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen");
        let kps: Vec<KeyPackage> = key_packages(&ks).expect("key packages").into_values().collect();
        (kps, ks)
    }

    /// A holder link that NEVER answers (a silently-dead socket): `send` is accepted, `recv` blocks
    /// past any test deadline then errors (so the detached blocking thread does not leak forever).
    struct NeverAnswersLink;
    impl HolderTransport for NeverAnswersLink {
        fn send(&self, _event: CoSignEvent) -> anyhow::Result<()> {
            Ok(())
        }
        fn recv(&self) -> anyhow::Result<CoSignEvent> {
            std::thread::sleep(Duration::from_secs(3));
            anyhow::bail!("silently-dead holder socket (never answered)")
        }
    }

    /// A probe transport factory for the wire teeth: each address is either a LIVE holder (a real
    /// [`RemoteHolderServer`] over an [`InProcessHolderLink`]) or SILENT (a [`NeverAnswersLink`]).
    enum ProbeHolder {
        Live(Arc<RemoteHolderServer>),
        Silent,
    }
    struct ProbeFleet {
        holders: HashMap<String, ProbeHolder>,
        gate: CeremonyGate,
    }
    impl HolderTransportFactory for ProbeFleet {
        fn connect(&self, address: &str) -> anyhow::Result<Box<dyn HolderTransport + Send + Sync>> {
            match self.holders.get(address) {
                Some(ProbeHolder::Live(server)) => {
                    Ok(Box::new(InProcessHolderLink::new(Arc::clone(server))))
                }
                Some(ProbeHolder::Silent) => Ok(Box::new(NeverAnswersLink)),
                None => anyhow::bail!("no probe holder at {address:?}"),
            }
        }
        fn ceremony_gate(&self) -> CeremonyGate {
            self.gate.clone()
        }
    }

    /// The REAL [`RelayHolderProbe`] gets `Live` from a real holder server answering `ROUND_PROBE`
    /// (authenticated by the reply-sender identity), and drives `can_assemble_quorum` to `CanSign`.
    #[tokio::test]
    async fn wire_real_probe_gets_live_from_a_real_holder_server() {
        let (kps, ks) = three_kps();
        // A real holder server for identifier 2 (its own share), at address "h2".
        let server2 = Arc::new(RemoteHolderServer::new(kps[1].clone(), ks.pubkeys.clone()));
        let id2 = server2.id();
        let fleet = ProbeFleet {
            holders: HashMap::from([("h2".to_string(), ProbeHolder::Live(server2))]),
            gate: CeremonyGate::new(),
        };
        let probe = RelayHolderProbe::new(&fleet);

        // Directly: the real probe returns Live with the holder's authenticated identifier.
        let outcome = probe.probe("h2", id2, AGENT, Duration::from_secs(2)).await;
        assert_eq!(
            outcome,
            ProbeOutcome::Live { identifier: id2 },
            "the real probe must get an authenticated Live ack from a real holder server"
        );

        // Through can_assemble_quorum: this node (identifier 1) + the live holder 2 = CanSign.
        let roster = roster(&[(1, "self"), (id2, "h2")]);
        let readiness =
            can_assemble_quorum(AGENT, 1, true, &roster, generous(), &probe).await;
        assert_eq!(readiness, QuorumReadiness::CanSign);
        println!("WIRE-LIVE PASS: RelayHolderProbe got an authenticated Live ack from a real RemoteHolderServer");
    }

    /// The REAL [`RelayHolderProbe`] against a silently-dead holder returns `Unreachable` within the
    /// deadline (never the ~110s floor), and a wrong-sender ack is rejected (holder-auth).
    #[tokio::test]
    async fn wire_real_probe_half_open_and_wrong_sender_fail_closed() {
        let (kps, ks) = three_kps();

        // (a) A silently-dead holder: the real probe times out at the caller's deadline.
        let fleet_silent = ProbeFleet {
            holders: HashMap::from([("h2".to_string(), ProbeHolder::Silent)]),
            gate: CeremonyGate::new(),
        };
        let probe_silent = RelayHolderProbe::new(&fleet_silent);
        let roster_silent = roster(&[(1, "self"), (2, "h2"), (3, "h3-absent")]);
        let deadlines =
            ProbeDeadlines { per_holder: Duration::from_millis(400), overall: Duration::from_secs(1) };
        let start = Instant::now();
        let readiness = can_assemble_quorum(AGENT, 1, true, &roster_silent, deadlines, &probe_silent).await;
        let elapsed = start.elapsed();
        assert_eq!(readiness, QuorumReadiness::QuorumUnreachable);
        assert!(
            elapsed < Duration::from_secs(3),
            "the real probe must fail closed at its deadline (got {elapsed:?}), never ~110s"
        );

        // (b) Wrong-sender: the holder at "h2" is really identifier 2, but the placement claims it is
        //     identifier 3 -> the sender-identity bind rejects it (an authenticated response, but not
        //     for the dialed placement entry).
        let server2 = Arc::new(RemoteHolderServer::new(kps[1].clone(), ks.pubkeys.clone()));
        let fleet_spoof = ProbeFleet {
            holders: HashMap::from([("h2".to_string(), ProbeHolder::Live(server2))]),
            gate: CeremonyGate::new(),
        };
        let probe_spoof = RelayHolderProbe::new(&fleet_spoof);
        let wrong = probe_spoof.probe("h2", 3, AGENT, Duration::from_secs(2)).await;
        assert_eq!(
            wrong,
            ProbeOutcome::Unreachable,
            "a live ack whose sender identity != the dialed placement identifier must be rejected"
        );
        println!("WIRE-FAILCLOSED PASS: real probe fails closed on half-open ({elapsed:?}) and on wrong-sender");
    }
}
