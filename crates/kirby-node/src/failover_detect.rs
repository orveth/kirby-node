//! AUTOMATIC FAILOVER DETECTION — the pure decision (resilience finding G-4, the NO-FAILOVER gap).
//!
//! ## The problem
//! A tenant agent is supervised on ONE node. If that node dies (crash, power loss, network
//! partition), its agent's relay-lease stops being heartbeated and ages past the TTL
//! ([`crate::relay_lease::LEASE_TTL_SECS`]) — the agent goes DARK and stays dark. Nothing on a
//! SURVIVING node currently notices and takes the agent over. G-4 closes that: a peer that has
//! been OBSERVING the fleet's leases (via [`crate::relay_lease::FleetLeaseObserver`]) detects a
//! lease that went stale and decides to take the agent over by claiming the next monotonic term.
//!
//! ## This chunk: the PURE decision ONLY
//! [`detect_takeovers`] is a PURE function over (a point-in-time observed-lease snapshot, this
//! node's id, the set of agents this node already hosts, `now`, the TTL, a `takeover_grace`, and a
//! per-agent grace-state map) returning a `Vec<`[`TakeoverVerdict`]`>`. No daemon wiring, no relay
//! I/O, no `claim`, no VM — fully deterministic over its inputs, so the load-bearing SAFETY
//! invariants run in-process as fast unit tests (mirroring the fence-test style in
//! [`crate::fleet_reconcile`] and `spawn.rs`). The async drain (folding relay leases into the
//! observer) and the ACTUAL takeover (`claim(term + 1)` against the live relay, single-winner-on-
//! race, fencing the revived) live in the WIRING, the NEXT chunk.
//!
//! ## The decision, per agent in the snapshot
//! An agent is a takeover CANDIDATE only if ALL hold:
//!  1. it is NOT in this node's hosted set (never take over an agent we already run), AND
//!  2. we have OBSERVED a lease for it at some point (it is IN the snapshot) — **absent ≠ stale**:
//!     an agent we have never seen is not a failure to recover, it is an agent we have no evidence
//!     exists; claiming it would be inventing one, AND
//!  3. its latest observed lease is PAST the TTL as of `now` (stale — its holder stopped
//!     heartbeating).
//!
//! A candidate becomes a [`TakeoverVerdict`] only after it has been CONTINUOUSLY stale for at least
//! `takeover_grace` (the GRACE WINDOW, tracked in `grace_state`): a brief blip that recovers
//! (stale -> fresh) within the grace window CLEARS the timer and yields no takeover. The verdict's
//! `beat_term` is the OBSERVED stale term `+ 1` (a monotonic fencing token that beats the lease we
//! actually saw — never our own last-known term, which could be staler or unrelated).
//!
//! ## THE OBSERVER-BLIND FAIL-SAFE (the critical safety invariant)
//! Before ANY per-agent reasoning, [`detect_takeovers`] checks whether this node has observed AT
//! LEAST ONE lease that is still FRESH within the TTL. If NOTHING is fresh, it emits ZERO verdicts
//! and stands down. Rationale: a node whose own relay link has dropped (e.g. the 55s keepalive-ping
//! self-kill the reconcile wiring deliberately disables — see `main.rs` /
//! `nerve::add_relay_no_ping`) stops receiving ALL lease events, so EVERY observed lease ages past
//! the TTL TOGETHER. That is indistinguishable, per-agent, from real peer deaths — but a
//! SIMULTANEOUS fleet-wide death is astronomically less likely than our own blindness. A blind node
//! that "failed over" every agent would MASS-FALSE-TAKE-OVER the entire fleet (double-spawning
//! everything, burning real money, forking every agent's identity). Standing down on total silence
//! is what prevents that. Even one fresh lease proves the link is delivering, so a stale peer
//! beside it is a genuine candidate.
//!
//! When the fail-safe trips, the grace map is left UNTOUCHED: a blind tick is not trustworthy
//! evidence of staleness, so it must not seed/advance grace timers (otherwise the instant the link
//! recovered, every agent would already have "aged out" its grace and be taken over at once).

use std::collections::BTreeMap;

use crate::lease::LeaseNodeId;
use crate::relay_lease::{ObservedLeaseRecord, LEASE_TTL_SECS};

/// THE TAKEOVER DECISION for one agent: which agent this node should take over, and the term to
/// beat it at. The wiring (next chunk) turns this into a `claim(beat_term)` against the live relay
/// — with the single-winner-on-race tiebreak + fence-the-revived that are explicitly OUT of this
/// pure chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakeoverVerdict {
    /// The agent whose lease went stale and should be taken over.
    pub agent_id: String,
    /// The term to claim the lease at: the OBSERVED stale term `+ 1` (a monotonic fencing token
    /// that beats the lease we actually saw). NOT this node's own last-known term.
    pub beat_term: u64,
}

/// Whether a lease issued at `issued_at` is STALE as of `now` for a given `ttl` (its TTL has
/// elapsed). Mirrors `relay_lease`'s private `is_stale` EXACTLY but takes the
/// TTL as a parameter so the detector reasons over the SAME boundary the fresh projection uses
/// while staying a pure, self-contained decision. A lease from the FUTURE (clock skew) is treated
/// as fresh (not stale), the safe direction (we do not take over an agent that looks fresh).
fn lease_is_stale(issued_at: u64, now: u64, ttl: u64) -> bool {
    now.saturating_sub(issued_at) > ttl
}

/// THE PURE FAILOVER-DETECTION DECISION (the unit-tested core). From a point-in-time observed-lease
/// `snapshot` (agent_id -> latest observed `{holder, term, issued_at}`, TTL-IGNORED — built by
/// [`crate::relay_lease::FleetLeaseObserver::observed_snapshot`]), decide which PEER agents THIS
/// node (`node_id`) should take over. `hosted` is the set of agents this node already runs (never
/// taken over). `now` + `ttl` judge staleness; `takeover_grace` is the continuous-staleness dwell
/// required before acting; `grace_state` (agent_id -> first-seen-stale `now`) is consulted AND
/// UPDATED in place so continuity is tracked across ticks.
///
/// Returns the agents to take over, each with `beat_term = observed_stale_term + 1`.
///
/// ## Order of reasoning (the safety invariants, in priority order)
///  1. **Observer-blind fail-safe FIRST**: if NO observed lease is fresh within the TTL as of
///     `now`, return EMPTY and leave `grace_state` untouched (total silence is our blindness, not a
///     fleet-wide death — see the module doc).
///  2. Per agent in the snapshot, it is a CANDIDATE iff: not in `hosted` (i), observed at all —
///     guaranteed by snapshot membership, **absent ≠ stale** (ii), and past the TTL (iii).
///  3. A non-candidate (hosted, or fresh) has its `grace_state` entry CLEARED (a stale->fresh
///     transition resets the dwell). A candidate seeds its first-seen-stale time on the first tick
///     it is seen stale, then emits a [`TakeoverVerdict`] once `now - first_seen_stale >= grace`.
///
/// `grace_state` entries for agents NO LONGER in the snapshot are pruned (they cannot be candidates
/// anyway; pruning keeps the map from growing unbounded as agents churn).
///
// TODO(G-4 wiring): the NEXT chunk consumes these verdicts to `claim(beat_term)` against the live
// relay, resolves the single-winner-on-race tiebreak (two survivors both detecting the same stale
// lease) via the monotonic-term fence, and fences the revived original. None of that is here.
pub fn detect_takeovers(
    snapshot: &BTreeMap<String, ObservedLeaseRecord>,
    node_id: LeaseNodeId,
    hosted: &std::collections::HashSet<String>,
    now: u64,
    ttl: u64,
    takeover_grace: u64,
    grace_state: &mut BTreeMap<String, u64>,
) -> Vec<TakeoverVerdict> {
    // `node_id` does not gate the candidate test (we take over agents we do NOT `hosted`; a stale
    // lease that happens to name US is a remnant the reconcile path reaps, not a takeover target).
    // It is part of the signature because the wiring claims as THIS node and the NEXT chunk's
    // single-winner-on-race tiebreak references it. Bound here so the shape is wiring-ready.
    let _ = node_id;

    // (1) THE OBSERVER-BLIND FAIL-SAFE. If nothing is fresh, our relay link is (almost certainly)
    //     down: stand down entirely and do NOT let this untrustworthy tick poison the grace timers.
    let any_fresh = snapshot.values().any(|l| !lease_is_stale(l.issued_at, now, ttl));
    if !any_fresh {
        return Vec::new();
    }

    // We are NOT blind (at least one fresh lease proves the link delivers). Reason per agent, and
    // garbage-collect grace entries for agents that are no longer takeover-eligible this tick.
    let mut verdicts = Vec::new();
    let mut keep_stale: BTreeMap<String, u64> = BTreeMap::new();

    for (agent_id, lease) in snapshot {
        // (2.i) Never take over an agent THIS node already hosts.
        if hosted.contains(agent_id) {
            continue;
        }
        // (2.iii) Candidate only if the latest observed lease is STALE. (2.ii absent != stale is
        //         satisfied structurally: we only iterate agents PRESENT in the snapshot, i.e.
        //         actually observed.) A fresh lease is not a failure — skip it (and its grace entry
        //         is dropped below by not being carried into `keep_stale`, clearing the dwell).
        if !lease_is_stale(lease.issued_at, now, ttl) {
            continue;
        }

        // The agent is a candidate (peer, observed, stale). Track continuous staleness: the first
        // tick we see it stale seeds `now`; subsequent stale ticks carry that original time forward
        // so the dwell measures CONTINUOUS staleness (a fresh blip in between cleared it).
        let first_seen_stale = grace_state.get(agent_id).copied().unwrap_or(now);
        keep_stale.insert(agent_id.clone(), first_seen_stale);

        // (3) Emit a takeover only once it has been continuously stale for >= the grace window.
        if now.saturating_sub(first_seen_stale) >= takeover_grace {
            verdicts.push(TakeoverVerdict {
                agent_id: agent_id.clone(),
                // beat the OBSERVED stale term, never our own last-known term.
                beat_term: lease.term + 1,
            });
        }
    }

    // Replace the grace map with ONLY the agents still continuously stale this tick: any agent that
    // recovered (went fresh), is now hosted, or vanished from the snapshot has its dwell cleared.
    *grace_state = keep_stale;
    verdicts
}

/// The crate's default takeover grace window in seconds: how long a peer's lease must be
/// CONTINUOUSLY stale before this node takes it over. Layered ON TOP of the TTL (a lease is first
/// stale at `> ttl`, then must dwell stale this much longer), it absorbs brief relay propagation
/// blips / a holder that is slow to heartbeat without prematurely double-spawning. The wiring picks
/// the live value; kept here so the one place to retune the detector's dwell is next to its logic.
pub const DEFAULT_TAKEOVER_GRACE_SECS: u64 = LEASE_TTL_SECS;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Build an observed-lease snapshot from `(agent_id, holder, term, issued_at)` rows.
    fn snapshot(rows: &[(&str, LeaseNodeId, u64, u64)]) -> BTreeMap<String, ObservedLeaseRecord> {
        rows.iter()
            .map(|(a, holder, term, issued_at)| {
                (
                    a.to_string(),
                    ObservedLeaseRecord { holder_node_id: *holder, term: *term, issued_at: *issued_at },
                )
            })
            .collect()
    }

    fn hosted(agents: &[&str]) -> HashSet<String> {
        agents.iter().map(|s| s.to_string()).collect()
    }

    /// A grace window of 0 means "act as soon as stale" (no dwell) — used by the tests that isolate
    /// the candidate logic from the grace logic. The grace tests use a non-zero window.
    const NO_GRACE: u64 = 0;
    const TTL: u64 = LEASE_TTL_SECS;

    /// TEETH 1: a PEER lease past the TTL ⇒ exactly one `Takeover{observed_term + 1}`; the SAME
    /// lease within the TTL ⇒ none. The core stale-vs-fresh boundary.
    #[test]
    fn stale_peer_past_ttl_is_taken_over_within_ttl_is_not() {
        // alice held by node 2 at term 5, last heartbeat at issued_at=1000. We are node 7, host
        // nothing. A fresh peer `live` (heartbeat at 5000) is always present so the detector is NOT
        // observer-blind — this test isolates the stale/fresh boundary from the fail-safe (TEETH 5).
        let stale_alice = ("alice", 2, 5, 1000);
        let fresh_live = ("live", 9, 1, 5000);

        // WITHIN alice's TTL (now = issued_at + TTL): not stale ⇒ no takeover for alice.
        let snap = snapshot(&[("alice", 2, 5, 5000 - TTL), fresh_live]); // alice 30s old at now=5000
        let mut gs = BTreeMap::new();
        let v = detect_takeovers(&snap, 7, &hosted(&[]), 5000, TTL, NO_GRACE, &mut gs);
        assert!(v.is_empty(), "a lease within its TTL is fresh ⇒ no takeover (got {v:?})");

        // PAST alice's TTL: stale ⇒ exactly one takeover at the OBSERVED term + 1. live stays fresh.
        let snap = snapshot(&[stale_alice, fresh_live]);
        let mut gs = BTreeMap::new();
        let v = detect_takeovers(&snap, 7, &hosted(&[]), 1000 + TTL + 1, TTL, NO_GRACE, &mut gs);
        assert_eq!(
            v,
            vec![TakeoverVerdict { agent_id: "alice".to_string(), beat_term: 6 }],
            "a peer lease past its TTL ⇒ exactly one Takeover at observed_term(5)+1"
        );
    }

    /// TEETH 2: a fresh / heartbeating peer (its latest observed lease is well within the TTL) is
    /// NEVER a verdict, no matter how long the detector runs.
    #[test]
    fn fresh_heartbeating_peer_is_never_taken_over() {
        // bob heartbeats: latest observed issued_at keeps advancing, always within the TTL.
        let mut gs = BTreeMap::new();
        for tick in 0..10u64 {
            let now = 2000 + tick * 5; // every 5s
            let snap = snapshot(&[("bob", 3, 1, now)]); // issued_at == now ⇒ 0s old, fresh
            let v = detect_takeovers(&snap, 7, &hosted(&[]), now, TTL, NO_GRACE, &mut gs);
            assert!(v.is_empty(), "a heartbeating peer must never be taken over (tick {tick}, got {v:?})");
        }
    }

    /// TEETH 3: a SELF / hosted agent is skipped even when its observed lease is stale (a stale
    /// lease naming an agent we already run is a remnant the reconcile path reaps, not a takeover).
    #[test]
    fn self_hosted_agent_is_skipped_even_when_stale() {
        // We are node 7 and we HOST alice; her observed lease is stale. We must NOT take ourselves
        // over. carol (a stale peer we do NOT host) IS taken over, proving it is the `hosted` set —
        // not blindness — that suppresses alice. A fresh peer `live` keeps the detector non-blind so
        // the fail-safe is not what is doing the suppressing.
        let snap = snapshot(&[("alice", 7, 4, 1000), ("carol", 2, 9, 1000), ("live", 3, 1, 5000)]);
        let mut gs = BTreeMap::new();
        let v = detect_takeovers(&snap, 7, &hosted(&["alice"]), 5000, TTL, NO_GRACE, &mut gs);
        // alice (hosted) suppressed; live (fresh) skipped; only carol (stale peer) taken over.
        assert_eq!(
            v,
            vec![TakeoverVerdict { agent_id: "carol".to_string(), beat_term: 10 }],
            "a hosted agent must be skipped; a stale PEER must still be taken over (got {v:?})"
        );
    }

    /// TEETH 4: a NEVER-OBSERVED agent is NOT a candidate — absent ≠ stale. An agent we have no
    /// lease for at all is simply not in the snapshot, so it can never produce a verdict (we would
    /// be inventing an agent, not failing one over).
    #[test]
    fn never_observed_agent_is_not_a_candidate() {
        // Only `live` (fresh) is in the snapshot. "ghost" is asked about implicitly: it is absent.
        let snap = snapshot(&[("live", 3, 1, 5000)]);
        let mut gs = BTreeMap::new();
        let v = detect_takeovers(&snap, 7, &hosted(&[]), 5000, TTL, NO_GRACE, &mut gs);
        assert!(
            v.is_empty(),
            "a never-observed (absent) agent must NOT be taken over (absent ≠ stale); got {v:?}"
        );
    }

    /// TEETH 5 (THE OBSERVER-BLIND FAIL-SAFE — the regression guard for the ping-blindness hazard):
    /// when NO observed lease is fresh within the TTL, the detector emits ZERO verdicts even with
    /// MANY stale-looking agents. Total silence is the signature of OUR relay link being down, not a
    /// simultaneous fleet-wide death; a blind node that took everything over would mass-double-spawn
    /// the whole fleet. This is the invariant that keeps a blind node from doing catastrophic harm.
    #[test]
    fn observer_blind_no_fresh_lease_takes_over_nothing() {
        // Five peers, ALL stale (every lease aged well past the TTL — exactly what a dropped relay
        // link looks like: every event stopped arriving, so everything aged out together).
        let snap = snapshot(&[
            ("a", 2, 1, 1000),
            ("b", 3, 1, 1000),
            ("c", 4, 1, 1000),
            ("d", 5, 1, 1000),
            ("e", 6, 1, 1000),
        ]);
        let now = 1000 + TTL + 100; // every lease is stale
        let mut gs = BTreeMap::new();
        let v = detect_takeovers(&snap, 7, &hosted(&[]), now, TTL, NO_GRACE, &mut gs);
        assert!(
            v.is_empty(),
            "observer-blind (no fresh lease anywhere) ⇒ ZERO takeovers, never mass false-takeover (got {v:?})"
        );
        // And the blind tick must NOT have seeded grace timers (so a recovered link does not
        // immediately mass-take-over): the grace map stays empty.
        assert!(gs.is_empty(), "a blind tick must not seed grace timers");
    }

    /// TEETH 6a (GRACE — recovery clears it): a peer that goes stale then FRESH again within the
    /// grace window is NEVER taken over — the stale->fresh transition resets the dwell.
    #[test]
    fn grace_stale_then_fresh_within_grace_clears_no_takeover() {
        let grace = 20u64;
        let mut gs = BTreeMap::new();
        // `live` stays fresh throughout so the detector is never blind; we watch `flaky`.
        // Tick 1 (now=1031): flaky's last heartbeat was 1000 ⇒ 31s old > TTL(30) ⇒ stale. Seeds dwell.
        let snap = snapshot(&[("flaky", 2, 4, 1000), ("live", 9, 1, 1031)]);
        let v = detect_takeovers(&snap, 7, &hosted(&[]), 1031, TTL, grace, &mut gs);
        assert!(v.is_empty(), "first stale tick (dwell just started) ⇒ no takeover yet");
        assert_eq!(gs.get("flaky").copied(), Some(1031), "dwell seeded at first-seen-stale");

        // Tick 2 (now=1040, only 9s into the 20s dwell): flaky HEARTBEATS (fresh issued_at=1040).
        // The stale->fresh transition must CLEAR its dwell ⇒ no takeover, and the grace entry drops.
        let snap = snapshot(&[("flaky", 2, 4, 1040), ("live", 9, 1, 1040)]);
        let v = detect_takeovers(&snap, 7, &hosted(&[]), 1040, TTL, grace, &mut gs);
        assert!(v.is_empty(), "a recovery within grace ⇒ no takeover");
        assert!(!gs.contains_key("flaky"), "stale->fresh within grace CLEARS the dwell timer");

        // Tick 3 (now=1075): flaky's last heartbeat was 1040 ⇒ 35s old ⇒ stale AGAIN, but the dwell
        // restarts from NOW (1075), not the original 1031 — proving the clear was real.
        let snap = snapshot(&[("flaky", 2, 4, 1040), ("live", 9, 1, 1075)]);
        let v = detect_takeovers(&snap, 7, &hosted(&[]), 1075, TTL, grace, &mut gs);
        assert!(v.is_empty(), "freshly-stale-again dwell restarts ⇒ no immediate takeover");
        assert_eq!(gs.get("flaky").copied(), Some(1075), "the dwell restarted at the NEW first-seen-stale");
    }

    /// TEETH 6b (GRACE — stayed stale past it ⇒ takeover): a peer that is CONTINUOUSLY stale across
    /// ticks until it exceeds the grace window IS taken over, at the observed term + 1.
    #[test]
    fn grace_stayed_stale_past_grace_takes_over() {
        let grace = 20u64;
        let mut gs = BTreeMap::new();
        // Tick 1 (now=1031): dead's heartbeat (1000) is 31s old ⇒ stale. Dwell seeds at 1031. live keeps us non-blind.
        let snap = snapshot(&[("dead", 2, 5, 1000), ("live", 9, 1, 1031)]);
        let v = detect_takeovers(&snap, 7, &hosted(&[]), 1031, TTL, grace, &mut gs);
        assert!(v.is_empty(), "dwell just started ⇒ no takeover yet");

        // Tick 2 (now=1045, 14s into the 20s dwell): still stale (dead never heartbeats), not yet eligible.
        let snap = snapshot(&[("dead", 2, 5, 1000), ("live", 9, 1, 1045)]);
        let v = detect_takeovers(&snap, 7, &hosted(&[]), 1045, TTL, grace, &mut gs);
        assert!(v.is_empty(), "still inside the grace window ⇒ no takeover");
        assert_eq!(gs.get("dead").copied(), Some(1031), "the dwell start is carried forward (continuous staleness)");

        // Tick 3 (now=1051, 20s into the dwell ⇒ >= grace): NOW take it over, at observed term(5)+1.
        let snap = snapshot(&[("dead", 2, 5, 1000), ("live", 9, 1, 1051)]);
        let v = detect_takeovers(&snap, 7, &hosted(&[]), 1051, TTL, grace, &mut gs);
        assert_eq!(
            v,
            vec![TakeoverVerdict { agent_id: "dead".to_string(), beat_term: 6 }],
            "continuously stale past the grace window ⇒ takeover at observed_term+1 (got {v:?})"
        );
    }

    /// TEETH 7: `beat_term` is ALWAYS the OBSERVED term + 1 — it beats the lease we saw, regardless
    /// of magnitude, so the fencing token is monotonic over the real lease history (never our own
    /// last-known term).
    #[test]
    fn beat_term_is_observed_term_plus_one() {
        for observed_term in [0u64, 1, 41, 9999] {
            let snap = snapshot(&[("z", 2, observed_term, 1000), ("live", 9, 1, 5000)]);
            let mut gs = BTreeMap::new();
            let v = detect_takeovers(&snap, 7, &hosted(&[]), 1000 + TTL + 1, TTL, NO_GRACE, &mut gs);
            assert_eq!(
                v,
                vec![TakeoverVerdict { agent_id: "z".to_string(), beat_term: observed_term + 1 }],
                "beat_term must be the OBSERVED term ({observed_term}) + 1"
            );
        }
    }

    /// A stale lease that happens to name a node OTHER than us, beside a fresh one, is the canonical
    /// real-world case: one peer died, the rest are alive. Exactly that one stale peer is taken
    /// over, and the fresh peers are left alone. (Belt-and-braces over the unit teeth: proves the
    /// per-agent decision composes correctly on a mixed fleet.)
    #[test]
    fn mixed_fleet_takes_over_only_the_one_dead_peer() {
        // node 2 (alice) DIED at 1000; nodes 3/4 (bob/carol) are alive and heartbeating at 5000.
        let snap = snapshot(&[("alice", 2, 7, 1000), ("bob", 3, 2, 5000), ("carol", 4, 3, 5000)]);
        let mut gs = BTreeMap::new();
        let v = detect_takeovers(&snap, 9, &hosted(&[]), 5000, TTL, NO_GRACE, &mut gs);
        assert_eq!(
            v,
            vec![TakeoverVerdict { agent_id: "alice".to_string(), beat_term: 8 }],
            "only the single dead peer is taken over; the live ones are untouched (got {v:?})"
        );
    }
}
