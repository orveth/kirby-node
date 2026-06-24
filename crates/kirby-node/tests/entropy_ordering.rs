//! FAST UNGATED proof of the G7 entropy re-derive ORDERING (D-5 red-team gate),
//! the in-process companion to the HW-gated `entropy_resume.rs`.
//!
//! The HW test proves fingerprint DIVERGENCE across a real snapshot+resume. The
//! ORDERING piece (the genome must call `GetEntropyNonce` at the BUMPED generation
//! BEFORE its first post-resume act) is otherwise only exercised inside the gated
//! VM e2e. This drives the gateway service DIRECTLY (no VM, no image, no network)
//! through the daemon's own observer seam (`observe_events`), the SAME stream the
//! VM test reads, and asserts the post-resume event sequence keyed on event KIND
//! and the issued GENERATION (never wall-clock). A negative-control models a genome
//! that acts before re-deriving at the bumped generation and shows the assertion
//! catches it.

use std::sync::Arc;

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::rail::MockRail;
use kirby_node::treasury::Treasury;
use kirby_proto::node_gateway_server::NodeGateway;
use kirby_proto::{Event, EntropyRequest, SessionRequest};

/// Build a gateway with an attached event observer, mirroring the daemon's boot
/// wiring (the observer is the diagnostic stream the genome's ReportEvents and the
/// synthetic entropy_nonce_call both flow through).
fn gateway_with_observer() -> (GatewayService, tokio::sync::mpsc::UnboundedReceiver<Event>) {
    let treasury = Treasury::open_temporary(1_000_000).expect("open temporary treasury");
    let session = Session {
        task_descriptor: "entropy-ordering".into(),
        budget_sats: 1_000_000,
        allowlisted_destinations: vec!["mint.test.local".to_string()],
    };
    let mut svc = GatewayService::new(treasury, Arc::new(MockRail::new()), session);
    let rx = svc.observe_events();
    (svc, rx)
}

/// Drain every event currently buffered on the observer into a Vec (kind, generation).
/// `generation` is parsed from an `entropy_nonce_call` detail (`generation=N`) and is
/// `None` for any other event. The drain is non-blocking: the gateway feeds the
/// observer synchronously inside each RPC, so by the time the awaited RPC returns its
/// event is already queued.
fn drain(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>) -> Vec<(String, Option<u64>)> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        let generation = event
            .detail
            .split_whitespace()
            .find_map(|t| t.strip_prefix("generation="))
            .and_then(|s| s.parse::<u64>().ok());
        out.push((event.kind, generation));
    }
    out
}

/// G7 ORDERING (correct genome): after a resume (the daemon bumps the VMGenID
/// generation), a correct genome fetches the session context, then re-derives its
/// entropy by calling GetEntropyNonce at the BUMPED generation, THEN reports its
/// first post-resume act (a heartbeat). The observed sequence, keyed on event kind
/// and the issued generation, must be:
///   GetSessionContext (implicit, no event) -> entropy_nonce_call(gen == post-resume)
///   -> first heartbeat. The entropy call must precede the heartbeat AND be tagged
/// with the post-resume generation, proving re-derive-before-act at the right gen.
#[tokio::test]
async fn g7_ordering_entropy_call_precedes_first_post_resume_act_at_bumped_generation() {
    let (svc, mut rx) = gateway_with_observer();

    // Pre-resume: the genome is at generation 0. (No assertion needed here; this is
    // the baseline the daemon resumes from.)
    let gen_pre = svc.vm_generation();
    assert_eq!(gen_pre, 0, "fresh gateway starts at generation 0");

    // RESUME: the daemon bumps the VMGenID generation on restore (the kernel CSPRNG
    // reseed signal). This is the host-side action, independent of the genome.
    let gen_post = svc.bump_generation();
    assert_eq!(gen_post, gen_pre + 1, "restore bumps the generation by exactly 1");

    // The correct genome's post-resume sequence:
    // 1. read the fresh session context (carries the bumped state).
    svc.get_session_context(tonic::Request::new(SessionRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
    }))
    .await
    .unwrap();
    // 2. re-derive entropy: GetEntropyNonce. The gateway feeds a synthetic
    //    entropy_nonce_call event tagged with the generation the nonce was issued at.
    let nonce = svc
        .get_entropy_nonce(tonic::Request::new(EntropyRequest {
            schema_version: kirby_proto::SCHEMA_VERSION,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        nonce.vm_generation, gen_post,
        "the issued nonce is tagged with the post-resume generation"
    );
    // 3. ACT: report the first post-resume heartbeat.
    svc.report_event(tonic::Request::new(Event {
        schema_version: kirby_proto::SCHEMA_VERSION,
        kind: "heartbeat".into(),
        detail: "post-resume act".into(),
    }))
    .await
    .unwrap();

    let seq = drain(&mut rx);

    // The entropy_nonce_call must appear, tagged with the POST-resume generation
    // (NOT the pre-resume one): the genome re-derived at the bumped generation.
    let entropy_idx = seq
        .iter()
        .position(|(kind, gen)| kind == "entropy_nonce_call" && *gen == Some(gen_post))
        .expect("an entropy_nonce_call tagged with the post-resume generation must be observed");

    // The first post-resume act (heartbeat) must appear.
    let heartbeat_idx = seq
        .iter()
        .position(|(kind, _)| kind == "heartbeat")
        .expect("the post-resume heartbeat act must be observed");

    // THE ORDERING INVARIANT: the entropy re-derive at the bumped generation lands
    // BEFORE the first post-resume act. A genome that signed/acted first would land
    // the heartbeat ahead of (or without) the bumped-generation entropy call.
    assert!(
        entropy_idx < heartbeat_idx,
        "GetEntropyNonce (at the post-resume generation) must precede the first post-resume act: \
         observed sequence {seq:?}"
    );

    // Belt-and-suspenders: there must be NO entropy_nonce_call tagged with the STALE
    // (pre-resume) generation in this post-resume window. Re-deriving at the old
    // generation would be the nonce-reuse the gate forbids.
    assert!(
        !seq.iter().any(|(kind, gen)| kind == "entropy_nonce_call" && *gen == Some(gen_pre)),
        "no entropy call may be tagged with the stale pre-resume generation: {seq:?}"
    );
}

/// G7 ORDERING NEGATIVE CONTROL: a genome that ACTS (reports its heartbeat) BEFORE
/// re-deriving entropy at the bumped generation violates the asserted ordering. This
/// proves the ordering assertion above has teeth: the SAME `entropy_idx < heartbeat_idx`
/// predicate that PASSES for the correct genome FAILS for this one. (The bumped-
/// generation entropy call here lands AFTER the act, the catastrophic re-use ordering.)
#[tokio::test]
async fn g7_ordering_negative_control_act_before_redrive_violates_ordering() {
    let (svc, mut rx) = gateway_with_observer();
    let gen_pre = svc.vm_generation();
    let gen_post = svc.bump_generation();
    assert_eq!(gen_post, gen_pre + 1);

    // The BROKEN genome's order: it ACTS first (heartbeat), THEN re-derives entropy.
    svc.report_event(tonic::Request::new(Event {
        schema_version: kirby_proto::SCHEMA_VERSION,
        kind: "heartbeat".into(),
        detail: "post-resume act BEFORE re-derive (broken)".into(),
    }))
    .await
    .unwrap();
    svc.get_entropy_nonce(tonic::Request::new(EntropyRequest {
        schema_version: kirby_proto::SCHEMA_VERSION,
    }))
    .await
    .unwrap();

    let seq = drain(&mut rx);

    let entropy_idx = seq
        .iter()
        .position(|(kind, gen)| kind == "entropy_nonce_call" && *gen == Some(gen_post))
        .expect("the broken genome still eventually calls GetEntropyNonce at the bumped generation");
    let heartbeat_idx = seq
        .iter()
        .position(|(kind, _)| kind == "heartbeat")
        .expect("the broken genome's heartbeat act is observed");

    // THE TEETH: the SAME ordering predicate that the correct genome SATISFIES is
    // VIOLATED here, because the act preceded the bumped-generation entropy re-derive.
    assert!(
        entropy_idx > heartbeat_idx,
        "the broken genome acted before re-deriving entropy at the bumped generation, so the \
         re-derive-before-act ordering does NOT hold (the violation the gate catches): {seq:?}"
    );
}
