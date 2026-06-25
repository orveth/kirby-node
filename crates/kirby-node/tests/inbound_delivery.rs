//! E2 teeth: the daemon-half INBOUND-DELIVERY pipeline (earn-loop Component 1).
//!
//! Inbound is a NEW ATTACKER-CONTROLLED ENTRY POINT: foreign relay events now enter the
//! genome (via a typed queue). The daemon is the trust boundary. These tests drive the
//! pipeline DIRECTLY (construct events with in-process nostr-sdk `Keys`, run
//! `verify_and_enqueue`, drain via the gateway `PollInbox` RPC method) -- no real relay,
//! no microVM -- so they are fast, deterministic, and in the standard gate.
//!
//! Coverage (the spec's required E2 teeth):
//!   - a FORGED-signature event is DROPPED (never enqueued, never drains) .. `forged_signature_is_dropped`
//!   - an OVERSIZED payload is DROPPED (not truncated) .................... `oversized_payload_is_dropped_not_truncated`
//!   - an UNRECOGNIZED kind is DROPPED (default-deny) .................... `unrecognized_kind_is_dropped`
//!   - the cursor is monotonic; ack_seq never re-delivers / never skips .. `cursor_is_monotonic_no_redeliver_no_skip`
//!   - a redial + re-poll does not re-deliver a consumed event .......... `redial_does_not_redeliver_consumed_events`
//!   - long-poll returns an EMPTY batch on the deadline ................. `long_poll_returns_empty_on_deadline`
//!   - long-poll wakes the instant an event lands ...................... `long_poll_wakes_on_enqueue`
//!   - want_kinds INTERSECT allowlist narrows (disallowed silently ignored) `want_kinds_intersect_allowlist_narrows`
//!   - inbound disabled (empty allowlist) delivers nothing ............. `empty_allowlist_disables_inbound`

use std::sync::Arc;
use std::time::Duration;

use kirby_node::gateway::{GatewayService, Session};
use kirby_node::nerve::{verify_and_enqueue, InboundQueue, MAX_INBOUND_PAYLOAD_BYTES};
use kirby_node::rail::MockRail;
use kirby_node::treasury::Treasury;
// PollInbox is a trait method; bring the trait into scope to call it on the service.
use kirby_proto::node_gateway_server::NodeGateway;
use kirby_proto::{InboundKind, InboxRequest};

use nostr_sdk::prelude::*;

/// A deterministic keypair from a single seed byte (matches the engram test idiom).
fn keys_from_byte(b: u8) -> Keys {
    let secret = SecretKey::from_slice(&[b; 32]).expect("32-byte secret");
    Keys::new(secret)
}

/// Build a VALID, signed NIP-90 job-request event (kind 5000, in the JOB_REQUEST range)
/// addressed to `recipient` (`#p`), authored by `author`, with `content` as the job input.
fn signed_job_request(author: &Keys, recipient: PublicKey, content: &str) -> Event {
    EventBuilder::new(Kind::from(5000u16), content)
        .tags([Tag::public_key(recipient)])
        .sign_with_keys(author)
        .expect("sign job request")
}

/// Build a signed event of an arbitrary kind (for the unrecognized-kind drop test).
fn signed_event_of_kind(author: &Keys, kind: u16, content: &str) -> Event {
    EventBuilder::new(Kind::from(kind), content)
        .sign_with_keys(author)
        .expect("sign event")
}

/// FORGE an event: sign a valid one, then RECONSTRUCT it with tampered content. The id was
/// computed over the ORIGINAL content, so `verify_id()` (inside `Event::verify`) fails --
/// exactly what a relay-injected / man-in-the-middle forgery looks like. We keep the
/// original id + sig (the attacker cannot recompute a valid sig) but swap the content.
fn forge_with_tampered_content(valid: &Event, tampered_content: &str) -> Event {
    Event::new(
        valid.id,
        valid.pubkey,
        valid.created_at,
        valid.kind,
        valid.tags.clone().to_vec(),
        tampered_content,
        valid.sig,
    )
}

/// A gateway wired with an inbound queue and an inbound allowlist of `kinds`. Returns the
/// service and the SAME queue handle a `run_inbound` task would feed (so the test plays the
/// producer). The treasury/rail are inert here (inbound never touches them).
fn inbound_gateway(kinds: Vec<InboundKind>) -> (GatewayService, InboundQueue) {
    inbound_gateway_with_cap(kinds, kirby_node::nerve::INBOUND_QUEUE_CAP)
}

fn inbound_gateway_with_cap(kinds: Vec<InboundKind>, cap: usize) -> (GatewayService, InboundQueue) {
    let treasury = Treasury::open_temporary(1_000).expect("open temporary treasury");
    let session = Session {
        task_descriptor: "inbound-test".into(),
        budget_sats: 1_000,
        allowlisted_destinations: Vec::new(),
        allowlisted_inbound_kinds: kinds,
    };
    let queue = InboundQueue::with_capacity(cap);
    let service = GatewayService::new(treasury, Arc::new(MockRail::new()), session)
        .with_inbound_queue(queue.clone());
    (service, queue)
}

/// Drain helper: a single non-blocking poll (wait_ms=0) for the full allowlisted set.
async fn poll_now(svc: &GatewayService, ack_seq: u64) -> Vec<kirby_proto::InboundEvent> {
    let resp = svc
        .poll_inbox(tonic::Request::new(InboxRequest {
            schema_version: kirby_proto::SCHEMA_VERSION,
            want_kinds: Vec::new(),
            ack_seq,
            wait_ms: 0,
        }))
        .await
        .expect("poll_inbox");
    resp.into_inner().events
}

// ---- E2: a forged-signature event is DROPPED ----

#[tokio::test]
async fn forged_signature_is_dropped() {
    let (svc, queue) = inbound_gateway(vec![InboundKind::JobRequest]);
    let author = keys_from_byte(1);
    let node = keys_from_byte(9);

    let valid = signed_job_request(&author, node.public_key(), "render this prompt");
    let forged = forge_with_tampered_content(&valid, "render THIS prompt instead (tampered)");

    // The forged event must NOT enqueue.
    assert_eq!(
        verify_and_enqueue(&queue, &forged),
        None,
        "a bad-signature event must be dropped, never enqueued"
    );
    assert!(queue.is_empty(), "the queue must hold nothing after a forged event");

    // And it never drains.
    let events = poll_now(&svc, 0).await;
    assert!(events.is_empty(), "a forged event must never reach the genome");

    // Sanity: the VALID twin DOES enqueue (so the drop is the forgery, not the harness).
    assert!(verify_and_enqueue(&queue, &valid).is_some());
    assert_eq!(poll_now(&svc, 0).await.len(), 1);
}

// ---- E2: an oversized payload is DROPPED (not truncated) ----

#[tokio::test]
async fn oversized_payload_is_dropped_not_truncated() {
    let (svc, queue) = inbound_gateway(vec![InboundKind::JobRequest]);
    let author = keys_from_byte(2);
    let node = keys_from_byte(9);

    // Exactly-at-cap content is accepted; one byte over is dropped.
    let at_cap = "a".repeat(MAX_INBOUND_PAYLOAD_BYTES);
    let over_cap = "b".repeat(MAX_INBOUND_PAYLOAD_BYTES + 1);

    let over = signed_job_request(&author, node.public_key(), &over_cap);
    assert_eq!(
        verify_and_enqueue(&queue, &over),
        None,
        "an oversized payload must be dropped"
    );
    assert!(queue.is_empty(), "nothing queued for an oversized payload");
    assert!(
        poll_now(&svc, 0).await.is_empty(),
        "an oversized event must never drain (and must NOT be truncated into a delivery)"
    );

    // The at-cap twin is accepted and delivered VERBATIM (proves we drop, not truncate).
    let ok = signed_job_request(&author, node.public_key(), &at_cap);
    assert!(verify_and_enqueue(&queue, &ok).is_some());
    let events = poll_now(&svc, 0).await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].payload.len(),
        MAX_INBOUND_PAYLOAD_BYTES,
        "the at-cap payload is delivered whole, never truncated"
    );
}

// ---- E2: an unrecognized kind is DROPPED (default-deny) ----

#[tokio::test]
async fn unrecognized_kind_is_dropped() {
    let (svc, queue) = inbound_gateway(vec![InboundKind::JobRequest]);
    let author = keys_from_byte(3);

    // kind 1 (a text note), kind 4999 (just below the NIP-90 range), kind 6000 (a job
    // RESULT, not a request): none map to an allowlisted InboundKind => all dropped.
    for kind in [1u16, 4_999, 6_000, 7_000, 30_000] {
        let ev = signed_event_of_kind(&author, kind, "noise");
        assert_eq!(
            verify_and_enqueue(&queue, &ev),
            None,
            "kind {kind} is not in the host allowlist; it must be dropped (default-deny)"
        );
    }
    assert!(queue.is_empty());
    assert!(poll_now(&svc, 0).await.is_empty());
}

// ---- E2: the cursor is monotonic -- ack_seq never re-delivers, never skips ----

#[tokio::test]
async fn cursor_is_monotonic_no_redeliver_no_skip() {
    let (svc, queue) = inbound_gateway(vec![InboundKind::JobRequest]);
    let author = keys_from_byte(4);
    let node = keys_from_byte(9);

    // Enqueue three jobs.
    for i in 0..3 {
        let ev = signed_job_request(&author, node.public_key(), &format!("job {i}"));
        assert!(verify_and_enqueue(&queue, &ev).is_some());
    }

    // First poll from ack_seq=0 returns all three, seqs 1,2,3, in order. The cursor only
    // ever ADVANCES in real operation, so we walk it forward (0 -> 1 -> 3).
    let batch = poll_now(&svc, 0).await;
    let seqs: Vec<u64> = batch.iter().map(|e| e.inbox_seq).collect();
    assert_eq!(seqs, vec![1, 2, 3], "monotonic, in-order, no skip");

    // The genome acks seq 1 (advances its cursor to 1): the next poll returns ONLY 2 and 3
    // (never 1 again -- no re-delivery -- and never skipping 2).
    let after_one = poll_now(&svc, 1).await;
    let seqs: Vec<u64> = after_one.iter().map(|e| e.inbox_seq).collect();
    assert_eq!(seqs, vec![2, 3]);

    // The genome acks through seq 3 (the high-water): re-polling returns NOTHING.
    assert!(
        poll_now(&svc, 3).await.is_empty(),
        "ack_seq at the high-water must not re-deliver"
    );

    // A brand-new event continues the monotone sequence (seq 4), never reusing 1..=3.
    let ev = signed_job_request(&author, node.public_key(), "job 3");
    assert!(verify_and_enqueue(&queue, &ev).is_some());
    let next = poll_now(&svc, 3).await;
    assert_eq!(next.iter().map(|e| e.inbox_seq).collect::<Vec<_>>(), vec![4]);
}

// ---- E2: a redial + re-poll does not re-deliver an already-consumed event ----

#[tokio::test]
async fn redial_does_not_redeliver_consumed_events() {
    // The genome holds its own ack_seq cursor; a redial is just a fresh poll at that cursor.
    // The queue's seq counter is monotone for its lifetime, so consumed seqs are never reused.
    let (svc, queue) = inbound_gateway(vec![InboundKind::JobRequest]);
    let author = keys_from_byte(5);
    let node = keys_from_byte(9);

    let ev = signed_job_request(&author, node.public_key(), "the one job");
    assert!(verify_and_enqueue(&queue, &ev).is_some());

    // Genome receives it (seq 1) on a first poll at ack_seq=0.
    let first = poll_now(&svc, 0).await;
    assert_eq!(first.len(), 1);
    let cursor = first.iter().map(|e| e.inbox_seq).max().unwrap();
    assert_eq!(cursor, 1);

    // A crash/redial BEFORE the genome advanced its cursor (still ack_seq=0) RE-DELIVERS the
    // event (at-least-once on the wire); the genome's own monotonic cursor dedupes it to
    // exactly-once. This is the spec's "at-least-once becomes exactly-once at the genome".
    let before_ack = poll_now(&svc, 0).await;
    assert_eq!(
        before_ack.iter().map(|e| e.inbox_seq).collect::<Vec<_>>(),
        vec![1],
        "a re-poll at the OLD cursor re-delivers (at-least-once); the genome dedupes via the cursor"
    );

    // Once the genome ADVANCES its saved cursor (acks seq 1), a redial + re-poll at the new
    // cursor must NOT re-deliver the consumed event (it is pruned).
    let after_redial = poll_now(&svc, cursor).await;
    assert!(
        after_redial.is_empty(),
        "a redial + re-poll at the saved (advanced) cursor must not re-deliver the consumed event"
    );
}

// ---- E2: long-poll returns an EMPTY batch on the deadline ----

#[tokio::test]
async fn long_poll_returns_empty_on_deadline() {
    let (svc, _queue) = inbound_gateway(vec![InboundKind::JobRequest]);
    let start = std::time::Instant::now();
    let resp = svc
        .poll_inbox(tonic::Request::new(InboxRequest {
            schema_version: kirby_proto::SCHEMA_VERSION,
            want_kinds: Vec::new(),
            ack_seq: 0,
            wait_ms: 50, // short deadline for the test
        }))
        .await
        .expect("poll_inbox")
        .into_inner();
    assert!(resp.events.is_empty(), "empty batch on the deadline");
    assert_eq!(resp.high_seq, 0, "high_seq is 0 on an empty batch (cursor unchanged)");
    assert!(
        start.elapsed() >= Duration::from_millis(45),
        "the poll held open for ~the deadline before returning empty"
    );
}

// ---- long-poll wakes the instant an event lands (latency, not just deadline) ----

#[tokio::test]
async fn long_poll_wakes_on_enqueue() {
    let (svc, queue) = inbound_gateway(vec![InboundKind::JobRequest]);
    let author = keys_from_byte(6);
    let node = keys_from_byte(9);

    // Park a long-poll with a generous deadline, then enqueue from another task.
    let producer = queue.clone();
    let feeder = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let ev = signed_job_request(&author, node.public_key(), "woke you up");
        verify_and_enqueue(&producer, &ev);
    });

    let start = std::time::Instant::now();
    let resp = svc
        .poll_inbox(tonic::Request::new(InboxRequest {
            schema_version: kirby_proto::SCHEMA_VERSION,
            want_kinds: Vec::new(),
            ack_seq: 0,
            wait_ms: 5_000, // far longer than the 20ms feed
        }))
        .await
        .expect("poll_inbox")
        .into_inner();
    feeder.await.unwrap();

    assert_eq!(resp.events.len(), 1, "the parked poll woke as soon as the event landed");
    assert_eq!(resp.high_seq, 1);
    assert!(
        start.elapsed() < Duration::from_millis(2_000),
        "the poll returned well before its 5s deadline (woke on enqueue, not on timeout)"
    );
}

// ---- E2: want_kinds INTERSECT allowlist narrows (disallowed silently ignored) ----

#[tokio::test]
async fn want_kinds_intersect_allowlist_narrows() {
    // The session allowlists ONLY JOB_REQUEST.
    let (svc, queue) = inbound_gateway(vec![InboundKind::JobRequest]);
    let author = keys_from_byte(7);
    let node = keys_from_byte(9);

    let ev = signed_job_request(&author, node.public_key(), "do the job");
    assert!(verify_and_enqueue(&queue, &ev).is_some());

    // A want for an ALLOWLISTED kind delivers.
    let resp = svc
        .poll_inbox(tonic::Request::new(InboxRequest {
            schema_version: kirby_proto::SCHEMA_VERSION,
            want_kinds: vec![InboundKind::JobRequest as i32],
            ack_seq: 0,
            wait_ms: 0,
        }))
        .await
        .expect("poll_inbox")
        .into_inner();
    assert_eq!(resp.events.len(), 1, "an allowlisted want delivers");
    assert_eq!(resp.events[0].kind, InboundKind::JobRequest as i32);

    // A want for a NON-allowlisted kind (MENTION, not in the session allowlist) is silently
    // ignored: the genome narrowed to a disallowed set, so it gets NOTHING (not an error, and
    // NOT a widening to the full allowlisted set).
    let resp = svc
        .poll_inbox(tonic::Request::new(InboxRequest {
            schema_version: kirby_proto::SCHEMA_VERSION,
            want_kinds: vec![InboundKind::Mention as i32],
            ack_seq: 0,
            wait_ms: 0,
        }))
        .await
        .expect("poll_inbox")
        .into_inner();
    assert!(
        resp.events.is_empty(),
        "a want_kind NOT in the allowlist is silently ignored; the genome cannot widen"
    );
}

// ---- inbound disabled (empty allowlist) delivers nothing, even with a queued event ----

#[tokio::test]
async fn empty_allowlist_disables_inbound() {
    // Inbound allowlist is EMPTY: the workload is not configured for inbound (default-deny).
    let (svc, queue) = inbound_gateway(Vec::new());
    let author = keys_from_byte(8);
    let node = keys_from_byte(9);

    // Even if the pipeline somehow queued an event, the gateway must deliver nothing.
    let ev = signed_job_request(&author, node.public_key(), "nobody is listening");
    let _ = verify_and_enqueue(&queue, &ev); // it WILL enqueue (the pipeline is allowlist-agnostic)

    // Default want (empty => "the full allowlisted set", which is empty here).
    assert!(
        poll_now(&svc, 0).await.is_empty(),
        "an empty inbound allowlist disables delivery (default-deny)"
    );

    // An explicit want for any kind also gets nothing.
    let resp = svc
        .poll_inbox(tonic::Request::new(InboxRequest {
            schema_version: kirby_proto::SCHEMA_VERSION,
            want_kinds: vec![InboundKind::JobRequest as i32],
            ack_seq: 0,
            wait_ms: 0,
        }))
        .await
        .expect("poll_inbox")
        .into_inner();
    assert!(resp.events.is_empty());
}
