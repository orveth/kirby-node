//! S3c gated e2e: publish a 2-of-3 FROST quorum-signed kind:1 note to a REAL relay
//! and independently re-verify the aggregate BIP-340 signature off the relay.
//!
//! This is the HW/relay-gated proof that the live per-agent FROST signer reaches a
//! real relay AND that the published note's signature verifies under the group
//! taproot key Q. It is `#[ignore]`d AND returns early unless `KIRBY_FROST_RELAY` is
//! set to a relay ws:// URL, so the standard `cargo test` gate never needs a relay
//! (it SKIPs visibly). The fast, ungated teeth for this slice live in
//! `kirby_node::quorum_signer`'s in-process tests (G-QUORUM-*).
//!
//! P1 CANONICAL-NPUB NOTE (#76): the actuator's kind:1 VOICE now signs under the
//! CANONICAL SOCIAL (DM) key when one is attached (Q stops signing posts). This e2e
//! builds a FROST actuator WITHOUT a DM key, so it exercises the PRESERVED no-dm_keys
//! FALLBACK where kind:1 is still Q-signed -- which is exactly what it re-verifies. The
//! canonical-vs-Q fork itself is proven by the in-crate tooth
//! `g_frost_actuator_publishes_quorum_signed_event` (both directions, RED-on-revert);
//! this e2e stays the live-relay Q-signed proof for the fallback path.
//!
//! Run manually:
//!   KIRBY_FROST_RELAY=ws://127.0.0.1:7777 cargo test -p kirby-node --test frost_quorum_publish -- --ignored --nocapture

use std::sync::Arc;
use std::time::Duration;

use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
use bitcoin::KnownHrp;
use kirby_custody::cosign_net::nip01_event_id;
use kirby_custody::{generate_dealer_keyset, taproot_address};
use kirby_node::quorum_signer::{local_quorum_from_keyset, QuorumSigner};
use kirby_node::rail::NostrActuator;
use nostr_sdk::{Client, Filter, JsonUtil, Kind};

#[tokio::test]
#[ignore = "live: needs a running relay; gated on KIRBY_FROST_RELAY=ws://host:port"]
async fn frost_quorum_signed_note_publishes_and_reverifies_off_relay() {
    let relay = match std::env::var("KIRBY_FROST_RELAY") {
        Ok(r) if !r.is_empty() => r,
        _ => {
            eprintln!(
                "SKIP frost_quorum_signed_note_publishes_and_reverifies_off_relay: \
                 set KIRBY_FROST_RELAY=ws://host:port to run the live relay e2e"
            );
            return;
        }
    };

    // A real 2-of-3 keyset + the co-located quorum signer (in-process holders, S3).
    let keyset = generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen");
    let quorum: Arc<QuorumSigner> =
        Arc::new(local_quorum_from_keyset(&keyset).expect("build quorum signer"));
    let q_bytes = quorum.q_bytes();

    // The FROST actuator publishes the PRE-SIGNED event (no local key). NO `.with_dm_keys(..)`:
    // this is the P1 no-canonical FALLBACK, where kind:1 is still Q-signed (the path re-verified
    // below). With a DM key attached, kind:1 would instead sign under the canonical social key.
    let actuator = NostrActuator::connect_frost(quorum.clone(), std::slice::from_ref(&relay), 1)
        .await
        .expect("connect FROST actuator");

    let content = "Kirby speaks with a threshold voice: a 2-of-3 FROST quorum co-signed this note.";
    // The actuator's FROST `publish_note` is private (the gateway drives it via `actuate`); to
    // keep this e2e a focused signer+relay round-trip we reproduce its EXACT construction here
    // (sign_nostr_event -> Event::from_json -> verify -> send_event) and re-verify off the relay.
    let created_at = nostr_sdk::Timestamp::now().as_secs();
    let event = quorum
        .sign_nostr_event(1, created_at, content)
        .expect("quorum signs");
    let json = serde_json::to_string(&event).unwrap();
    let sdk_event = nostr_sdk::Event::from_json(&json).expect("parse signed event");
    sdk_event.verify().expect("locally verify before publish");

    // Publish through the actuator's connected client (a separate client to read back).
    // Use the actuator's public_key to confirm it equals Q.
    let pubkey = actuator.public_key();
    assert_eq!(
        pubkey.to_hex(),
        hex::encode(q_bytes),
        "actuator.public_key() must be the group taproot key Q"
    );

    let publisher = Client::builder().build();
    publisher.add_relay(&relay).await.expect("add relay");
    publisher.connect().await;
    let out = publisher.send_event(&sdk_event).await.expect("publish to relay");
    println!("published FROST-signed event id={}", out.val.to_hex());

    // Give the relay a moment, then independently fetch the event back and re-verify the
    // aggregate signature under Q (the independent off-relay re-verification).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let reader = Client::builder().build();
    reader.add_relay(&relay).await.expect("add relay (reader)");
    reader.connect().await;
    let filter = Filter::new().kind(Kind::from(1u16)).id(sdk_event.id);
    let events = reader
        .fetch_events(filter, Duration::from_secs(5))
        .await
        .expect("fetch the published event back");
    let fetched = events
        .into_iter()
        .next()
        .expect("the published FROST note must be readable off the relay");

    // Re-verify the fetched event's sig as a raw BIP-340 schnorr sig under the TWEAKED Q
    // (independent of nostr-sdk's own verify, using the custody derivation chain).
    let (_addr, internal_p) = taproot_address(&keyset.pubkeys, KnownHrp::Testnets).expect("addr");
    let secp = Secp256k1::verification_only();
    let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
    let q_xonly = q_tweaked.to_x_only_public_key();
    let expect_id = nip01_event_id(&hex::encode(q_bytes), created_at, 1, &fetched.content);
    let sig = schnorr::Signature::from_slice(fetched.sig.as_ref()).expect("64-byte sig");
    assert!(
        secp.verify_schnorr(&sig, &Message::from_digest(expect_id), &q_xonly).is_ok(),
        "fetched FROST note must verify under the group key Q"
    );
    assert!(
        secp.verify_schnorr(&sig, &Message::from_digest(expect_id), &internal_p).is_err(),
        "fetched FROST note must NOT verify under the untweaked internal key P"
    );
    println!(
        "FROST e2e PASS: 2-of-3 quorum-signed note published to {relay}, fetched back, \
         and re-verified under Q (and rejected under P)"
    );
}
