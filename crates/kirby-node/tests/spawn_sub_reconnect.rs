//! TEETH for the spawn control-plane's relay-reconnect deafness (the 6-day-daemon bug):
//! the control plane subscribes to `KIND_KIRBY_SPAWN_REQUEST` (31003) + `KIND_KIRBY_LEASE`
//! (31002) ONCE at startup and then loops on `client.notifications()`. The node's outbound
//! presence beacon is timer-driven (re-published every tick), so it survives anything —
//! but the inbound subscription is armed exactly once. If it ever dies, the node looks
//! healthy while being permanently deaf to spawn requests.
//!
//! WHAT WAS ACTUALLY FOUND (investigated against nostr-sdk/nostr-relay-pool 0.44.1
//! source + proven live by these tests):
//!   * A clean relay kill/restart is RECOVERED by the pool itself: `post_connection`
//!     re-issues the REQ (`resubscribe()`), so plain reconnects were NOT the deafness.
//!     (`spawn_subscription_survives_relay_restart` passes even without the fix — kept as
//!     regression teeth over the wire path.)
//!   * The PERMANENT deafness is the CLOSED-removal path: if the relay answers a REQ with
//!     `CLOSED` carrying most machine-readable prefixes (`error:`, `invalid:`, `blocked:`,
//!     `unsupported:`, `restricted:`, ... or NO prefix), `nostr-relay-pool` REMOVES the
//!     subscription from its map (`handle_relay_message` -> `HandleClosedMsg::Remove`).
//!     From then on NO reconnect ever re-arms it — the resubscribe loop iterates an empty
//!     map. A relay that bounces and briefly rejects REQs while warming up (or applies a
//!     transient policy) kills the control-plane's only ear FOREVER, exactly matching the
//!     production forensics: presence kept beating, spawns were never claimed, restart
//!     fixed it.
//!
//! The fix is a belt-and-braces periodic re-arm at the CLIENT level
//! (`nerve::SubscriptionRearmer`, driven by a `tokio::select!` tick in every long-lived
//! subscribe-once loop: the spawn control-plane, the presence peer watch, the NIP-90
//! inbox, and the NIP-17 DM inbox): `subscribe_with_id` with the SAME id + filter
//! re-registers the subscription in the pool (recovering even the removed case) and
//! re-issues the REQ (idempotent on the relay: same REQ id replaces the old one). The
//! owner must retain the id + filter because the pool's `subscriptions()` view merely
//! aggregates the per-relay maps — after the CLOSED-removal the client itself no longer
//! remembers the subscription.
//!
//! All three tests drive the REAL wire path: a real in-process websocket relay
//! (`nostr-relay-builder`'s `LocalRelay`), subscribers built EXACTLY the way
//! `run_spawn_control_plane` / `run_dm_inbound` build their clients
//! (`nerve::add_relay_no_ping` + `subscribe` + `notifications()`), real kill/restart on
//! the same port, real 31003/31002/1059-shaped publishes.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nostr_relay_builder::builder::{PolicyResult, QueryPolicy, RelayBuilder};
use nostr_relay_builder::local::LocalRelay;
use nostr_sdk::prelude::*;
use nostr_sdk::RelayPoolNotification;

use kirby_node::nerve;
use kirby_proto::{KIND_KIRBY_LEASE, KIND_KIRBY_SPAWN_REQUEST};

/// Pick a free localhost port (bind :0, read it back, release).
fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind :0")
        .local_addr()
        .expect("local addr")
        .port()
}

/// A query policy that rejects every REQ while the shared flag is up — models a relay
/// that transiently refuses subscriptions (warming up after a restart, applying a
/// policy, shedding load). The rejection reaches the client as `CLOSED` with an
/// `error:` prefix, which is exactly the message that makes nostr-relay-pool 0.44
/// REMOVE the subscription permanently.
#[derive(Debug)]
struct RejectWhile(Arc<AtomicBool>);

impl QueryPolicy for RejectWhile {
    fn admit_query<'a>(
        &'a self,
        _query: &'a Filter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if self.0.load(Ordering::SeqCst) {
                PolicyResult::Reject("relay warming up".to_string())
            } else {
                PolicyResult::Accept
            }
        })
    }
}

/// Start a real in-process websocket relay on `port`. `rejecting` (shared, flippable)
/// drives the REQ-rejection policy; pass a fresh `false` flag for an always-accepting relay.
async fn start_relay(port: u16, rejecting: Arc<AtomicBool>) -> LocalRelay {
    let relay = LocalRelay::new(
        RelayBuilder::default()
            .addr(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .port(port)
            .query_policy(RejectWhile(rejecting)),
    );
    relay.run().await.expect("local relay runs");
    relay
}

/// Build the subscriber EXACTLY like `run_spawn_control_plane` builds its client:
/// throwaway keys, `add_relay_no_ping` (reconnect on, keepalive ping off), connect, one
/// subscribe on the spawn-request + lease filter. Returns (client, sub id, filter).
async fn control_plane_subscriber(url: &str) -> (Client, SubscriptionId, Filter) {
    let client = Client::builder().signer(Keys::generate()).build();
    nerve::add_relay_no_ping(&client, url)
        .await
        .expect("add relay");
    client.connect().await;
    wait_for_status(
        &client,
        url,
        RelayStatus::Connected,
        Duration::from_secs(10),
    )
    .await;
    let filter = Filter::new().kinds([
        Kind::from(KIND_KIRBY_SPAWN_REQUEST),
        Kind::from(KIND_KIRBY_LEASE),
    ]);
    let sub_id = client
        .subscribe(filter.clone(), None)
        .await
        .expect("subscribe")
        .val;
    (client, sub_id, filter)
}

/// Publish `event` from a fresh throwaway publisher client, returning its id. A fresh
/// client per publish means the publisher never depends on reconnect behavior — only
/// the SUBSCRIBER's ear is under test (in production the outbound side is timer-driven
/// and survives anything, which is exactly why the deaf node looked healthy).
async fn publish_event(url: &str, event: Event) -> EventId {
    let client = Client::builder().signer(Keys::generate()).build();
    client.add_relay(url).await.expect("publisher add relay");
    client.connect().await;
    wait_for_status(
        &client,
        url,
        RelayStatus::Connected,
        Duration::from_secs(10),
    )
    .await;
    let id = event.id;
    client.send_event(&event).await.expect("publish event");
    client.disconnect().await;
    id
}

/// A `kind`-shaped addressable event with a `d` tag (31003 spawn request / 31002 lease).
fn kind_d_event(kind: u16, agent_id: &str) -> Event {
    let keys = Keys::generate();
    EventBuilder::new(Kind::from(kind), "{}")
        .tags([Tag::parse(["d", agent_id]).expect("d tag")])
        .sign_with_keys(&keys)
        .expect("sign event")
}

/// A gift-wrap-shaped (kind:1059) event addressed (`#p`) to `to` — shaped like what the
/// NIP-17 DM inbox subscription matches (the DM trust boundary that unwraps/verifies it
/// is downstream of the subscription and out of scope here).
fn gift_wrap_shaped_event(to: &PublicKey) -> Event {
    let keys = Keys::generate();
    EventBuilder::new(Kind::GiftWrap, "ciphertext")
        .tags([Tag::public_key(*to)])
        .sign_with_keys(&keys)
        .expect("sign gift wrap")
}

/// Poll the client's relay status until it reaches `want` (or panic after `timeout`).
async fn wait_for_status(client: &Client, url: &str, want: RelayStatus, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let status = client
            .pool()
            .relay(url)
            .await
            .expect("relay registered in pool")
            .status();
        if status == want {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "relay {url} never reached {want:?} (stuck at {status:?})"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Poll until the pool has DROPPED the subscription (the CLOSED-removal under test), or
/// panic after `timeout`.
async fn wait_for_subscription_removed(
    client: &Client,
    url: &str,
    sub_id: &SubscriptionId,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let relay = client.pool().relay(url).await.expect("relay in pool");
        if relay.subscription(sub_id).await.is_none() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the pool never removed subscription {sub_id} after the relay's CLOSED"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Drain notifications until `want` arrives (true) or `timeout` elapses (false).
async fn recv_event(
    notifications: &mut tokio::sync::broadcast::Receiver<RelayPoolNotification>,
    want: EventId,
    timeout: Duration,
) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            match notifications.recv().await {
                Ok(RelayPoolNotification::Event { event, .. }) if event.id == want => return true,
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// THE TOOTH (the production deafness): a relay bounce where the relay briefly REJECTS
/// REQs while coming back (CLOSED with an `error:` prefix) makes nostr-relay-pool 0.44
/// REMOVE the subscription — after that, no reconnect ever re-arms it, and the node is
/// permanently deaf to BOTH kinds on this subscription: 31003 spawn requests (no spawn
/// is ever claimed) AND 31002 leases (the failover detector goes blind: every peer reads
/// as stale-or-invisible on a long-up daemon). The periodic re-arm
/// (`nerve::SubscriptionRearmer`, the control-plane's tick) is what recovers it.
#[tokio::test(flavor = "multi_thread")]
async fn spawn_subscription_survives_req_rejecting_relay_bounce() {
    let port = free_port();
    let url = format!("ws://127.0.0.1:{port}");
    let rejecting = Arc::new(AtomicBool::new(false));

    let relay = start_relay(port, rejecting.clone()).await;
    let (client, sub_id, filter) = control_plane_subscriber(&url).await;
    let mut notifications = client.notifications();

    // The production fix object, created exactly as run_spawn_control_plane creates it.
    let mut rearmer = nerve::SubscriptionRearmer::new(
        "spawn control-plane (test)",
        client.clone(),
        sub_id.clone(),
        filter,
    )
    .await;

    // Baseline: a spawn request published while the relay is healthy is received.
    let id1 = publish_event(
        &url,
        kind_d_event(KIND_KIRBY_SPAWN_REQUEST, "agent-before-bounce"),
    )
    .await;
    assert!(
        recv_event(&mut notifications, id1, Duration::from_secs(10)).await,
        "baseline: the spawn request published before the bounce must be received"
    );

    // BOUNCE the relay into a briefly-REQ-rejecting restart: kill it, bring it back on
    // the same port with the query policy rejecting. The client auto-reconnects and
    // re-issues its REQ; the relay answers CLOSED ("error: relay warming up"); the pool
    // REMOVES the subscription (the permanent-deafness trigger).
    relay.shutdown();
    drop(relay);
    wait_for_status(
        &client,
        &url,
        RelayStatus::Disconnected,
        Duration::from_secs(15),
    )
    .await;
    rejecting.store(true, Ordering::SeqCst);
    let relay2 = start_relay(port, rejecting.clone()).await;
    wait_for_status(
        &client,
        &url,
        RelayStatus::Connected,
        Duration::from_secs(60),
    )
    .await;
    wait_for_subscription_removed(&client, &url, &sub_id, Duration::from_secs(15)).await;

    // The relay finishes warming up: REQs are accepted again. The transport is healthy,
    // the relay is healthy — but the subscription is GONE and nothing in the pool will
    // ever bring it back.
    rejecting.store(false, Ordering::SeqCst);

    // The fix under test: the control-plane loop periodically re-arms the subscription
    // (a tokio::select! tick driving nerve::SubscriptionRearmer with the SAME sub id +
    // filter). Fire one tick here, exactly as the timer arm does.
    rearmer.tick().await;

    // A spawn request published after the bounce must be received — this is the assert
    // that fails (deaf node) without the periodic re-arm.
    let id2 = publish_event(
        &url,
        kind_d_event(KIND_KIRBY_SPAWN_REQUEST, "agent-after-bounce"),
    )
    .await;
    assert!(
        recv_event(&mut notifications, id2, Duration::from_secs(15)).await,
        "DEAF NODE: the spawn request published after the REQ-rejecting relay bounce was \
         never delivered — the subscription was removed on CLOSED and never re-armed"
    );

    // A 31002 LEASE published after the bounce must reach the same subscription too —
    // this is the failover detector's ear (FleetLeaseObserver is fed from this exact
    // notifications stream in run_spawn_control_plane).
    let lease_id = publish_event(
        &url,
        kind_d_event(KIND_KIRBY_LEASE, "agent-lease-after-bounce"),
    )
    .await;
    assert!(
        recv_event(&mut notifications, lease_id, Duration::from_secs(15)).await,
        "BLIND FAILOVER: the lease published after the relay bounce was never delivered \
         — the lease-observer side of the control-plane subscription did not recover"
    );

    drop(relay2);
}

/// The SAME deafness path against the NIP-17 DM inbox subscription shape
/// (`run_dm_inbound`: kind:1059 gift wraps `#p`-addressed to the agent's DM pubkey,
/// subscribe-once + notifications loop). Proves the shared `SubscriptionRearmer` tick
/// recovers the DM fast path after a REQ-rejecting relay bounce.
#[tokio::test(flavor = "multi_thread")]
async fn dm_subscription_survives_req_rejecting_relay_bounce() {
    let port = free_port();
    let url = format!("ws://127.0.0.1:{port}");
    let rejecting = Arc::new(AtomicBool::new(false));
    let relay = start_relay(port, rejecting.clone()).await;

    // The subscriber, built EXACTLY like run_dm_inbound builds its client: throwaway
    // keys, add_relay_no_ping, gift-wrap filter #p-addressed to the DM pubkey.
    let dm_keys = Keys::generate();
    let me = dm_keys.public_key();
    let client = Client::builder().signer(Keys::generate()).build();
    nerve::add_relay_no_ping(&client, &url)
        .await
        .expect("add relay");
    client.connect().await;
    wait_for_status(
        &client,
        &url,
        RelayStatus::Connected,
        Duration::from_secs(10),
    )
    .await;
    let filter = Filter::new().kind(Kind::GiftWrap).pubkey(me);
    let sub_id = client
        .subscribe(filter.clone(), None)
        .await
        .expect("subscribe")
        .val;
    let mut notifications = client.notifications();
    let mut rearmer = nerve::SubscriptionRearmer::new(
        "NIP-17 DM inbox (test)",
        client.clone(),
        sub_id.clone(),
        filter,
    )
    .await;

    // Baseline: a gift wrap addressed to us lands.
    let id1 = publish_event(&url, gift_wrap_shaped_event(&me)).await;
    assert!(
        recv_event(&mut notifications, id1, Duration::from_secs(10)).await,
        "baseline: the gift wrap published before the bounce must be received"
    );

    // The REQ-rejecting bounce (same choreography as the spawn test).
    relay.shutdown();
    drop(relay);
    wait_for_status(
        &client,
        &url,
        RelayStatus::Disconnected,
        Duration::from_secs(15),
    )
    .await;
    rejecting.store(true, Ordering::SeqCst);
    let relay2 = start_relay(port, rejecting.clone()).await;
    wait_for_status(
        &client,
        &url,
        RelayStatus::Connected,
        Duration::from_secs(60),
    )
    .await;
    wait_for_subscription_removed(&client, &url, &sub_id, Duration::from_secs(15)).await;
    rejecting.store(false, Ordering::SeqCst);

    // One rearm tick (the timer arm in run_dm_inbound), then a DM must land again.
    rearmer.tick().await;
    let id2 = publish_event(&url, gift_wrap_shaped_event(&me)).await;
    assert!(
        recv_event(&mut notifications, id2, Duration::from_secs(15)).await,
        "DEAF DM INBOX: the gift wrap published after the REQ-rejecting relay bounce was \
         never delivered — the DM subscription was removed on CLOSED and never re-armed"
    );

    drop(relay2);
}

/// Regression teeth for the CLEAN restart path: a plain relay kill/restart (no CLOSED)
/// is recovered by nostr-relay-pool's own reconnect-resubscribe, and the periodic re-arm
/// must not break it (re-issuing the same REQ id is an idempotent replace). This one
/// passes even without the fix — it pins the behavior the control plane relies on.
#[tokio::test(flavor = "multi_thread")]
async fn spawn_subscription_survives_relay_restart() {
    let port = free_port();
    let url = format!("ws://127.0.0.1:{port}");
    let relay = start_relay(port, Arc::new(AtomicBool::new(false))).await;

    let (client, sub_id, filter) = control_plane_subscriber(&url).await;
    let mut notifications = client.notifications();

    let mut rearmer = nerve::SubscriptionRearmer::new(
        "spawn control-plane (test)",
        client.clone(),
        sub_id.clone(),
        filter,
    )
    .await;

    // Baseline: a spawn request published while the first relay is up is received.
    let id1 = publish_event(
        &url,
        kind_d_event(KIND_KIRBY_SPAWN_REQUEST, "agent-before-restart"),
    )
    .await;
    assert!(
        recv_event(&mut notifications, id1, Duration::from_secs(10)).await,
        "baseline: the spawn request published before the restart must be received"
    );

    // KILL the relay and wait until the subscriber actually observes the disconnect.
    relay.shutdown();
    drop(relay);
    wait_for_status(
        &client,
        &url,
        RelayStatus::Disconnected,
        Duration::from_secs(15),
    )
    .await;

    // RESTART a fresh (healthy) relay on the SAME port and wait for the automatic
    // reconnect (default retry interval is 10s).
    let relay2 = start_relay(port, Arc::new(AtomicBool::new(false))).await;
    wait_for_status(
        &client,
        &url,
        RelayStatus::Connected,
        Duration::from_secs(60),
    )
    .await;

    // Fire one periodic re-arm, exactly as the control-plane tick does (must be a no-op
    // replace on top of the pool's own resubscribe).
    rearmer.tick().await;

    // A spawn request published AFTER the restart must ALSO be received.
    let id2 = publish_event(
        &url,
        kind_d_event(KIND_KIRBY_SPAWN_REQUEST, "agent-after-restart"),
    )
    .await;
    assert!(
        recv_event(&mut notifications, id2, Duration::from_secs(15)).await,
        "the spawn request published after the relay restart was never delivered — the \
         subscription did not survive the reconnect"
    );

    drop(relay2);
}
