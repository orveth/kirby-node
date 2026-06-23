//! The Kirby "nerve" (Nostr presence + discovery), slice 1: "the fleet exists".
//!
//! The nerve is Kirby's coordination/public layer over a Nostr relay (the
//! body/vault/nerve triad: body = the Firecracker sandbox, vault = the custody
//! quorum, nerve = Nostr). Slice 1 gives N nodes self-discovery + liveness with
//! NO central registry: each node has its own Nostr identity, publishes a
//! REPLACEABLE presence beacon ([`kirby_proto::KIND_KIRBY_PRESENCE`]) to a shared
//! relay on an interval, and subscribes to every node's beacon. A relay keeps only
//! the latest beacon per node pubkey, so the current set of beacons IS the fleet;
//! a node that stops publishing leaves a beacon whose `created_at` goes stale,
//! which is the death signal. (Slice 2, later, is FROST co-signing over the relay;
//! out of scope here.)
//!
//! This is entirely HOST-SIDE and UNPRIVILEGED: the relay connection is an
//! outbound websocket from the daemon (the same host-network path as the
//! daemon->mint HTTP in C-6), NOT a VM/genome concern. It does not touch the
//! genome, the `SandboxBackend`/`SandboxInstance` trait, or any sudo/jailer path,
//! and it does not affect the C-5 per-VM egress lockdown (that is VM-TAP-only).
//!
//! The node's identity is a secp256k1/BIP340 (schnorr, x-only) keypair = its Nostr
//! key. It is generated on first run (with `OsRng`) and persisted in the node state
//! directory, then loaded thereafter, so a node keeps the SAME npub across restarts
//! (the stable cluster identity). See [`NodeIdentity`].

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use kirby_proto::{KIND_KIRBY_AGENT_STATE, KIND_KIRBY_LIFECYCLE, KIND_KIRBY_PRESENCE};

/// The default file name for the persisted node Nostr secret key, under the node
/// state directory (the `--treasury-path` dir, unless `--nostr-key-path` overrides
/// the location). Stored as a bech32 `nsec...` string, perms 0600.
pub const DEFAULT_KEY_FILE: &str = "node.nostr.key";

/// The tag name (single-letter `d`-style is reserved for addressable kinds; we use
/// a custom `node_id` tag) carrying the human node label on the presence beacon, so
/// the fleet read can surface it. The authoritative payload is the content JSON;
/// the tag is a convenience mirror.
const TAG_NODE_ID: &str = "node_id";
/// The optional advertised-endpoint tag (informational in slice 1; all coordination
/// is via the relay).
const TAG_ENDPOINT: &str = "endpoint";
/// The relay-wide discovery tag every Kirby event carries (`["t","kirby"]`), so the
/// UI (and any consumer) can subscribe with a single `#t=kirby` filter and receive
/// every Kirby kind. Used on the 9100 lifecycle event per the unified tag vocabulary
/// (`plans/kirby-cluster-event-kinds-20260619.md`).
const TAG_T: &str = "t";
/// The discovery-tag value: every Kirby node/agent event is tagged `#t=kirby`.
const TAG_T_KIRBY: &str = "kirby";
/// The node-scope tag (`["node",<node_id>]`) the unified vocabulary uses. kirby-ui
/// filters and groups by it.
const TAG_NODE: &str = "node";
/// The agent-scope tag (`["a",<agent_id>]`) on agent-scoped events (the 9100
/// lifecycle event). The UI filters per-agent by it.
const TAG_A: &str = "a";
/// The NIP-01 addressable `d` tag. For the 31000 agent-state event the value is the
/// `agent_id`, so the relay keeps only the latest state per agent (per pubkey/kind).
const TAG_D: &str = "d";

/// The node's cryptographic identity: a Nostr (secp256k1/BIP340) keypair. The npub
/// is the node's stable cluster identity across restarts.
#[derive(Clone)]
pub struct NodeIdentity {
    keys: Keys,
    key_path: PathBuf,
}

impl NodeIdentity {
    /// Load the node identity from `key_path`, or GENERATE and persist a new one if
    /// the file is absent (idempotent: the same file yields the same npub on every
    /// run). The new secret key is drawn from `OsRng` and written as a bech32
    /// `nsec...` with perms `0600` (owner read/write only).
    ///
    /// `key_path` is the full path to the key FILE. The caller resolves it from
    /// `--nostr-key-path`, or defaults it to `<state-dir>/node.nostr.key`.
    pub fn load_or_create(key_path: &Path) -> anyhow::Result<Self> {
        if key_path.exists() {
            let nsec = std::fs::read_to_string(key_path)
                .with_context(|| format!("read node key file {}", key_path.display()))?;
            let keys = Keys::parse(nsec.trim()).with_context(|| {
                format!("parse the persisted node key in {}", key_path.display())
            })?;
            tracing::info!(
                npub = %keys.public_key().to_bech32().unwrap_or_default(),
                path = %key_path.display(),
                "loaded persisted node identity"
            );
            Ok(NodeIdentity { keys, key_path: key_path.to_path_buf() })
        } else {
            // Generate from the OS CSPRNG (the spec-mandated OsRng), then persist.
            let mut rng = rand::rngs::OsRng;
            let keys = Keys::generate_with_rng(&mut rng);
            persist_key(key_path, &keys)?;
            tracing::info!(
                npub = %keys.public_key().to_bech32().unwrap_or_default(),
                path = %key_path.display(),
                "generated and persisted a new node identity"
            );
            Ok(NodeIdentity { keys, key_path: key_path.to_path_buf() })
        }
    }

    /// Resolve the key file path from an optional explicit `--nostr-key-path` and
    /// the node state directory. If `explicit` is `Some` and names a directory (or
    /// has no extension and does not exist as a file), the key file goes inside it;
    /// if it names a file path, that file is used verbatim. If `explicit` is `None`,
    /// the key lives at `<state_dir>/node.nostr.key`.
    pub fn resolve_key_path(explicit: Option<&Path>, state_dir: &Path) -> PathBuf {
        match explicit {
            Some(p) if p.is_dir() => p.join(DEFAULT_KEY_FILE),
            Some(p) => p.to_path_buf(),
            None => state_dir.join(DEFAULT_KEY_FILE),
        }
    }

    /// This node's public key.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// This node's npub (bech32 public key), the stable cluster identity.
    pub fn npub(&self) -> String {
        self.keys.public_key().to_bech32().unwrap_or_default()
    }

    /// The underlying signing keys (used to build the Nostr client signer).
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// The path the secret key is persisted at.
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }
}

/// Write `keys` to `path` as a bech32 `nsec...` string with perms 0600, creating
/// parent directories as needed.
fn persist_key(path: &Path, keys: &Keys) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create key dir {}", parent.display()))?;
    }
    let nsec = keys
        .secret_key()
        .to_bech32()
        .context("encode node secret key as nsec")?;

    // Create with 0600 from the start (do not briefly expose the secret as 0644).
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("create node key file {}", path.display()))?;
    f.write_all(nsec.as_bytes())
        .with_context(|| format!("write node key file {}", path.display()))?;
    f.flush().ok();

    // Belt and suspenders: enforce 0600 even if the file pre-existed via a race.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set 0600 on {}", path.display()))?;
    }
    Ok(())
}

/// The decoded payload of a presence beacon (the content JSON), plus the
/// relay-derived metadata (the author pubkey and the beacon's `created_at`).
#[derive(Clone, Debug, Serialize)]
pub struct PresenceRecord {
    /// The publishing node's npub (its stable cluster identity).
    pub npub: String,
    /// The human node label the node advertised.
    pub node_id: String,
    /// The advertised endpoint, if any (informational in slice 1).
    pub endpoint: Option<String>,
    /// The self-declared status (always "alive" in slice 1).
    pub status: String,
    /// The beacon's `created_at` (unix seconds) = the last-seen time.
    pub last_seen_unix: u64,
    /// Age in seconds at the moment this record was computed (now - last_seen).
    pub age_secs: u64,
    /// Whether the beacon is fresh (age <= stale threshold).
    pub alive: bool,
}

/// The JSON content shape of a presence beacon. `node_id` is the human label,
/// `endpoint` is optional, `status` is "alive".
#[derive(Serialize, Deserialize)]
struct PresenceContent {
    node_id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    endpoint: Option<String>,
    status: String,
}

/// Build a presence [`EventBuilder`] for this node: a REPLACEABLE
/// `KIND_KIRBY_PRESENCE` event whose content is the presence JSON and whose tags
/// mirror the node_id (and endpoint, if any) for read-path legibility. The client
/// signs it and sets `created_at` at publish time, so each publish replaces the
/// prior beacon (bumping last-seen).
fn build_presence(node_id: &str, endpoint: Option<&str>) -> anyhow::Result<EventBuilder> {
    let content = PresenceContent {
        node_id: node_id.to_string(),
        endpoint: endpoint.map(|s| s.to_string()),
        status: "alive".to_string(),
    };
    let json = serde_json::to_string(&content).context("serialize presence content")?;
    let mut tags: Vec<Tag> = vec![Tag::parse([TAG_NODE_ID, node_id])?];
    if let Some(ep) = endpoint {
        tags.push(Tag::parse([TAG_ENDPOINT, ep])?);
    }
    Ok(EventBuilder::new(Kind::from(KIND_KIRBY_PRESENCE), json).tags(tags))
}

/// The JSON content shape of a 9100 lifecycle event (`born`/`died`), per the unified
/// event-kinds contract (`plans/kirby-cluster-event-kinds-20260619.md`):
/// `{ agent_id, event, treasury_sats, reason }`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LifecycleContent {
    /// The agent this lifecycle event is about (e.g. "agent-0").
    pub agent_id: String,
    /// "born" or "died".
    pub event: String,
    /// born: the committed initial budget; died: 0 (the treasury is exhausted).
    pub treasury_sats: u64,
    /// born: "funded"; died: "broke".
    pub reason: String,
}

/// Build a 9100 `KIND_KIRBY_LIFECYCLE` [`EventBuilder`] (a REGULAR/stored event, the
/// signed birth/death log) for `agent_id` on `node_id`, mirroring [`build_presence`]'s
/// shape. Tags per the contract: `["t","kirby"]`, `["a",<agent_id>]`, `["node",<node_id>]`.
/// Signed by the node key at publish time. The `event`/`treasury_sats`/`reason` are the
/// caller's (born = funded + initial budget; died = broke + 0).
fn build_lifecycle(
    agent_id: &str,
    node_id: &str,
    event: &str,
    treasury_sats: u64,
    reason: &str,
) -> anyhow::Result<EventBuilder> {
    let content = LifecycleContent {
        agent_id: agent_id.to_string(),
        event: event.to_string(),
        treasury_sats,
        reason: reason.to_string(),
    };
    let json = serde_json::to_string(&content).context("serialize lifecycle content")?;
    let tags: Vec<Tag> = vec![
        Tag::parse([TAG_T, TAG_T_KIRBY])?,
        Tag::parse([TAG_A, agent_id])?,
        Tag::parse([TAG_NODE, node_id])?,
    ];
    Ok(EventBuilder::new(Kind::from(KIND_KIRBY_LIFECYCLE), json).tags(tags))
}

/// Decode a received presence [`Event`] into a [`PresenceRecord`], computing age +
/// liveness against `now_unix` and `stale_after`. Returns `None` if the content is
/// not a well-formed presence payload (a foreign event of the same kind, say).
fn record_from_event(ev: &Event, now_unix: u64, stale_after: Duration) -> Option<PresenceRecord> {
    let content: PresenceContent = serde_json::from_str(&ev.content).ok()?;
    let last_seen = ev.created_at.as_secs();
    let age = now_unix.saturating_sub(last_seen);
    Some(PresenceRecord {
        npub: ev.pubkey.to_bech32().unwrap_or_default(),
        node_id: content.node_id,
        endpoint: content.endpoint,
        status: content.status,
        last_seen_unix: last_seen,
        age_secs: age,
        alive: age <= stale_after.as_secs(),
    })
}

/// Configuration for the persistent presence task.
pub struct PresenceConfig {
    /// The relay websocket URL (e.g. `ws://127.0.0.1:7777`).
    pub relay_url: String,
    /// This node's human label (advertised in the beacon).
    pub node_id: String,
    /// The optional advertised endpoint (informational in slice 1).
    pub endpoint: Option<String>,
    /// How often to (re-)publish the beacon.
    pub interval: Duration,
    /// A peer whose latest beacon is older than this is presumed dead (STALE).
    pub stale_after: Duration,
}

/// Build a connected Nostr [`Client`] for `identity`, add `relay_url`, and connect.
/// Shared by the presence task and the fleet read path, and reused by the hibernation
/// wake-request publish path ([`crate::hibernate::wake`]) so it does not duplicate the
/// relay-client construction.
pub(crate) async fn connect_client(
    identity: &NodeIdentity,
    relay_url: &str,
) -> anyhow::Result<Client> {
    let client = Client::builder().signer(identity.keys().clone()).build();
    client
        .add_relay(relay_url)
        .await
        .with_context(|| format!("add relay {relay_url}"))?;
    client.connect().await;
    Ok(client)
}

/// Build a connected, read-only Nostr [`Client`] (a throwaway identity) for the
/// fleet read path: it only queries, never publishes, so it needs no node identity.
/// Reused by the hibernation wake-request fetch path ([`crate::hibernate::wake`]).
pub(crate) async fn connect_reader(relay_url: &str) -> anyhow::Result<Client> {
    let client = Client::builder().signer(Keys::generate()).build();
    client
        .add_relay(relay_url)
        .await
        .with_context(|| format!("add relay {relay_url}"))?;
    client.connect().await;
    Ok(client)
}

/// The current unix time in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run the persistent presence task to completion (until `shutdown` fires). This is
/// the supervisor loop the daemon spawns: it (a) publishes this node's beacon every
/// `interval`, (b) maintains a live subscription to every node's beacon and tracks
/// the peer set, and (c) emits `tracing` events when a peer JOINS, REFRESHES, or
/// goes STALE, including the current fleet size. Self-beacons are excluded from the
/// peer set (a node knows its own npub).
///
/// The relay client is built from `identity` so published beacons are signed by
/// this node's key. The function returns when `shutdown` resolves (a graceful
/// stop), or on an unrecoverable client error.
pub async fn run_presence(
    identity: NodeIdentity,
    config: PresenceConfig,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let me = identity.public_key();
    let my_npub = identity.npub();
    tracing::info!(
        npub = %my_npub,
        node_id = %config.node_id,
        relay = %config.relay_url,
        interval_secs = config.interval.as_secs(),
        stale_after_secs = config.stale_after.as_secs(),
        "presence task starting (the fleet nerve)"
    );

    let client = connect_client(&identity, &config.relay_url).await?;

    // Subscribe to EVERY node's presence beacon (all authors, this kind). The relay
    // keeps only the latest per pubkey, so this stream is the live fleet.
    let filter = Filter::new().kind(Kind::from(KIND_KIRBY_PRESENCE));
    client
        .subscribe(filter, None)
        .await
        .context("subscribe to the fleet presence")?;

    // The peer set: npub -> the last-seen unix time we observed for it. Used to log
    // joins/refreshes and to sweep for staleness. Excludes this node.
    let mut peers: HashMap<String, PeerState> = HashMap::new();

    // Notifications carry NEW events (the relay's stored latest on connect, then
    // live updates). Note: nostr-sdk does NOT deliver our OWN events here, so the
    // peer set is naturally peers-only; we still guard on `me` for clarity.
    let mut notifications = client.notifications();

    // Publish immediately so peers see us without waiting a full interval, then on
    // the interval thereafter.
    publish_presence(&client, &config).await;

    let mut publish_tick = tokio::time::interval(config.interval);
    publish_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    publish_tick.tick().await; // consume the immediate first tick (we just published)

    // Sweep for staleness on a cadence finer than the interval so a death is
    // detected promptly (and at least once per interval).
    let sweep_period = sweep_period(config.stale_after, config.interval);
    let mut sweep_tick = tokio::time::interval(sweep_period);
    sweep_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    sweep_tick.tick().await;

    loop {
        tokio::select! {
            // Graceful shutdown.
            _ = &mut shutdown => {
                tracing::info!(npub = %my_npub, "presence task shutting down");
                break;
            }
            // Re-publish our beacon (bumps created_at, replaces the prior).
            _ = publish_tick.tick() => {
                publish_presence(&client, &config).await;
            }
            // Sweep the peer set for staleness.
            _ = sweep_tick.tick() => {
                sweep_stale(&mut peers, config.stale_after);
            }
            // A relay notification: a (new) presence event from a peer.
            notif = notifications.recv() => {
                match notif {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        if event.kind == Kind::from(KIND_KIRBY_PRESENCE) {
                            ingest_event(&mut peers, &event, me, config.stale_after);
                        }
                    }
                    Ok(RelayPoolNotification::Shutdown) => {
                        tracing::warn!("relay pool shut down; presence task stopping");
                        break;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "presence notifications lagged; some updates skipped");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::warn!("presence notification channel closed; task stopping");
                        break;
                    }
                }
            }
        }
    }

    // Best-effort clean disconnect.
    client.disconnect().await;
    Ok(())
}

/// Per-peer tracking state for the live presence task.
struct PeerState {
    node_id: String,
    last_seen_unix: u64,
    /// Whether we currently consider this peer stale (so we log the transition once).
    stale: bool,
}

/// Publish (or re-publish) this node's presence beacon. Logs but does not fail the
/// task on a transient publish error (the next interval retries).
async fn publish_presence(client: &Client, config: &PresenceConfig) {
    match build_presence(&config.node_id, config.endpoint.as_deref()) {
        Ok(builder) => match client.send_event_builder(builder).await {
            Ok(output) => {
                tracing::debug!(
                    event_id = %output.val,
                    node_id = %config.node_id,
                    "published presence beacon"
                );
            }
            Err(e) => tracing::warn!(error = %e, "failed to publish presence beacon (will retry next interval)"),
        },
        Err(e) => tracing::error!(error = %e, "failed to build presence beacon"),
    }
}

/// Publish ONE 9100 `KIND_KIRBY_LIFECYCLE` event (a born/died milestone) to the relay,
/// signed by this node's key, then disconnect. A one-shot connect-publish-disconnect:
/// births and deaths are rare (not an interval cadence), so a dedicated short-lived
/// client is the simplest correct shape and never contends with the persistent presence
/// client. Returns the published event id on success.
///
/// This is the SINGLE-AGENT lifecycle path for a sovereign node: it emits `born` once
/// on its own boot and `died` once on its own budget-death (or clean shutdown). It does
/// NOT carry the cluster's at-most-once-across-fleet dedup (that is the Raft cluster's
/// concern, and a sovereign node IS its own single agent on its own machine).
///
/// `node_id` is this node's id as the contract's `["node",X]` value. The content/tags
/// follow the contract (`plans/kirby-cluster-event-kinds-20260619.md`): `["t","kirby"]`,
/// `["a",<agent_id>]`, `["node",<node_id>]`, content `{ agent_id, event, treasury_sats,
/// reason }`.
pub async fn publish_lifecycle(
    identity: &NodeIdentity,
    relay_url: &str,
    agent_id: &str,
    node_id: &str,
    event: &str,
    treasury_sats: u64,
    reason: &str,
) -> anyhow::Result<String> {
    let builder = build_lifecycle(agent_id, node_id, event, treasury_sats, reason)?;
    let client = connect_client(identity, relay_url).await?;
    let result = client
        .send_event_builder(builder)
        .await
        .context("publish lifecycle event");
    // Best-effort clean disconnect regardless of the send outcome.
    client.disconnect().await;
    let output = result?;
    let id = output.val.to_hex();
    tracing::info!(
        agent_id,
        node_id,
        event,
        treasury_sats,
        reason,
        event_id = %id,
        "published 9100 lifecycle event (the signed birth/death log)"
    );
    Ok(id)
}

/// The JSON content shape of a 31000 agent-state event (the live "Kirby face"), per
/// the unified event-kinds contract (`plans/kirby-cluster-event-kinds-20260619.md`):
/// `{ agent_id, treasury_sats, runway_secs, lifecycle, backend, lease_holder_node,
/// lease_term }`. `treasury_sats` is the LIVE current balance (never a genesis
/// number); `runway_secs` is the estimated seconds until broke at the current burn
/// (`null` until a burn rate is established). On a sovereign node there is no Raft
/// lease, so `lease_holder_node`/`lease_term` are always `null`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AgentStateContent {
    /// The agent this state event is about (e.g. "agent-0"); also the `d`-tag value.
    pub agent_id: String,
    /// The LIVE current treasury balance in sats.
    pub treasury_sats: u64,
    /// Estimated seconds until the treasury is exhausted at the current burn rate.
    /// `None` (serialized `null`) until a burn rate is established (the first tick).
    #[serde(default)]
    pub runway_secs: Option<u64>,
    /// "running" while alive + funded; "dying" near budget exhaustion; "dead" once
    /// at budget-death (the final state, after which the node stops emitting).
    pub lifecycle: String,
    /// The sandbox backend: "firecracker" or "vz".
    pub backend: String,
    /// The Raft lease holder node, or `null` on a sovereign node (no Raft lease).
    #[serde(default)]
    pub lease_holder_node: Option<String>,
    /// The Raft lease term, or `null` on a sovereign node (no Raft lease).
    #[serde(default)]
    pub lease_term: Option<u64>,
}

impl AgentStateContent {
    /// Build the sovereign-path content from the live fields: `lease_*` are always
    /// `null` (no Raft lease). `runway_secs` is `None` until a burn rate is known.
    pub fn sovereign(
        agent_id: &str,
        treasury_sats: u64,
        runway_secs: Option<u64>,
        lifecycle: &str,
        backend: &str,
    ) -> Self {
        AgentStateContent {
            agent_id: agent_id.to_string(),
            treasury_sats,
            runway_secs,
            lifecycle: lifecycle.to_string(),
            backend: backend.to_string(),
            lease_holder_node: None,
            lease_term: None,
        }
    }
}

/// Build a 31000 `KIND_KIRBY_AGENT_STATE` [`EventBuilder`] (an ADDRESSABLE event, the
/// live agent face) from `content` on `node_id`, mirroring [`build_lifecycle`]'s
/// shape. Tags per the contract: `["d",<agent_id>]`, `["t","kirby"]`,
/// `["a",<agent_id>]`, `["node",<node_id>]`. The `d` tag makes it addressable, so the
/// relay keeps only the latest state per agent. Signed by the node key at publish
/// time.
fn build_agent_state(content: &AgentStateContent, node_id: &str) -> anyhow::Result<EventBuilder> {
    let json = serde_json::to_string(content).context("serialize agent-state content")?;
    let tags: Vec<Tag> = vec![
        Tag::parse([TAG_D, &content.agent_id])?,
        Tag::parse([TAG_T, TAG_T_KIRBY])?,
        Tag::parse([TAG_A, &content.agent_id])?,
        Tag::parse([TAG_NODE, node_id])?,
    ];
    Ok(EventBuilder::new(Kind::from(KIND_KIRBY_AGENT_STATE), json).tags(tags))
}

/// Publish ONE 31000 `KIND_KIRBY_AGENT_STATE` event (the live "Kirby face") to the
/// relay, signed by this node's key, then disconnect. A one-shot
/// connect-publish-disconnect mirroring [`publish_lifecycle`]: the event is
/// addressable (keyed by the `agent_id` `d` tag), so each publish REPLACES the prior
/// state on the relay, and the UI reads the latest per agent. Re-published on the
/// presence cadence with the LIVE treasury balance.
///
/// `content` carries the live current balance + runway (`None` until a burn rate is
/// established) + lifecycle ("running" | "dying" | "dead") + backend ("firecracker" |
/// "vz"). The content/tags follow the contract
/// (`plans/kirby-cluster-event-kinds-20260619.md`): `["d",<agent_id>]`,
/// `["t","kirby"]`, `["a",<agent_id>]`, `["node",<node_id>]`, content `{ agent_id,
/// treasury_sats, runway_secs, lifecycle, backend, lease_holder_node, lease_term }`.
/// Returns the published event id on success.
pub async fn publish_agent_state(
    identity: &NodeIdentity,
    relay_url: &str,
    node_id: &str,
    content: &AgentStateContent,
) -> anyhow::Result<String> {
    let builder = build_agent_state(content, node_id)?;
    let client = connect_client(identity, relay_url).await?;
    let result = client
        .send_event_builder(builder)
        .await
        .context("publish agent-state event");
    // Best-effort clean disconnect regardless of the send outcome.
    client.disconnect().await;
    let output = result?;
    let id = output.val.to_hex();
    tracing::debug!(
        agent_id = %content.agent_id,
        node_id,
        treasury_sats = content.treasury_sats,
        runway_secs = content.runway_secs,
        lifecycle = %content.lifecycle,
        backend = %content.backend,
        event_id = %id,
        "published 31000 agent-state event (the live Kirby face)"
    );
    Ok(id)
}

/// Fold a received presence event into the peer set, logging JOIN / REFRESH and the
/// current fleet size. Ignores our own beacon.
fn ingest_event(
    peers: &mut HashMap<String, PeerState>,
    event: &Event,
    me: PublicKey,
    stale_after: Duration,
) {
    if event.pubkey == me {
        return; // our own beacon; not a peer
    }
    let npub = event.pubkey.to_bech32().unwrap_or_default();
    let last_seen = event.created_at.as_secs();
    let node_id = serde_json::from_str::<PresenceContent>(&event.content)
        .map(|c| c.node_id)
        .unwrap_or_else(|_| "<unknown>".to_string());

    match peers.get_mut(&npub) {
        None => {
            peers.insert(
                npub.clone(),
                PeerState { node_id: node_id.clone(), last_seen_unix: last_seen, stale: false },
            );
            tracing::info!(
                peer_npub = %npub,
                peer_node_id = %node_id,
                fleet_size = peers.len(),
                "peer JOINED the fleet"
            );
        }
        Some(state) => {
            // Only treat strictly-newer beacons as a refresh (replaceable events can
            // be re-delivered; an older or equal one is not news).
            if last_seen > state.last_seen_unix {
                let was_stale = state.stale;
                state.last_seen_unix = last_seen;
                state.node_id = node_id.clone();
                state.stale = false;
                if was_stale {
                    tracing::info!(
                        peer_npub = %npub,
                        peer_node_id = %node_id,
                        fleet_size = alive_count(peers, stale_after),
                        "peer REFRESHED (was STALE, now alive again)"
                    );
                } else {
                    tracing::debug!(peer_npub = %npub, peer_node_id = %node_id, "peer REFRESHED");
                }
            }
        }
    }
}

/// Sweep the peer set for newly-stale peers and log the STALE transition once.
fn sweep_stale(peers: &mut HashMap<String, PeerState>, stale_after: Duration) {
    let now = now_unix();
    let threshold = stale_after.as_secs();
    for state in peers.values_mut() {
        let age = now.saturating_sub(state.last_seen_unix);
        let is_stale = age > threshold;
        if is_stale && !state.stale {
            state.stale = true;
            tracing::warn!(
                peer_node_id = %state.node_id,
                age_secs = age,
                "peer went STALE (no fresh beacon past the stale threshold; presumed dead)"
            );
        }
    }
    tracing::debug!(
        alive = peers.values().filter(|s| !s.stale).count(),
        total_known = peers.len(),
        "presence sweep"
    );
}

/// The count of peers currently considered alive.
fn alive_count(peers: &HashMap<String, PeerState>, stale_after: Duration) -> usize {
    let now = now_unix();
    let threshold = stale_after.as_secs();
    peers
        .values()
        .filter(|s| now.saturating_sub(s.last_seen_unix) <= threshold)
        .count()
}

/// Choose the staleness-sweep cadence: a fraction of the stale threshold, capped to
/// at most the publish interval, and at least 1s. This makes a death visible within
/// roughly one sweep of crossing the threshold.
fn sweep_period(stale_after: Duration, interval: Duration) -> Duration {
    let third = stale_after / 3;
    let chosen = third.min(interval);
    chosen.max(Duration::from_secs(1))
}

/// Query the relay ONCE for the current fleet (every node's latest presence beacon)
/// and return the records, sorted by node_id then npub for stable output. Used by
/// the `presence` read subcommand. `timeout` bounds the relay query.
pub async fn read_fleet_once(
    relay_url: &str,
    stale_after: Duration,
    timeout: Duration,
) -> anyhow::Result<Vec<PresenceRecord>> {
    let client = connect_reader(relay_url).await?;
    let records = fetch_fleet(&client, stale_after, timeout).await?;
    client.disconnect().await;
    Ok(records)
}

/// Fetch the current fleet over an already-connected client (stream the stored
/// latest beacons, which auto-closes on EOSE), de-duplicated to the newest beacon
/// per pubkey, decoded into records.
async fn fetch_fleet(
    client: &Client,
    stale_after: Duration,
    timeout: Duration,
) -> anyhow::Result<Vec<PresenceRecord>> {
    use futures::StreamExt as _;

    let filter = Filter::new().kind(Kind::from(KIND_KIRBY_PRESENCE));
    let mut stream = client
        .stream_events(filter, timeout)
        .await
        .context("stream the fleet presence")?;

    // Keep the newest beacon per pubkey (the relay should already only hold the
    // latest replaceable event, but de-dup defensively across relays/races).
    let mut latest: HashMap<String, Event> = HashMap::new();
    while let Some(event) = stream.next().await {
        if event.kind != Kind::from(KIND_KIRBY_PRESENCE) {
            continue;
        }
        let key = event.pubkey.to_hex();
        match latest.get(&key) {
            Some(prev) if prev.created_at >= event.created_at => {}
            _ => {
                latest.insert(key, event);
            }
        }
    }

    let now = now_unix();
    let mut records: Vec<PresenceRecord> = latest
        .values()
        .filter_map(|ev| record_from_event(ev, now, stale_after))
        .collect();
    records.sort_by(|a, b| a.node_id.cmp(&b.node_id).then(a.npub.cmp(&b.npub)));
    Ok(records)
}

/// Format a fleet snapshot as human-readable lines, one per node.
pub fn format_fleet_human(records: &[PresenceRecord]) -> String {
    if records.is_empty() {
        return "fleet: (no presence beacons found on the relay)".to_string();
    }
    let mut out = format!("fleet: {} node(s)\n", records.len());
    for r in records {
        let status = if r.alive { "ALIVE" } else { "STALE" };
        let endpoint = r.endpoint.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "  [{status}] {npub}  node_id={node_id}  last_seen={age}s ago  endpoint={endpoint}\n",
            npub = r.npub,
            node_id = r.node_id,
            age = r.age_secs,
        ));
    }
    out.trim_end().to_string()
}

/// Format a fleet snapshot as a JSON array of records (machine-parseable).
pub fn format_fleet_json(records: &[PresenceRecord]) -> String {
    serde_json::to_string_pretty(records).unwrap_or_else(|_| "[]".to_string())
}

/// Stream live fleet updates for the `presence --watch` path: print the fleet
/// snapshot (human + JSON) on every relay notification, until `shutdown` fires.
/// Uses a throwaway reader identity (no publishing). It maintains the latest beacon
/// per pubkey from the live subscription and re-renders on change.
pub async fn watch_fleet(
    relay_url: &str,
    stale_after: Duration,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let client = connect_reader(relay_url).await?;
    let filter = Filter::new().kind(Kind::from(KIND_KIRBY_PRESENCE));
    client
        .subscribe(filter, None)
        .await
        .context("subscribe to the fleet presence (watch)")?;

    let mut latest: HashMap<String, Event> = HashMap::new();
    let mut notifications = client.notifications();
    // Re-render on a cadence too, so STALE transitions show without a new event.
    let mut tick = tokio::time::interval(sweep_period(stale_after, stale_after));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    render_watch(&latest, stale_after);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tick.tick() => {
                render_watch(&latest, stale_after);
            }
            notif = notifications.recv() => {
                match notif {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        if event.kind == Kind::from(KIND_KIRBY_PRESENCE) {
                            let key = event.pubkey.to_hex();
                            let newer = latest.get(&key).map(|p| event.created_at > p.created_at).unwrap_or(true);
                            if newer {
                                latest.insert(key, *event);
                                render_watch(&latest, stale_after);
                            }
                        }
                    }
                    Ok(RelayPoolNotification::Shutdown) => break,
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    client.disconnect().await;
    Ok(())
}

/// Render one watch frame: the human lines plus a JSON line, from the current
/// latest-per-pubkey map.
fn render_watch(latest: &HashMap<String, Event>, stale_after: Duration) {
    let now = now_unix();
    let mut records: Vec<PresenceRecord> = latest
        .values()
        .filter_map(|ev| record_from_event(ev, now, stale_after))
        .collect();
    records.sort_by(|a, b| a.node_id.cmp(&b.node_id).then(a.npub.cmp(&b.npub)));
    println!("{}", format_fleet_human(&records));
    println!("{}", format_fleet_json(&records));
    println!("---");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_idempotent_across_loads() {
        let dir = tempdir();
        let path = dir.join("node.nostr.key");
        let a = NodeIdentity::load_or_create(&path).unwrap();
        let npub_a = a.npub();
        // Second load reads the SAME persisted key.
        let b = NodeIdentity::load_or_create(&path).unwrap();
        assert_eq!(npub_a, b.npub(), "same key file must yield the same npub");
        assert!(npub_a.starts_with("npub1"), "npub bech32 prefix");

        // A different path = a different identity.
        let path2 = dir.join("other.key");
        let c = NodeIdentity::load_or_create(&path2).unwrap();
        assert_ne!(npub_a, c.npub(), "distinct key files must yield distinct npubs");
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir();
        let path = dir.join("node.nostr.key");
        let _ = NodeIdentity::load_or_create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file must be 0600, got {mode:o}");
        cleanup(&dir);
    }

    #[test]
    fn presence_content_roundtrips_through_an_event() {
        // Build a presence event, sign it, and decode it back into a record.
        let keys = Keys::generate();
        let builder = build_presence("node-A", Some("1.2.3.4:5000")).unwrap();
        let event = builder.sign_with_keys(&keys).unwrap();
        assert_eq!(event.kind, Kind::from(KIND_KIRBY_PRESENCE));
        assert!(event.kind.is_replaceable(), "presence kind must be replaceable");

        let now = event.created_at.as_secs();
        let rec = record_from_event(&event, now, Duration::from_secs(45)).unwrap();
        assert_eq!(rec.node_id, "node-A");
        assert_eq!(rec.endpoint.as_deref(), Some("1.2.3.4:5000"));
        assert_eq!(rec.status, "alive");
        assert!(rec.alive, "a just-created beacon is alive");
        assert_eq!(rec.npub, keys.public_key().to_bech32().unwrap());
    }

    #[test]
    fn staleness_is_age_based() {
        let keys = Keys::generate();
        let event = build_presence("old", None).unwrap().sign_with_keys(&keys).unwrap();
        let created = event.created_at.as_secs();
        // 100s later, with a 45s threshold -> stale.
        let rec = record_from_event(&event, created + 100, Duration::from_secs(45)).unwrap();
        assert!(!rec.alive, "a beacon older than the threshold is stale");
        assert_eq!(rec.age_secs, 100);
        // 10s later -> alive.
        let rec2 = record_from_event(&event, created + 10, Duration::from_secs(45)).unwrap();
        assert!(rec2.alive);
    }

    #[test]
    fn foreign_event_content_is_ignored() {
        // An event of the same kind but with non-presence content decodes to None.
        let keys = Keys::generate();
        let ev = EventBuilder::new(Kind::from(KIND_KIRBY_PRESENCE), "not json")
            .sign_with_keys(&keys)
            .unwrap();
        assert!(record_from_event(&ev, now_unix(), Duration::from_secs(45)).is_none());
    }

    #[test]
    fn lifecycle_event_shape_matches_the_contract() {
        // 9100 born: tags ["t","kirby"]+["a",agent]+["node",node], content
        // {agent_id, event, treasury_sats, reason}.
        let keys = Keys::generate();
        let event = build_lifecycle("agent-0", "node-1", "born", 1_000_000, "funded")
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(event.kind, Kind::from(KIND_KIRBY_LIFECYCLE));
        assert!(
            event.kind.is_regular(),
            "9100 is a REGULAR (stored) kind so the relay keeps the birth/death log"
        );
        let has_tag = |name: &str, val: &str| {
            event.tags.iter().any(|t| {
                let s = t.as_slice();
                s.first().map(String::as_str) == Some(name)
                    && s.get(1).map(String::as_str) == Some(val)
            })
        };
        assert!(has_tag("t", "kirby"));
        assert!(has_tag("a", "agent-0"));
        assert!(has_tag("node", "node-1"));
        let content: LifecycleContent = serde_json::from_str(&event.content).unwrap();
        assert_eq!(
            content,
            LifecycleContent {
                agent_id: "agent-0".to_string(),
                event: "born".to_string(),
                treasury_sats: 1_000_000,
                reason: "funded".to_string(),
            }
        );

        // 9100 died: treasury 0, reason broke.
        let died = build_lifecycle("agent-0", "node-1", "died", 0, "broke")
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();
        let dc: LifecycleContent = serde_json::from_str(&died.content).unwrap();
        assert_eq!(dc.event, "died");
        assert_eq!(dc.treasury_sats, 0);
        assert_eq!(dc.reason, "broke");
    }

    #[test]
    fn agent_state_event_shape_matches_the_contract() {
        // 31000 running: addressable (d=agent_id), tags
        // ["d",agent]+["t","kirby"]+["a",agent]+["node",node], content
        // {agent_id, treasury_sats, runway_secs, lifecycle, backend,
        // lease_holder_node, lease_term} with null leases on the sovereign path.
        let keys = Keys::generate();
        let content = AgentStateContent::sovereign("agent-0", 1_234, Some(42), "running", "firecracker");
        let event = build_agent_state(&content, "node-1")
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(event.kind, Kind::from(KIND_KIRBY_AGENT_STATE));
        assert!(
            event.kind.is_addressable(),
            "31000 is an ADDRESSABLE kind so the relay keeps only the latest per (pubkey, kind, d)"
        );
        let has_tag = |name: &str, val: &str| {
            event.tags.iter().any(|t| {
                let s = t.as_slice();
                s.first().map(String::as_str) == Some(name)
                    && s.get(1).map(String::as_str) == Some(val)
            })
        };
        assert!(has_tag("d", "agent-0"), "the addressable d tag is the agent_id");
        assert!(has_tag("t", "kirby"));
        assert!(has_tag("a", "agent-0"));
        assert!(has_tag("node", "node-1"));
        let content: AgentStateContent = serde_json::from_str(&event.content).unwrap();
        assert_eq!(
            content,
            AgentStateContent {
                agent_id: "agent-0".to_string(),
                treasury_sats: 1_234,
                runway_secs: Some(42),
                lifecycle: "running".to_string(),
                backend: "firecracker".to_string(),
                lease_holder_node: None,
                lease_term: None,
            }
        );
        // The lease fields serialize as JSON null (sovereign = no Raft lease).
        let raw: serde_json::Value = serde_json::from_str(&event.content).unwrap();
        assert!(raw["lease_holder_node"].is_null());
        assert!(raw["lease_term"].is_null());

        // A first-tick state with no established burn rate: runway_secs is null.
        let no_runway_content = AgentStateContent::sovereign("agent-0", 3_000, None, "running", "vz");
        let no_runway = build_agent_state(&no_runway_content, "node-1")
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();
        let raw2: serde_json::Value = serde_json::from_str(&no_runway.content).unwrap();
        assert!(raw2["runway_secs"].is_null(), "no burn rate yet -> null runway");
        assert_eq!(raw2["backend"], "vz");

        // The final dead state at budget-death: treasury 0, lifecycle "dead".
        let dead_content = AgentStateContent::sovereign("agent-0", 0, None, "dead", "firecracker");
        let dead = build_agent_state(&dead_content, "node-1")
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();
        let dc: AgentStateContent = serde_json::from_str(&dead.content).unwrap();
        assert_eq!(dc.lifecycle, "dead");
        assert_eq!(dc.treasury_sats, 0);
    }

    #[test]
    fn resolve_key_path_defaults_and_overrides() {
        let dir = tempdir();
        // None -> state_dir/node.nostr.key
        let p = NodeIdentity::resolve_key_path(None, &dir);
        assert_eq!(p, dir.join(DEFAULT_KEY_FILE));
        // explicit file path -> verbatim
        let f = dir.join("custom.key");
        let p2 = NodeIdentity::resolve_key_path(Some(&f), &dir);
        assert_eq!(p2, f);
        // explicit existing dir -> dir/node.nostr.key
        let sub = dir.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let p3 = NodeIdentity::resolve_key_path(Some(&sub), &dir);
        assert_eq!(p3, sub.join(DEFAULT_KEY_FILE));
        cleanup(&dir);
    }

    // Minimal temp-dir helpers (no extra dev-dep; uses the OS temp dir + pid + a
    // counter so parallel tests do not collide).
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("kirby-nerve-test-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn cleanup(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }
}
