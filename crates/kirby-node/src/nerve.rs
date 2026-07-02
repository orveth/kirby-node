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

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};

use kirby_proto::{
    InboundEvent, InboundKind, KIND_KIRBY_AGENT_STATE, KIND_KIRBY_LIFECYCLE, KIND_KIRBY_PRESENCE,
    NIP90_JOB_REQUEST_KIND_MAX, NIP90_JOB_REQUEST_KIND_MIN,
};

use crate::quorum_signer::QuorumSigner;

/// S3e: how the agent's PUBLIC beacons (presence 10100 / lifecycle 9100 / agent-state
/// 31000) are signed. The agent's identity for ALL its Nostr output is ONE key:
///   * `NodeKey` — the single-agent / non-FROST path (`kirby run` with no
///     `frost_keystore_dir`). Beacons sign with the node identity key, BYTE-IDENTICAL to
///     the pre-S3e behavior (G-CLEAN). This is the existing `connect_client(.signer(node))`
///     + `send_event_builder` path.
///   * `Frost` — a FROST tenant (the supervisor provisioned a per-agent keystore). Beacons
///     are quorum-signed under the SAME group taproot key Q the actuator's voice (S3c/S3d)
///     uses, so EVERY public event the agent emits -- voice AND beacons -- is signed by Q
///     ("Q signs everything", gudnuf's decision A). The event is built locally, the JSON +
///     tags are co-signed by the 2-of-3 quorum (guardian membrane on every holder), and
///     the PRE-SIGNED event is published via `send_event` (NOT `send_event_builder`; there
///     is no node-local key).
///
/// COST NOTE (S5/S6): the Frost branch runs a full quorum ceremony PER beacon (every
/// presence interval). For S3 the holders are co-located in-process (sub-ms), so this is
/// fine. When holders move off-box (S5/S6) a ceremony per presence beacon is too expensive
/// on the wire -- that lane MUST adopt a cheaper presence cadence or a short-lived session
/// sub-key delegated by Q. Not built here.
#[derive(Clone)]
pub enum BeaconSigner {
    /// Sign beacons with the node identity key (single-agent / non-FROST; unchanged path).
    NodeKey(NodeIdentity),
    /// Sign beacons with the agent's FROST quorum key Q (a FROST tenant).
    Frost(Arc<QuorumSigner>),
}

impl BeaconSigner {
    /// The public key beacons are signed under (the node key, or the FROST group key Q).
    pub fn public_key(&self) -> anyhow::Result<PublicKey> {
        match self {
            BeaconSigner::NodeKey(identity) => Ok(identity.public_key()),
            BeaconSigner::Frost(quorum) => PublicKey::from_slice(&quorum.q_bytes())
                .map_err(|e| anyhow::anyhow!("FROST group key Q is not a valid x-only key: {e}")),
        }
    }

    /// The npub beacons are signed under (the agent's stable public identity).
    pub fn npub(&self) -> String {
        self.public_key()
            .ok()
            .and_then(|pk| pk.to_bech32().ok())
            .unwrap_or_default()
    }
}

impl From<NodeIdentity> for BeaconSigner {
    fn from(identity: NodeIdentity) -> Self {
        BeaconSigner::NodeKey(identity)
    }
}

/// FROST-sign a Nostr event (the given `kind`/`tags`/`content`) under the quorum key Q
/// and re-materialize + locally-VERIFY it as a nostr-sdk [`Event`] before it is published.
/// Fail closed: if the aggregate signature is bad the event is never built (so a broken
/// quorum never reaches the relay). Mirrors the actuator's `frost_sign_event`. The beacon
/// JSON content is signed VERBATIM (the note sanitizer is kind:1-only, inside the signer).
fn frost_sign_beacon(
    quorum: &QuorumSigner,
    kind: u16,
    tags: &[Tag],
    content: &str,
    created_at: u64,
) -> anyhow::Result<Event> {
    // Convert nostr-sdk Tags into the `Vec<Vec<String>>` the FROST id is computed over
    // (the exact wire form NIP-01 hashes). The guardian re-derives the id over these.
    let tag_vecs: Vec<Vec<String>> = tags.iter().map(|t| t.as_slice().to_vec()).collect();
    let signed = quorum
        .sign_nostr_event_with_tags(kind as u32, created_at, &tag_vecs, content)
        .context("FROST quorum failed to co-sign the beacon event")?;
    // Re-materialize from NIP-01 JSON and VERIFY locally (id + BIP-340 sig under Q) before
    // sending -- fail closed if the aggregate is bad.
    let json = serde_json::to_string(&signed).context("serialize FROST-signed beacon to JSON")?;
    let event =
        Event::from_json(&json).map_err(|e| anyhow::anyhow!("parse FROST-signed beacon: {e}"))?;
    event
        .verify()
        .map_err(|e| anyhow::anyhow!("FROST-signed beacon failed local verification: {e}"))?;
    Ok(event)
}

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
/// The CANONICAL SOCIAL binding tag (`["social",<hex>]`) on the Q-signed 31000 beacon
/// (the discovery spine, #76). Its value is the 32-byte HEX pubkey of the agent's
/// canonical social key (= the DM key = the kind:0/kind:10050 signer = the NIP-17
/// recipient). Because the 31000 is signed by the sovereign Q, this binding is
/// FORGE-PROOF: it lets a reader resolve `agent_id -> the ONE live DM target` under an
/// authority (Q) the social key cannot self-assert (a canonical-self-signed binding
/// would be circular/forgeable if the social key leaked). Absent for non-DM agents.
const TAG_SOCIAL: &str = "social";

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

/// Build the presence beacon's `(content_json, tags)`: a REPLACEABLE
/// `KIND_KIRBY_PRESENCE` event whose content is the presence JSON and whose tags
/// mirror the node_id (and endpoint, if any) for read-path legibility. The node-key
/// path wraps this in an [`EventBuilder`]; the FROST path feeds the SAME content+tags
/// into the quorum so both sign byte-identical events.
fn build_presence_parts(
    node_id: &str,
    endpoint: Option<&str>,
) -> anyhow::Result<(String, Vec<Tag>)> {
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
    Ok((json, tags))
}

/// Build a presence [`EventBuilder`] (the node-key signing path). Kept for the
/// non-FROST presence publish (and the existing presence tests).
fn build_presence(node_id: &str, endpoint: Option<&str>) -> anyhow::Result<EventBuilder> {
    let (json, tags) = build_presence_parts(node_id, endpoint)?;
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
fn build_lifecycle_parts(
    agent_id: &str,
    node_id: &str,
    event: &str,
    treasury_sats: u64,
    reason: &str,
) -> anyhow::Result<(String, Vec<Tag>)> {
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
    Ok((json, tags))
}

/// Build a 9100 lifecycle [`EventBuilder`] (the node-key signing path).
fn build_lifecycle(
    agent_id: &str,
    node_id: &str,
    event: &str,
    treasury_sats: u64,
    reason: &str,
) -> anyhow::Result<EventBuilder> {
    let (json, tags) = build_lifecycle_parts(agent_id, node_id, event, treasury_sats, reason)?;
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

/// Add `relay_url` to `client` with the client-side keepalive ping DISABLED.
///
/// `nostr-relay-pool` pings the relay every `PING_INTERVAL` (55s) and self-terminates
/// the connection with `Error::NotRepliedToPing` if a single ping is unanswered before
/// the next tick. On a high-latency node (e.g. a far macOS node at ~190ms RTT) a
/// transient stall across one 55s window self-kills the connection; repeated kills drop
/// the relay's success rate until the pool terminates it and the presence task exits —
/// the node then looks dead in the fleet/UI even though its agent is alive. We re-publish
/// the presence beacon every interval (<=15s), so the 55s keepalive is pure downside;
/// `reconnect` (default true) still recovers genuine drops. The `Client::add_relay`
/// shortcut uses default opts (which include PING), so go through the pool to override.
///
/// Shared by every long-lived fleet relay client — the presence beacon, the lease
/// observer, and the reconcile observer — so none of them self-kills on a laggy path
/// (a self-killed observer goes blind, which a failover loop reads as "every peer stale").
pub async fn add_relay_no_ping(client: &Client, relay_url: &str) -> anyhow::Result<()> {
    client
        .pool()
        .add_relay(relay_url, RelayOptions::new().ping(false))
        .await
        .with_context(|| format!("add relay {relay_url}"))?;
    Ok(())
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
    add_relay_no_ping(&client, relay_url).await?;
    client.connect().await;
    Ok(client)
}

/// Build a connected Nostr [`Client`] for a [`BeaconSigner`]:
///   * `NodeKey` — the client carries the node-key signer (the existing
///     `send_event_builder` path, byte-identical to pre-S3e).
///   * `Frost` — the client carries NO signer (a FROST beacon is signed by the quorum
///     and published as a PRE-SIGNED owned `Event` via `send_event`; there is no
///     node-local key), mirroring the actuator's `connect_frost`.
async fn connect_beacon_client(signer: &BeaconSigner, relay_url: &str) -> anyhow::Result<Client> {
    let client = match signer {
        BeaconSigner::NodeKey(identity) => {
            Client::builder().signer(identity.keys().clone()).build()
        }
        // No `.signer(..)`: a FROST beacon is signed by the quorum, never by a local key.
        BeaconSigner::Frost(_) => Client::builder().build(),
    };
    add_relay_no_ping(&client, relay_url).await?;
    client.connect().await;
    Ok(client)
}

/// Build a connected, read-only Nostr [`Client`] (a throwaway identity) for the
/// fleet read path: it only queries, never publishes, so it needs no node identity.
/// Reused by the hibernation wake-request fetch path ([`crate::hibernate::wake`]).
pub(crate) async fn connect_reader(relay_url: &str) -> anyhow::Result<Client> {
    let client = Client::builder().signer(Keys::generate()).build();
    add_relay_no_ping(&client, relay_url).await?;
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
/// Beacons are signed by `signer`: the node key (`NodeKey`, the existing path) OR the
/// agent's FROST quorum key Q (`Frost`, the per-agent sovereign path -- "Q signs
/// everything"). The function returns when `shutdown` resolves (a graceful stop), or on
/// an unrecoverable client error.
pub async fn run_presence(
    signer: BeaconSigner,
    config: PresenceConfig,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let me = signer
        .public_key()
        .context("resolve the presence signer's public key")?;
    let my_npub = signer.npub();
    tracing::info!(
        npub = %my_npub,
        node_id = %config.node_id,
        relay = %config.relay_url,
        interval_secs = config.interval.as_secs(),
        stale_after_secs = config.stale_after.as_secs(),
        frost = matches!(signer, BeaconSigner::Frost(_)),
        "presence task starting (the fleet nerve)"
    );

    let client = connect_beacon_client(&signer, &config.relay_url).await?;

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
    publish_presence(&client, &signer, &config).await;

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
                publish_presence(&client, &signer, &config).await;
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

// ============================================================================
// INBOUND DELIVERY (earn-loop Component 1, daemon half): the daemon -> genome inbox.
//
// This is a NEW ATTACKER-CONTROLLED ENTRY POINT. The inbound subscription is the
// trust boundary: every relay event is signature-verified, kind-allowlisted
// (default-deny), and size-capped BEFORE it becomes a typed [`InboundEvent`] on a
// bounded per-genome queue. The genome NEVER sees a raw relay frame -- it long-polls
// the typed queue over the SAME outbound vsock gRPC channel (`PollInbox`), so the
// genome stays a pure client and the C-5 egress lockdown is untouched (this task is
// host-side network, exactly like `run_presence`).
//
// SAFETY ORDER (1.3), enforced in `verify_and_enqueue` for every event, BEFORE the
// queue: (1) signature-verify -- bad sig => DROP + log; (2) kind-allowlist via a fixed
// host-side table -- unrecognized => DROP + log; (3) size-cap the extracted payload --
// oversized => DROP + log, never TRUNCATE (a truncation could split a multibyte
// boundary, the `capable.rs` reasoning); (4) re-emit as a typed `InboundEvent` with a
// monotonic `inbox_seq` and enqueue on a BOUNDED queue (drop-oldest on overflow so the
// relay task never blocks and the host never OOMs).
// ============================================================================

/// The hard byte cap on a single inbound payload the daemon will deliver to the genome.
/// Reuses the engram value ceiling (`rail::MAX_MEMORY_VALUE_BYTES`) so the two inbound
/// and durable-store bounds cannot drift. An oversized extracted payload is DROPPED (not
/// truncated): a truncation could sever a multibyte char, the same reasoning as the
/// publish-note cap and `capable.rs`'s byte-boundary discipline.
pub const MAX_INBOUND_PAYLOAD_BYTES: usize = crate::rail::MAX_MEMORY_VALUE_BYTES;

/// The hard byte cap on a single inbound NIP-17 DM's decrypted plaintext content. A SEPARATE,
/// LOWER bound than [`MAX_INBOUND_PAYLOAD_BYTES`] precisely because the general inbound cap can
/// NEVER bite on the DM path: nostr's NIP-44 v2 hard-caps an encryptable plaintext at 65_408 B,
/// and a kind:14 DM rumor is sealed as its FULL JSON (id/pubkey/created_at/kind/tags/content +
/// base64 framing), so the structurally MAX deliverable DM `content` is only ~40 KB -- already
/// below the 65_535 general cap, leaving that check dead code on this path. 16 KiB sits well
/// under that ~40 KB reachable ceiling, so this cap GENUINELY bites a hostile/oversized DM (drop,
/// never truncate -- a truncation could sever a multibyte char). A DM is a short human message;
/// 16 KiB is generous for that and bounds the bytes the daemon hands the genome to think on.
pub const MAX_INBOUND_DM_BYTES: usize = 16_384;

/// The bounded capacity of a per-genome inbound queue. On overflow the daemon drops the
/// OLDEST queued event and logs (back-pressure that never blocks the relay task and never
/// OOMs the host). 1024 is generous for a long-poll consumer that drains on every tick.
pub const INBOUND_QUEUE_CAP: usize = 1024;

/// The dedup memory bound for an [`InboundQueue`]: how many recently-delivered correlation ids
/// (gift-wrap event ids) it remembers so a re-fetch cannot re-enqueue an already-delivered DM
/// (#103). Far above any realistic per-run DM volume; past it the OLDEST id is forgotten (a later
/// re-fetch of a very old, long-since-acked DM could then re-enqueue, harmless for the MVP volume).
pub const INBOUND_DEDUP_CAP: usize = 10_000;

/// The bounded wait for one DM backfill sweep's stored-wrap fetch (REQ -> EOSE). A slow relay that
/// never sends EOSE yields an empty sweep (the next tick retries) instead of wedging the DM task.
const DM_BACKFILL_FETCH_TIMEOUT_SECS: u64 = 5;

/// A bounded set of already-processed correlation ids (gift-wrap event ids) — the DM-delivery
/// dedup memory. It makes a re-delivered gift wrap idempotent so the backfill sweep (or a relay
/// re-REQ) can never enqueue the same DM twice, which would re-drive a reply the genome already
/// sent. Insertion order is tracked so the memory stays flat (drop-oldest at `cap`).
struct SeenIds {
    set: HashSet<String>,
    order: VecDeque<String>,
    cap: usize,
}

impl SeenIds {
    fn new(cap: usize) -> Self {
        SeenIds { set: HashSet::new(), order: VecDeque::new(), cap: cap.max(1) }
    }

    /// Record `id`; returns `true` if it was NEW (never seen), `false` if a duplicate. On a new id
    /// past `cap`, evicts the oldest first (bounded memory).
    fn insert(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return false;
        }
        while self.order.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            } else {
                break;
            }
        }
        self.set.insert(id.to_string());
        self.order.push_back(id.to_string());
        true
    }
}

/// The fixed HOST-SIDE kind-allowlist table (1.3, step 2): map a raw relay event kind to
/// a typed [`InboundKind`], default-deny. An unrecognized kind returns `None` and is
/// DROPPED. Only `JOB_REQUEST` (NIP-90 requests, kinds 5000-5999) is wired end-to-end this
/// chunk -- the earn trigger; MENTION / DIRECT_MESSAGE / PAYMENT_SETTLED are reserved in the
/// enum for additive growth but no relay kind maps to them yet (PAYMENT_SETTLED is
/// daemon-produced in a later chunk, never a foreign relay event). Adding a future surface
/// is a new arm here, exactly like the `capable.rs` positive-allowlist discipline.
pub fn classify_inbound_kind(relay_kind: u16) -> Option<InboundKind> {
    if (NIP90_JOB_REQUEST_KIND_MIN..=NIP90_JOB_REQUEST_KIND_MAX).contains(&relay_kind) {
        Some(InboundKind::JobRequest)
    } else {
        None
    }
}

/// Extract the TYPED, size-capped payload bytes for an allowlisted inbound kind from a
/// verified relay event. The genome never sees the raw frame: for a `JOB_REQUEST` the
/// daemon hands the genome the bounded job-input TEXT (the event content), which the
/// genome later parses with its own positive-allowlist parser (a later chunk). Returns
/// `None` if the extracted payload exceeds [`MAX_INBOUND_PAYLOAD_BYTES`] (DROP, never
/// truncate).
fn extract_payload(kind: InboundKind, event: &Event) -> Option<Vec<u8>> {
    let payload = match kind {
        // The job input the genome will think on. The content is opaque text here; the
        // genome applies its own total parser. We deliver the raw content BYTES.
        InboundKind::JobRequest => event.content.as_bytes().to_vec(),
        // No foreign relay kind maps to these yet (see `classify_inbound_kind`); a future
        // chunk wires their extraction. Treat as not-extractable (drop) for now.
        _ => return None,
    };
    if payload.len() > MAX_INBOUND_PAYLOAD_BYTES {
        return None;
    }
    Some(payload)
}

/// The per-genome BOUNDED inbound queue: the typed, daemon-verified events waiting for the
/// genome to `PollInbox`. Cheap to clone (`Arc`), so the relay task (the producer) and the
/// gateway service (the long-poll consumer) share one handle. The queue assigns a
/// MONOTONIC `inbox_seq` to every accepted event (an [`AtomicU64`]), so a genome's `ack_seq`
/// cursor makes delivery exactly-once across a redial (never re-deliver, never skip). A
/// [`tokio::sync::Notify`] lets a parked long-poll wake the instant an event lands.
#[derive(Clone)]
pub struct InboundQueue {
    inner: Arc<Mutex<VecDeque<InboundEvent>>>,
    /// The next `inbox_seq` to assign. Monotonic for the queue's lifetime; never reused even
    /// after a drop-oldest eviction (the cursor must never go backwards).
    next_seq: Arc<AtomicU64>,
    cap: usize,
    /// Wakes a parked `PollInbox` the instant a new event is enqueued (long-poll latency).
    notify: Arc<tokio::sync::Notify>,
    /// The DM-delivery dedup memory (gift-wrap event ids already enqueued this queue's lifetime),
    /// so the backfill sweep re-fetching stored wraps never double-enqueues a DM (#103). Bounded
    /// (drop-oldest at [`INBOUND_DEDUP_CAP`]). Shared across clones so the persistent-subscription
    /// producer and the backfill-sweep producer dedupe against ONE memory.
    seen: Arc<Mutex<SeenIds>>,
}

impl InboundQueue {
    /// A bounded queue with the default capacity ([`INBOUND_QUEUE_CAP`]).
    pub fn new() -> Self {
        Self::with_capacity(INBOUND_QUEUE_CAP)
    }

    /// A bounded queue with an explicit capacity (tests use a small cap to exercise the
    /// drop-oldest path). `inbox_seq` starts at 1 so 0 is a sentinel "no events consumed"
    /// (a genome's initial `ack_seq = 0` then receives seq >= 1).
    pub fn with_capacity(cap: usize) -> Self {
        InboundQueue {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            next_seq: Arc::new(AtomicU64::new(1)),
            cap: cap.max(1),
            notify: Arc::new(tokio::sync::Notify::new()),
            seen: Arc::new(Mutex::new(SeenIds::new(INBOUND_DEDUP_CAP))),
        }
    }

    /// Enqueue an already-CLASSIFIED, already-SIZE-CAPPED typed event, assigning it the next
    /// monotonic `inbox_seq`. On overflow the OLDEST queued event is evicted (drop-oldest
    /// back-pressure) and logged. Returns the assigned `inbox_seq`. The caller MUST have run
    /// the verify -> allowlist -> size-cap pipeline first (`verify_and_enqueue` does).
    pub fn push_typed(
        &self,
        kind: InboundKind,
        payload: Vec<u8>,
        source_pubkey: String,
        created_at: u64,
        correlation_id: String,
    ) -> u64 {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let event = InboundEvent {
            inbox_seq: seq,
            kind: kind as i32,
            payload,
            source_pubkey,
            created_at,
            correlation_id,
        };
        {
            let mut q = self.inner.lock().expect("inbound queue poisoned");
            while q.len() >= self.cap {
                if let Some(dropped) = q.pop_front() {
                    tracing::warn!(
                        dropped_seq = dropped.inbox_seq,
                        cap = self.cap,
                        "inbound queue full; dropped the OLDEST event (back-pressure)"
                    );
                }
            }
            q.push_back(event);
        }
        // Wake any parked long-poll: an event is now drainable.
        self.notify.notify_waiters();
        seq
    }

    /// Like [`push_typed`](Self::push_typed) but IDEMPOTENT on `correlation_id` (#103): if this
    /// correlation id was already enqueued (this queue's lifetime, bounded memory), the event is
    /// DROPPED and `None` returned; otherwise it is enqueued and its `inbox_seq` returned. The DM
    /// path uses this so the backfill sweep re-fetching stored gift wraps (or a relay re-REQ) never
    /// double-enqueues a DM already delivered live — which, once the genome advanced its `ack_seq`
    /// past it, would re-drive a reply the genome already sent. The check-and-record is atomic
    /// under one lock, so the persistent-subscription producer and the backfill producer cannot
    /// both enqueue the same wrap in a race. An EMPTY `correlation_id` is not deduped (nothing to
    /// key on) and always enqueues.
    pub fn push_typed_once(
        &self,
        kind: InboundKind,
        payload: Vec<u8>,
        source_pubkey: String,
        created_at: u64,
        correlation_id: String,
    ) -> Option<u64> {
        if !correlation_id.is_empty() {
            let mut seen = self.seen.lock().expect("inbound dedup set poisoned");
            if !seen.insert(&correlation_id) {
                return None;
            }
        }
        Some(self.push_typed(kind, payload, source_pubkey, created_at, correlation_id))
    }

    /// Collect every queued event with `inbox_seq > ack_seq` whose kind is in `want` (the
    /// already-intersected effective set; an EMPTY `want` means deliver ALL kinds), returned
    /// oldest-first. The `ack_seq` cursor is the genome's CONFIRMED progress: any event with
    /// `seq <= ack_seq` is PRUNED here (the genome has consumed it; never re-deliver, never
    /// keep it forever). Delivered-but-unacked events (`seq > ack_seq`) STAY queued, so
    /// delivery is at-least-once on the wire and exactly-once at the genome via the monotonic
    /// cursor (a redial + re-poll at the same ack_seq re-delivers, and the genome dedupes;
    /// once the genome advances ack_seq past them, the next poll prunes them). An event whose
    /// kind is NOT in `want` also stays queued (a later, broader want can still see it). This
    /// mirrors the gateway `idempotency_key` idiom: the cursor, not the queue, is the
    /// exactly-once authority.
    fn drain_after(&self, ack_seq: u64, want: &[InboundKind]) -> Vec<InboundEvent> {
        let mut q = self.inner.lock().expect("inbound queue poisoned");
        // Prune everything the genome has CONFIRMED consuming (seq <= ack_seq).
        q.retain(|ev| ev.inbox_seq > ack_seq);
        // Collect (without removing) the events this poll's `want` matches.
        q.iter()
            .filter(|ev| want.is_empty() || want.iter().any(|k| *k as i32 == ev.kind))
            .cloned()
            .collect()
    }

    /// Current queued depth (test/diagnostic).
    pub fn len(&self) -> usize {
        self.inner.lock().expect("inbound queue poisoned").len()
    }

    /// Whether the queue is empty (test/diagnostic).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The long-poll DRAIN the gateway's `PollInbox` calls. Returns immediately with any
    /// events `> ack_seq` matching `want`; otherwise PARKS up to `wait` (waking the instant
    /// an event is enqueued), then returns whatever is drainable (possibly empty on the
    /// deadline, so the genome re-polls). `want` is the EFFECTIVE set (already intersected
    /// with the session allowlist by the caller); empty => all kinds.
    pub async fn poll(
        &self,
        ack_seq: u64,
        want: &[InboundKind],
        wait: Duration,
    ) -> Vec<InboundEvent> {
        // Fast path: something is already drainable.
        let first = self.drain_after(ack_seq, want);
        if !first.is_empty() {
            return first;
        }
        // Slow path: park until an event lands OR the deadline elapses. Re-check on each
        // wake (a notify could be for an event a NARROWER want does not match).
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = self.notify.notified();
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Vec::new();
            }
            tokio::select! {
                _ = notified => {
                    let batch = self.drain_after(ack_seq, want);
                    if !batch.is_empty() {
                        return batch;
                    }
                    // Spurious for this want (e.g. an event of an unwanted kind): keep parking.
                }
                _ = tokio::time::sleep(remaining) => {
                    // Deadline: return an empty batch so the genome re-polls.
                    return self.drain_after(ack_seq, want);
                }
            }
        }
    }
}

impl Default for InboundQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// The verify -> allowlist -> size-cap -> typed-enqueue pipeline for ONE relay event
/// (1.3). This is the trust boundary: it is the ONLY way a foreign event reaches the
/// genome's inbox, and it NEVER panics on hostile input (a malformed event is a DROP +
/// log, never a crash). Returns the assigned `inbox_seq` on accept, `None` on any drop.
///
/// Order is load-bearing:
///   1. `event.verify()` (id + schnorr signature). A bad signature => DROP + log. nostr-sdk
///      treats relay events as pre-verified, but the daemon is the trust boundary now, so we
///      verify EXPLICITLY -- never assume the relay checked.
///   2. `classify_inbound_kind` (default-deny). An unrecognized kind => DROP + log.
///   3. `extract_payload` + size-cap. An oversized payload => DROP + log (never truncate).
///   4. enqueue as a typed `InboundEvent` with a monotonic `inbox_seq` (drop-oldest on full).
pub fn verify_and_enqueue(queue: &InboundQueue, event: &Event) -> Option<u64> {
    // (1) Signature-verify EXPLICITLY -- the daemon is the trust boundary.
    if let Err(e) = event.verify() {
        tracing::warn!(error = %e, "inbound: DROPPED event with a bad signature/id");
        return None;
    }
    // (2) Kind-allowlist (default-deny).
    let kind = match classify_inbound_kind(event.kind.as_u16()) {
        Some(k) => k,
        None => {
            tracing::warn!(
                relay_kind = event.kind.as_u16(),
                "inbound: DROPPED event of an unrecognized/unallowlisted kind (default-deny)"
            );
            return None;
        }
    };
    // (3) Size-cap the EXTRACTED typed payload (drop, never truncate).
    let payload = match extract_payload(kind, event) {
        Some(p) => p,
        None => {
            tracing::warn!(
                relay_kind = event.kind.as_u16(),
                cap = MAX_INBOUND_PAYLOAD_BYTES,
                "inbound: DROPPED event whose extracted payload was oversized or unextractable"
            );
            return None;
        }
    };
    // (4) Re-emit as a typed event with a monotonic seq; correlation_id = the source event
    // id (a stable per-job id the genome can echo back when it delivers + charges).
    let seq = queue.push_typed(
        kind,
        payload,
        event.pubkey.to_hex(),
        event.created_at.as_secs(),
        event.id.to_hex(),
    );
    tracing::info!(
        inbox_seq = seq,
        ?kind,
        relay_kind = event.kind.as_u16(),
        source = %event.pubkey.to_hex(),
        "inbound: VERIFIED + enqueued a typed event"
    );
    Some(seq)
}

/// Run the persistent INBOUND subscription task to completion (until `shutdown` fires), the
/// SIBLING of [`run_presence`]. It connects a read client, subscribes with a `#p`-addressed
/// filter (events tagged to THIS node's pubkey) for the allowlisted kinds, and runs the
/// `verify_and_enqueue` pipeline on every notification, feeding the shared [`InboundQueue`]
/// the gateway drains via `PollInbox`. Pure host-side network, exactly like presence: it
/// touches no genome, no socket into the VM, no egress path. Returns on graceful shutdown or
/// an unrecoverable client error.
pub async fn run_inbound(
    identity: &NodeIdentity,
    relay_url: &str,
    queue: InboundQueue,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let me = identity.public_key();
    tracing::info!(
        npub = %identity.npub(),
        relay = %relay_url,
        "inbound subscription task starting (the earn-loop inbox)"
    );

    let client = connect_reader(relay_url).await?;
    // Subscribe to the allowlisted inbound kinds ADDRESSED to this node (`#p` = node pubkey).
    // JOB_REQUEST = NIP-90 requests (kinds 5000-5999). The relay filter is a coarse prefilter;
    // `verify_and_enqueue` is the authoritative wall (it re-verifies + re-allowlists every
    // event, never trusting the filter or the relay).
    let kinds: Vec<Kind> = (NIP90_JOB_REQUEST_KIND_MIN..=NIP90_JOB_REQUEST_KIND_MAX)
        .map(Kind::from)
        .collect();
    let filter = Filter::new().kinds(kinds).pubkey(me);
    client
        .subscribe(filter, None)
        .await
        .context("subscribe to the inbound (earn) surface")?;

    let mut notifications = client.notifications();
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!(npub = %identity.npub(), "inbound task shutting down");
                break;
            }
            notif = notifications.recv() => {
                match notif {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        // The trust boundary: verify -> allowlist -> size-cap -> enqueue.
                        verify_and_enqueue(&queue, &event);
                    }
                    Ok(RelayPoolNotification::Shutdown) => {
                        tracing::warn!("relay pool shut down; inbound task stopping");
                        break;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "inbound notifications lagged; some events skipped");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::warn!("inbound notification channel closed; task stopping");
                        break;
                    }
                }
            }
        }
    }

    client.disconnect().await;
    Ok(())
}

// ============================================================================
// NIP-17 DM INBOUND (task #12): the agent receives + replies to encrypted DMs.
//
// A SECOND attacker-controlled entry point, SEPARATE from the job-request inbound above.
// NIP-17 wraps a message as kind:14 rumor -> kind:13 seal (NIP-44-enc to the recipient,
// signed by the sender's REAL key) -> kind:1059 gift wrap (NIP-44-enc, signed by a fresh
// throwaway key). Decrypting it needs a PLAIN keypair the daemon holds in full (NIP-44 is
// ECDH), so the DM path is bound to a DEDICATED PLAIN DM key -- NEVER the FROST money key Q
// (a threshold key cannot ECDH) and (by the "new entry point needs its own guards" rule, as
// keys) NOT the publish key or the memory/engram key either. A DM-path compromise then costs
// only DM privacy. The screened DM feeds the SAME bounded `InboundQueue` the gateway drains.
// ============================================================================

/// The DM trust boundary: verify -> unwrap -> assert-DM -> size-cap -> typed-enqueue for ONE
/// inbound NIP-17 gift wrap (kind:1059). The SIBLING of [`verify_and_enqueue`], but it holds the
/// DEDICATED PLAIN DM key to NIP-44-DECRYPT (a gift wrap is opaque without it), so it is async +
/// key-holding where the job-request path is pure. It is the ONLY way a DM reaches the genome's
/// inbox and it NEVER panics on hostile input (every failure is a DROP + log). Returns the
/// assigned `inbox_seq` on accept, `None` on any drop.
///
/// Order is load-bearing:
///   1. `event.verify()` -- cheap reject of a malformed/forged 1059 BEFORE the NIP-44 decrypt.
///   2. assert `event.kind == GiftWrap` -- the wall re-checks the relay filter, never trusts it.
///   3. `UnwrappedGift::from_gift_wrap(dm_keys, event)` -- NIP-44-decrypt the wrap -> seal, VERIFY
///      the seal signature, decrypt -> rumor, and ENFORCE `rumor.pubkey == seal.pubkey`. The
///      learned `sender` is the SEAL-verified author -- the REAL sender, NEVER the throwaway 1059
///      pubkey (the whole point of gift-wrap metadata privacy). A decrypt / seal-verify /
///      sender-mismatch failure (incl. a wrap not addressed to us) => DROP + log.
///   4. assert `rumor.kind == PrivateDirectMessage` (14) -- a wrap may carry a non-DM rumor; drop it.
///   5. size-cap the rumor content (drop, never truncate).
///   6. enqueue as a typed `DIRECT_MESSAGE` with `source_pubkey = sender` (the seal-verified
///      sender) -- BOTH the screening identity AND the reply-to recipient, so the one value guards
///      delivery integrity + anti-spoof together.
pub async fn screen_and_enqueue_dm<S: nostr_sdk::NostrSigner>(
    queue: &InboundQueue,
    signer: &S,
    event: &Event,
) -> Option<u64> {
    use nostr_sdk::nips::nip59::UnwrappedGift;
    // (1) Cheap reject: verify the gift-wrap id + signature BEFORE the expensive decrypt.
    if let Err(e) = event.verify() {
        tracing::warn!(error = %e, "inbound DM: DROPPED a gift wrap with a bad signature/id");
        return None;
    }
    // (2) The wall re-checks the kind; never trust the relay filter.
    if event.kind != Kind::GiftWrap {
        tracing::warn!(
            relay_kind = event.kind.as_u16(),
            "inbound DM: DROPPED a non-1059 event on the DM subscription"
        );
        return None;
    }
    // (3) Unwrap with the PLAIN DM key: decrypt + seal-verify + learn the REAL sender from the seal.
    let unwrapped = match UnwrappedGift::from_gift_wrap(signer, event).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "inbound DM: DROPPED a gift wrap that failed to unwrap (decrypt / seal-verify / sender-mismatch / not-for-us)"
            );
            return None;
        }
    };
    // (4) Only an actual NIP-17 DM rumor (kind:14) is accepted.
    if unwrapped.rumor.kind != Kind::PrivateDirectMessage {
        tracing::warn!(
            rumor_kind = unwrapped.rumor.kind.as_u16(),
            "inbound DM: DROPPED a gift wrap whose rumor was not a kind:14 DM"
        );
        return None;
    }
    // (5) Size-cap the decrypted message (drop, never truncate -- a truncation could sever a
    // multibyte char, the same discipline as the job-request path). NOTE: a DEDICATED, LOWER cap
    // ([`MAX_INBOUND_DM_BYTES`]) -- the general [`MAX_INBOUND_PAYLOAD_BYTES`] (65_535) can never
    // bite here because NIP-44's ~40 KB structural ceiling on a sealed kind:14 rumor's content
    // already sits below it (see the constant's doc). A DM is a short human message.
    let payload = unwrapped.rumor.content.as_bytes().to_vec();
    if payload.len() > MAX_INBOUND_DM_BYTES {
        tracing::warn!(
            len = payload.len(),
            cap = MAX_INBOUND_DM_BYTES,
            "inbound DM: DROPPED an oversized message"
        );
        return None;
    }
    // (6) Enqueue with the SEAL-VERIFIED sender as source_pubkey (= the reply-to recipient),
    // IDEMPOTENT on the gift-wrap id (#103): the persistent subscription AND the backfill sweep
    // both feed this wall, so a wrap the sweep re-fetches after the live sub already delivered it is
    // a DEDUP no-op -- never a second inbox event, never a duplicate reply.
    let seq = match queue.push_typed_once(
        InboundKind::DirectMessage,
        payload,
        unwrapped.sender.to_hex(),
        unwrapped.rumor.created_at.as_secs(),
        event.id.to_hex(),
    ) {
        Some(seq) => seq,
        None => {
            tracing::debug!(
                gift_wrap = %event.id.to_hex(),
                sender = %unwrapped.sender.to_hex(),
                "inbound DM: already delivered (dedup); skipping"
            );
            return None;
        }
    };
    tracing::info!(
        inbox_seq = seq,
        sender = %unwrapped.sender.to_hex(),
        "inbound DM: VERIFIED + enqueued a NIP-17 DM"
    );
    Some(seq)
}

/// Fetches stored NIP-17 gift wraps (kind:1059, `#p` = the DM key) for the DM backfill sweep (#103)
/// — a seam so the production path (a FRESH client per sweep) and tests (an injected event set)
/// share [`dm_backfill_sweep`]'s screen -> dedup -> enqueue logic without a live relay.
#[async_trait::async_trait]
pub(crate) trait GiftWrapFetcher: Send + Sync {
    /// Fetch every stored gift wrap addressed to `me` (`#p`), with NO `since`: NIP-17 backdates a
    /// wrap's `created_at` up to 2 days, so any `since` would silently drop backdated wraps. Errors
    /// bubble up so the sweep can log + skip (the next tick retries).
    async fn fetch_stored_wraps(&self, me: PublicKey) -> anyhow::Result<Vec<Event>>;
}

/// The production [`GiftWrapFetcher`]: one FRESH throwaway client per sweep. A new TCP connection —
/// so a silently half-open persistent socket (the #54 ping-off failure mode) cannot make the sweep
/// go deaf — and a fresh event DB, so the relay pool's seen-set never suppresses a re-delivered
/// stored wrap. Connect -> REQ (no `since`) -> collect until EOSE within `timeout` -> disconnect.
struct FreshClientFetcher {
    relays: Vec<String>,
    timeout: Duration,
}

#[async_trait::async_trait]
impl GiftWrapFetcher for FreshClientFetcher {
    async fn fetch_stored_wraps(&self, me: PublicKey) -> anyhow::Result<Vec<Event>> {
        let client = Client::builder().signer(Keys::generate()).build();
        for url in &self.relays {
            add_relay_no_ping(&client, url).await?;
        }
        client.connect().await;
        let filter = Filter::new().kind(Kind::GiftWrap).pubkey(me);
        let fetched = client.fetch_events(filter, self.timeout).await;
        // Always disconnect the throwaway client, whether the fetch succeeded or errored (the sweep
        // holds no long-lived connection — that is the whole point of a fresh client per sweep).
        client.disconnect().await;
        Ok(fetched.context("DM backfill: fetch stored gift wraps")?.into_iter().collect())
    }
}

/// Run ONE DM backfill sweep (#103): fetch stored gift wraps, then run each through the DM trust
/// boundary [`screen_and_enqueue_dm`], which dedupes by gift-wrap id — so a wrap already delivered
/// live (or by an earlier sweep) is skipped, and only a genuinely-missed DM is enqueued. Returns
/// how many NEW DMs it enqueued (0 on a fetch error, logged; the next tick retries). Factored out
/// of [`run_dm_inbound`] so a test can drive it with an injected [`GiftWrapFetcher`].
async fn dm_backfill_sweep<S: nostr_sdk::NostrSigner>(
    fetcher: &dyn GiftWrapFetcher,
    signer: &S,
    me: nostr_sdk::PublicKey,
    queue: &InboundQueue,
) -> usize {
    let wraps = match fetcher.fetch_stored_wraps(me).await {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(error = %e, "DM backfill sweep: fetch failed; skipping (next tick retries)");
            return 0;
        }
    };
    let mut recovered = 0usize;
    for event in &wraps {
        if screen_and_enqueue_dm(queue, signer, event).await.is_some() {
            recovered += 1;
        }
    }
    if recovered > 0 {
        tracing::info!(
            recovered,
            fetched = wraps.len(),
            "DM backfill sweep: recovered missed DM(s) the live subscription did not deliver"
        );
    } else {
        tracing::debug!(fetched = wraps.len(), "DM backfill sweep: nothing new");
    }
    recovered
}

/// Run the persistent DM INBOUND subscription task to completion (the SIBLING of [`run_inbound`],
/// for NIP-17 private DMs). It connects a read client, subscribes to kind:1059 gift wraps
/// `#p`-addressed to the DEDICATED DM identity, and runs `screen_and_enqueue_dm` (the key-holding
/// unwrap boundary) on every notification, feeding the SAME [`InboundQueue`] the gateway drains
/// via `PollInbox`. `dm_identity` is the plain DM keypair (NEVER the FROST money key); it both
/// addresses the subscription and decrypts. Pure host-side network; touches no genome, no VM
/// socket. Returns on graceful shutdown or an unrecoverable client error.
///
/// The persistent subscription is the low-latency FAST PATH, but it is not the delivery guarantee:
/// with the keepalive ping OFF (#54) a long-lived reader cannot notice a silently half-open socket,
/// so a DM that lands during a dead window sits unread on the relay forever (#103). Every
/// `backfill_secs` this task therefore also runs a [`dm_backfill_sweep`] on a FRESH connection
/// (no `since`, deduped by gift-wrap id) so delivery is guaranteed within one interval regardless
/// of the persistent socket's state. `backfill_secs == 0` disables the sweep (fast-path only).
pub async fn run_dm_inbound(
    dm_signer: std::sync::Arc<dyn nostr_sdk::NostrSigner>,
    me: nostr_sdk::PublicKey,
    relays: &[String],
    queue: InboundQueue,
    backfill_secs: u64,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    if relays.is_empty() {
        anyhow::bail!("run_dm_inbound requires at least one relay (the agent's DM inbox relays)");
    }
    // `me` (the agent's DM identity pubkey) addresses the #p filter; `dm_signer` unwraps. For a
    // born-unified agent both are Q (the QSigner threshold-decrypts); on the pre-P1 path both
    // come from the plain dm_keys. run_dm_inbound is signer-agnostic (the gate lives at boot).
    let me_npub = me.to_bech32().unwrap_or_default();
    tracing::info!(
        dm_npub = %me_npub,
        relays = relays.len(),
        "DM inbound subscription task starting (the NIP-17 inbox)"
    );
    // Watch ALL the agent's inbox relays (the same set advertised in its kind:10050), so a DM sent
    // to any advertised relay is seen. A throwaway client signer (the read client never publishes).
    let client = Client::builder().signer(Keys::generate()).build();
    for url in relays {
        add_relay_no_ping(&client, url).await?;
    }
    client.connect().await;
    // kind:1059 gift wraps addressed to the DM pubkey (#p). The relay filter is a coarse
    // prefilter; `screen_and_enqueue_dm` is the authoritative wall (verify + unwrap + re-check).
    let filter = Filter::new().kind(Kind::GiftWrap).pubkey(me);
    client
        .subscribe(filter, None)
        .await
        .context("subscribe to the NIP-17 DM inbox")?;

    let mut notifications = client.notifications();

    // The DM backfill sweep (#103): the durable-delivery backstop for the fast-path subscription
    // above. `None` when disabled (`backfill_secs == 0`). The fetcher opens a FRESH client each
    // sweep, so it is immune to a half-open persistent socket. `interval`'s first tick fires
    // immediately; we consume it up-front so the first sweep does not race the subscription's own
    // initial no-since REQ (which already covers the startup backlog) — the first real sweep is one
    // interval later, then every interval. When disabled we still arm a long idle timer so the
    // select arm compiles; its body is a guarded no-op.
    let backfill: Option<FreshClientFetcher> = (backfill_secs > 0).then(|| FreshClientFetcher {
        relays: relays.to_vec(),
        timeout: Duration::from_secs(DM_BACKFILL_FETCH_TIMEOUT_SECS),
    });
    let sweep_period = Duration::from_secs(if backfill_secs > 0 { backfill_secs } else { 3600 });
    let mut backfill_tick = tokio::time::interval(sweep_period);
    backfill_tick.tick().await;
    if backfill.is_some() {
        tracing::info!(
            dm_backfill_secs = backfill_secs,
            "DM inbound: backfill sweep armed (durable-delivery backstop; re-fetches missed DMs on a fresh connection)"
        );
    } else {
        tracing::info!("DM inbound: backfill sweep DISABLED (dm_backfill_secs=0; persistent subscription only)");
    }

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!(dm_npub = %me_npub, "DM inbound task shutting down");
                break;
            }
            _ = backfill_tick.tick() => {
                // Re-fetch stored wraps on a fresh connection and enqueue any missed DM (deduped).
                // A slow fetch briefly parks the live-notification arm; any live event that lags out
                // of the broadcast buffer meanwhile is exactly what the next sweep recovers.
                if let Some(fetcher) = &backfill {
                    dm_backfill_sweep(fetcher, &dm_signer, me, &queue).await;
                }
            }
            notif = notifications.recv() => {
                match notif {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        // The DM trust boundary: verify -> unwrap -> assert-DM -> size-cap -> enqueue.
                        screen_and_enqueue_dm(&queue, &dm_signer, &event).await;
                    }
                    Ok(RelayPoolNotification::Shutdown) => {
                        tracing::warn!("relay pool shut down; DM inbound task stopping");
                        break;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "DM inbound notifications lagged; some events skipped");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::warn!("DM inbound notification channel closed; task stopping");
                        break;
                    }
                }
            }
        }
    }

    client.disconnect().await;
    Ok(())
}

/// Publish this agent's NIP-17 DM-inbox relay list (kind:10050 `InboxRelays`), SIGNED BY THE
/// DEDICATED DM KEY, then disconnect (a one-shot connect-publish-disconnect like the lifecycle
/// beacon). This is how a NIP-17 client learns WHERE to reach this agent: it lists the relays the
/// agent watches for inbound gift wraps (highest-leverage for inbound reach). The list is signed
/// by the DM key because that is the npub a client DMs -- a 10050 under any other key would point
/// a sender at the wrong identity. MVP: the inbox relays ARE the agent's own relay set (where it
/// also runs `run_dm_inbound`). Returns the published event id.
pub async fn publish_inbox_relay_list(
    signer: std::sync::Arc<dyn nostr_sdk::NostrSigner>,
    relays: &[String],
) -> anyhow::Result<EventId> {
    if relays.is_empty() {
        anyhow::bail!("cannot publish a kind:10050 inbox relay list with no relays");
    }
    let tags: Vec<Tag> = relays
        .iter()
        .filter_map(|r| RelayUrl::parse(r).ok().map(|url| TagStandard::Relay(url).into()))
        .collect();
    if tags.is_empty() {
        anyhow::bail!("no valid relay URLs for the kind:10050 inbox relay list");
    }
    // Sign the 10050 via `signer` -- the npub a NIP-17 client will DM. On the born-unified path
    // (P1) this is the QSigner, so the 10050 is FROST-signed UNDER Q (routed through the guardian
    // membrane, which authorizes kind:10050); otherwise the plain dm_keys. A 10050 under any other
    // key would point a sender at the wrong identity, so the signer IS the DM identity.
    let client = Client::builder().signer(signer.clone()).build();
    for r in relays {
        add_relay_no_ping(&client, r).await?;
    }
    client.connect().await;
    let builder = EventBuilder::new(Kind::InboxRelays, "").tags(tags);
    let event_id = client
        .send_event_builder(builder)
        .await
        .context("publish the kind:10050 DM-inbox relay list")?
        .val;
    client.disconnect().await;
    let dm_npub = signer
        .get_public_key()
        .await
        .ok()
        .map(|pk| pk.to_bech32().unwrap_or_default())
        .unwrap_or_default();
    tracing::info!(
        %dm_npub,
        event_id = %event_id,
        relays = relays.len(),
        "published the kind:10050 DM-inbox relay list"
    );
    Ok(event_id)
}

/// Build + SIGN this agent's CANONICAL SOCIAL profile (kind:0 `Metadata`) under the
/// CANONICAL SOCIAL (DM) KEY -- the SAME npub that signs kind:1 posts, the kind:10050
/// inbox list, and NIP-17 DMs (P1, #76). `profile_json` is the raw kind:0 content (P1
/// minimal: `{"name":"<agent_id>"}`). Signing with any other key would name the WRONG
/// identity, so this is the load-bearing plane assertion of the whole publish path.
///
/// Factored out of [`publish_metadata_profile`] (relay-free) so a test can drive the REAL
/// signer line -- mirroring how `NostrActuator::sign_canonical_note` /
/// `frost_sign_event` are factored + driven by their teeth. This is what keeps the
/// `g_metadata_profile_signed_by_canonical` tooth honest against a future wrong-key
/// regression in the production signer.
fn build_metadata_profile_event(
    dm_identity: &NodeIdentity,
    profile_json: &str,
) -> anyhow::Result<Event> {
    EventBuilder::new(Kind::Metadata, profile_json)
        .sign_with_keys(dm_identity.keys())
        .context("sign the kind:0 canonical social profile under the DM key")
}

/// Publish this agent's CANONICAL SOCIAL profile (kind:0 `Metadata`), SIGNED BY THE
/// CANONICAL SOCIAL (DM) KEY -- the SAME npub that signs kind:1 posts, the kind:10050
/// inbox list, and NIP-17 DMs (P1, #76). This is how a client puts a human-legible name
/// on the ONE npub a reader resolves an agent to. `profile_json` is the raw kind:0
/// content (P1 minimal: `{"name":"<agent_id>"}`). A one-shot connect-publish-disconnect,
/// mirroring [`publish_inbox_relay_list`]: sign the event via
/// [`build_metadata_profile_event`], build a client (no signer needed for a PRE-SIGNED
/// event), add the relays, publish via `send_event`, disconnect. Returns the published
/// event id.
pub async fn publish_metadata_profile(
    dm_identity: &NodeIdentity,
    relays: &[String],
    profile_json: &str,
) -> anyhow::Result<EventId> {
    if relays.is_empty() {
        anyhow::bail!("cannot publish a kind:0 profile with no relays");
    }
    // Sign the kind:0 with the canonical social (DM) key -- the npub a client resolves this
    // agent to (posts + profile + DM all share it). A profile under any other key would name
    // the wrong identity. The pre-signed event carries its own signer, so the client holds no
    // key (mirrors the pre-signed `send_event` publish paths above).
    let event = build_metadata_profile_event(dm_identity, profile_json)?;
    let client = Client::builder().build();
    for r in relays {
        add_relay_no_ping(&client, r).await?;
    }
    client.connect().await;
    let event_id = client
        .send_event(&event)
        .await
        .context("publish the kind:0 canonical social profile")?
        .val;
    client.disconnect().await;
    tracing::info!(
        dm_npub = %dm_identity.npub(),
        event_id = %event_id,
        relays = relays.len(),
        "published the kind:0 canonical social profile"
    );
    Ok(event_id)
}

/// Per-peer tracking state for the live presence task.
struct PeerState {
    node_id: String,
    last_seen_unix: u64,
    /// Whether we currently consider this peer stale (so we log the transition once).
    stale: bool,
}

/// Publish (or re-publish) this node's presence beacon, signed by `signer`. Logs but
/// does not fail the task on a transient publish error (the next interval retries).
///   * `NodeKey`: the existing `send_event_builder` path (the client holds the node key).
///   * `Frost`: quorum-sign the SAME content+tags under Q, then publish the PRE-SIGNED
///     owned event via `send_event` (the client holds no key).
async fn publish_presence(client: &Client, signer: &BeaconSigner, config: &PresenceConfig) {
    let result: anyhow::Result<EventId> = async {
        match signer {
            BeaconSigner::NodeKey(_) => {
                let builder = build_presence(&config.node_id, config.endpoint.as_deref())?;
                Ok(client.send_event_builder(builder).await?.val)
            }
            BeaconSigner::Frost(quorum) => {
                let (content, tags) =
                    build_presence_parts(&config.node_id, config.endpoint.as_deref())?;
                let created_at = Timestamp::now().as_secs();
                let event =
                    frost_sign_beacon(quorum, KIND_KIRBY_PRESENCE, &tags, &content, created_at)?;
                Ok(client.send_event(&event).await?.val)
            }
        }
    }
    .await;
    match result {
        Ok(event_id) => tracing::debug!(
            event_id = %event_id,
            node_id = %config.node_id,
            "published presence beacon"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "failed to publish presence beacon (will retry next interval)"
        ),
    }
}

/// Publish ONE 9100 `KIND_KIRBY_LIFECYCLE` event (a born/died milestone) to the relay,
/// signed by `signer`, then disconnect. A one-shot connect-publish-disconnect: births
/// and deaths are rare (not an interval cadence), so a dedicated short-lived client is
/// the simplest correct shape and never contends with the persistent presence client.
/// Returns the published event id on success.
///
/// Signing (S3e): `NodeKey` uses the existing `send_event_builder` path; `Frost`
/// quorum-signs the SAME content+tags under Q and publishes the PRE-SIGNED event (the
/// agent's birth/death log is signed by its sovereign Q -- "Q signs everything").
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
    signer: &BeaconSigner,
    relay_url: &str,
    agent_id: &str,
    node_id: &str,
    event: &str,
    treasury_sats: u64,
    reason: &str,
) -> anyhow::Result<String> {
    let client = connect_beacon_client(signer, relay_url).await?;
    let result: anyhow::Result<EventId> = async {
        match signer {
            BeaconSigner::NodeKey(_) => {
                let builder = build_lifecycle(agent_id, node_id, event, treasury_sats, reason)?;
                Ok(client
                    .send_event_builder(builder)
                    .await
                    .context("publish lifecycle event")?
                    .val)
            }
            BeaconSigner::Frost(quorum) => {
                let (content, tags) =
                    build_lifecycle_parts(agent_id, node_id, event, treasury_sats, reason)?;
                let created_at = Timestamp::now().as_secs();
                let ev = frost_sign_beacon(quorum, KIND_KIRBY_LIFECYCLE, &tags, &content, created_at)?;
                Ok(client
                    .send_event(&ev)
                    .await
                    .context("publish pre-signed FROST lifecycle event")?
                    .val)
            }
        }
    }
    .await;
    // Best-effort clean disconnect regardless of the send outcome.
    client.disconnect().await;
    let id = result?.to_hex();
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
fn build_agent_state_parts(
    content: &AgentStateContent,
    node_id: &str,
    canonical_npub: Option<&str>,
) -> anyhow::Result<(String, Vec<Tag>)> {
    let json = serde_json::to_string(content).context("serialize agent-state content")?;
    let mut tags: Vec<Tag> = vec![
        Tag::parse([TAG_D, &content.agent_id])?,
        Tag::parse([TAG_T, TAG_T_KIRBY])?,
        Tag::parse([TAG_A, &content.agent_id])?,
        Tag::parse([TAG_NODE, node_id])?,
    ];
    // CANONICAL SOCIAL binding (#76): when the agent has a canonical social key, carry its
    // 32-byte HEX pubkey as `["social",<hex>]` so a reader can resolve `agent_id -> the ONE
    // live DM target` off this Q-signed (forge-proof) beacon. `None` for non-DM agents ->
    // no tag, byte-identical to before.
    if let Some(hex) = canonical_npub {
        tags.push(Tag::parse([TAG_SOCIAL, hex])?);
    }
    Ok((json, tags))
}

/// Build a 31000 agent-state [`EventBuilder`] (the node-key signing path).
fn build_agent_state(
    content: &AgentStateContent,
    node_id: &str,
    canonical_npub: Option<&str>,
) -> anyhow::Result<EventBuilder> {
    let (json, tags) = build_agent_state_parts(content, node_id, canonical_npub)?;
    Ok(EventBuilder::new(Kind::from(KIND_KIRBY_AGENT_STATE), json).tags(tags))
}

/// Publish ONE 31000 `KIND_KIRBY_AGENT_STATE` event (the live "Kirby face") to the
/// relay, signed by `signer`, then disconnect. A one-shot connect-publish-disconnect
/// mirroring [`publish_lifecycle`]: the event is addressable (keyed by the `agent_id`
/// `d` tag), so each publish REPLACES the prior state on the relay, and the UI reads the
/// latest per agent. Re-published on the presence cadence with the LIVE treasury balance.
///
/// Signing (S3e): `NodeKey` uses the existing `send_event_builder` path; `Frost`
/// quorum-signs the SAME content+tags under Q and publishes the PRE-SIGNED event (the
/// agent's live face is signed by its sovereign Q -- "Q signs everything").
///
/// `content` carries the live current balance + runway (`None` until a burn rate is
/// established) + lifecycle ("running" | "dying" | "dead") + backend ("firecracker" |
/// "vz"). The content/tags follow the contract
/// (`plans/kirby-cluster-event-kinds-20260619.md`): `["d",<agent_id>]`,
/// `["t","kirby"]`, `["a",<agent_id>]`, `["node",<node_id>]`, content `{ agent_id,
/// treasury_sats, runway_secs, lifecycle, backend, lease_holder_node, lease_term }`.
/// Returns the published event id on success.
///
/// `canonical_npub` (P1, #76): when `Some`, the beacon carries the `["social",<hex>]`
/// binding tag pointing at the agent's canonical social key (its DM/kind:0/kind:10050
/// npub as 32-byte HEX). `None` for non-DM agents keeps the beacon byte-identical to
/// before. Q STILL signs the whole beacon either way (`frost_sign_beacon` unchanged) --
/// only the tag set changes -- so the binding is forge-proof under the sovereign key.
pub async fn publish_agent_state(
    signer: &BeaconSigner,
    relay_url: &str,
    node_id: &str,
    content: &AgentStateContent,
    canonical_npub: Option<&str>,
) -> anyhow::Result<String> {
    let client = connect_beacon_client(signer, relay_url).await?;
    let result: anyhow::Result<EventId> = async {
        match signer {
            BeaconSigner::NodeKey(_) => {
                let builder = build_agent_state(content, node_id, canonical_npub)?;
                Ok(client
                    .send_event_builder(builder)
                    .await
                    .context("publish agent-state event")?
                    .val)
            }
            BeaconSigner::Frost(quorum) => {
                let (json, tags) = build_agent_state_parts(content, node_id, canonical_npub)?;
                let created_at = Timestamp::now().as_secs();
                let ev =
                    frost_sign_beacon(quorum, KIND_KIRBY_AGENT_STATE, &tags, &json, created_at)?;
                Ok(client
                    .send_event(&ev)
                    .await
                    .context("publish pre-signed FROST agent-state event")?
                    .val)
            }
        }
    }
    .await;
    // Best-effort clean disconnect regardless of the send outcome.
    client.disconnect().await;
    let id = result?.to_hex();
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

    // ---- NIP-17 DM inbound screening (task #12): the `screen_and_enqueue_dm` trust boundary ----

    /// Build a real NIP-17 gift wrap from `sender` to `recipient` carrying `text` (kind:14 rumor ->
    /// kind:13 seal -> kind:1059 wrap), exactly as a real client would (a fresh throwaway signs the
    /// outer wrap; `created_at` is randomized inside the builder).
    async fn make_dm_wrap(sender: &Keys, recipient: &PublicKey, text: &str) -> Event {
        EventBuilder::private_msg(sender, *recipient, text, [])
            .await
            .expect("build a NIP-17 DM gift wrap")
    }

    #[tokio::test]
    async fn dm_round_trip_enqueues_with_the_seal_verified_sender() {
        let sender = Keys::generate();
        let dm = Keys::generate(); // the agent's dedicated DM key
        let wrap = make_dm_wrap(&sender, &dm.public_key(), "hello kirby").await;
        // The outer 1059 author is a random throwaway, NOT the sender (metadata privacy).
        assert_ne!(
            wrap.pubkey,
            sender.public_key(),
            "the gift-wrap author must be an ephemeral throwaway, not the sender"
        );

        let queue = InboundQueue::with_capacity(8);
        let seq = screen_and_enqueue_dm(&queue, &dm, &wrap).await.expect("a valid DM enqueues");
        assert_eq!(seq, 1);

        let batch = queue.poll(0, &[InboundKind::DirectMessage], Duration::from_millis(0)).await;
        assert_eq!(batch.len(), 1, "exactly one DM enqueued");
        let ev = &batch[0];
        // TOOTH (keeper): source_pubkey is the SEAL-verified sender (= the reply-to recipient), and
        // is NEVER the throwaway 1059 author. Screening or replying on the wrap author would be a bug.
        assert_eq!(
            ev.source_pubkey,
            sender.public_key().to_hex(),
            "the enqueued sender must be the SEAL author (the real sender)"
        );
        assert_ne!(
            ev.source_pubkey,
            wrap.pubkey.to_hex(),
            "the enqueued sender must NOT be the throwaway gift-wrap author"
        );
        assert_eq!(ev.kind, InboundKind::DirectMessage as i32);
        assert_eq!(String::from_utf8_lossy(&ev.payload), "hello kirby");
    }

    #[tokio::test]
    async fn dm_with_mismatched_rumor_and_seal_sender_is_rejected() {
        // TOOTH (keeper): a wrap whose rumor claims author A but whose seal is signed by B must be
        // REJECTED (anti-spoof). Hand-craft it: a rumor authored by `spoofed`, sealed + signed by
        // `real` -> rumor.pubkey != seal.pubkey -> the library's SenderMismatch -> we drop it.
        let real = Keys::generate();
        let spoofed = Keys::generate();
        let dm = Keys::generate();
        let rumor =
            EventBuilder::private_msg_rumor(dm.public_key(), "i am someone else").build(spoofed.public_key());
        let seal = EventBuilder::seal(&real, &dm.public_key(), rumor)
            .await
            .unwrap()
            .sign_with_keys(&real)
            .unwrap();
        let wrap = EventBuilder::gift_wrap_from_seal(&dm.public_key(), &seal, []).unwrap();

        let queue = InboundQueue::with_capacity(8);
        assert!(
            screen_and_enqueue_dm(&queue, &dm, &wrap).await.is_none(),
            "a rumor/seal sender mismatch must be rejected"
        );
        assert_eq!(queue.len(), 0, "nothing enqueued for a spoofed sender");
    }

    #[tokio::test]
    async fn dm_addressed_to_a_different_key_is_dropped() {
        // A wrap encrypted to someone ELSE: our DM key cannot NIP-44-decrypt it -> dropped (never a
        // crash). This is also why FROST's Q can't be the DM identity: no single key to decrypt with.
        let sender = Keys::generate();
        let someone_else = Keys::generate();
        let dm = Keys::generate();
        let wrap = make_dm_wrap(&sender, &someone_else.public_key(), "not for you").await;

        let queue = InboundQueue::with_capacity(8);
        assert!(
            screen_and_enqueue_dm(&queue, &dm, &wrap).await.is_none(),
            "a wrap addressed to another key must be dropped"
        );
        assert_eq!(queue.len(), 0);
    }

    #[tokio::test]
    async fn dm_wrapping_a_non_dm_rumor_is_dropped() {
        // A valid gift wrap whose RUMOR is not a kind:14 DM (here a kind:1 note) is dropped at the
        // assert-DM step -- the DM inbox only accepts actual private direct messages.
        let sender = Keys::generate();
        let dm = Keys::generate();
        let rumor = EventBuilder::new(Kind::TextNote, "i am a note, not a dm").build(sender.public_key());
        let seal = EventBuilder::seal(&sender, &dm.public_key(), rumor)
            .await
            .unwrap()
            .sign_with_keys(&sender)
            .unwrap();
        let wrap = EventBuilder::gift_wrap_from_seal(&dm.public_key(), &seal, []).unwrap();

        let queue = InboundQueue::with_capacity(8);
        assert!(
            screen_and_enqueue_dm(&queue, &dm, &wrap).await.is_none(),
            "a gift wrap whose rumor is not a kind:14 DM must be dropped"
        );
        assert_eq!(queue.len(), 0);
    }

    // ---- #103: idempotent enqueue + the DM backfill sweep (durable delivery past a half-open socket) ----

    /// A [`GiftWrapFetcher`] that returns a canned set of wraps — so a test drives
    /// [`dm_backfill_sweep`]'s screen -> dedup -> enqueue logic with no live relay (mirroring how a
    /// real relay re-sends the SAME stored wraps on every REQ).
    struct StaticFetcher {
        wraps: Vec<Event>,
    }

    #[async_trait::async_trait]
    impl GiftWrapFetcher for StaticFetcher {
        async fn fetch_stored_wraps(&self, _me: PublicKey) -> anyhow::Result<Vec<Event>> {
            Ok(self.wraps.clone())
        }
    }

    #[tokio::test]
    async fn dm_redelivery_of_the_same_giftwrap_enqueues_once() {
        // TOOTH (#103): the enqueue is IDEMPOTENT on the gift-wrap id. A relay re-REQ (or a backfill
        // re-fetch) re-delivers the same wrap; it must NOT create a second inbox event — else, once
        // the genome advanced its ack_seq past it, the new seq would re-drive a reply it already sent.
        let sender = Keys::generate();
        let dm = Keys::generate();
        let wrap = make_dm_wrap(&sender, &dm.public_key(), "only once").await;

        let queue = InboundQueue::with_capacity(8);
        assert_eq!(
            screen_and_enqueue_dm(&queue, &dm, &wrap).await,
            Some(1),
            "the first delivery of a wrap enqueues at seq 1"
        );
        assert!(
            screen_and_enqueue_dm(&queue, &dm, &wrap).await.is_none(),
            "re-delivering the SAME gift wrap must be a dedup no-op"
        );
        assert_eq!(queue.len(), 1, "exactly one inbox event for one gift wrap");
        // REVERT CHECK: drop push_typed_once's dedup and the second call pushes a 2nd event (seq 2).
    }

    #[tokio::test]
    async fn dm_backfill_recovers_a_dm_the_live_sub_never_saw() {
        // TOOTH (#103): the sweep is the durable-delivery backstop. Model the field failure — a DM
        // that landed while the persistent socket was silently half-open (ping off, #54): never
        // delivered live, but stored on the relay. The sweep re-fetches on a fresh connection and
        // enqueues it, so delivery is guaranteed regardless of the persistent socket's state.
        let dir = tempdir();
        let dm_identity = NodeIdentity::load_or_create(&dir.join("dm.key")).unwrap();
        let sender = Keys::generate();
        let missed = make_dm_wrap(&sender, &dm_identity.public_key(), "did you get this?").await;

        let queue = InboundQueue::with_capacity(8);
        assert_eq!(queue.len(), 0, "the deaf live sub delivered nothing");

        let fetcher = StaticFetcher { wraps: vec![missed] };
        let recovered = dm_backfill_sweep(&fetcher, dm_identity.keys(), dm_identity.public_key(), &queue).await;
        assert_eq!(recovered, 1, "the sweep recovers the one missed DM");
        assert_eq!(queue.len(), 1, "the missed DM is now enqueued for the genome");

        let batch = queue.poll(0, &[InboundKind::DirectMessage], Duration::from_millis(0)).await;
        assert_eq!(String::from_utf8_lossy(&batch[0].payload), "did you get this?");
        cleanup(&dir);
        // REVERT CHECK: neuter dm_backfill_sweep to a no-op and a half-open reader never re-reads => #103.
    }

    #[tokio::test]
    async fn dm_backfill_is_idempotent_across_sweeps() {
        // TOOTH (#103): a relay returns the SAME stored wrap on EVERY REQ, so the sweep runs every
        // interval over the same set. It must enqueue each DM exactly once across all sweeps — else
        // the queue grows every interval and the genome re-replies to the same DM forever. This pins
        // the property that makes running the sweep on a timer SAFE.
        let dir = tempdir();
        let dm_identity = NodeIdentity::load_or_create(&dir.join("dm.key")).unwrap();
        let sender = Keys::generate();
        let wrap = make_dm_wrap(&sender, &dm_identity.public_key(), "steady").await;

        let queue = InboundQueue::with_capacity(8);
        let fetcher = StaticFetcher { wraps: vec![wrap] };
        let first = dm_backfill_sweep(&fetcher, dm_identity.keys(), dm_identity.public_key(), &queue).await;
        let second = dm_backfill_sweep(&fetcher, dm_identity.keys(), dm_identity.public_key(), &queue).await;
        let third = dm_backfill_sweep(&fetcher, dm_identity.keys(), dm_identity.public_key(), &queue).await;
        assert_eq!(first, 1, "the first sweep enqueues the stored DM");
        assert_eq!(second, 0, "a re-sweep of the same stored wrap enqueues nothing");
        assert_eq!(third, 0, "and stays idempotent");
        assert_eq!(queue.len(), 1, "exactly one inbox event no matter how many sweeps");
        cleanup(&dir);
    }

    #[tokio::test]
    async fn dm_delivered_live_is_not_reenqueued_by_a_later_sweep() {
        // TOOTH (#103): the fast path (persistent sub) and the backstop (sweep) share ONE dedup
        // memory. A DM delivered live must NOT be enqueued a second time when a later sweep re-fetches
        // the same stored wrap — proving the two producers compose without duplicating.
        let dir = tempdir();
        let dm_identity = NodeIdentity::load_or_create(&dir.join("dm.key")).unwrap();
        let sender = Keys::generate();
        let wrap = make_dm_wrap(&sender, &dm_identity.public_key(), "live first").await;

        let queue = InboundQueue::with_capacity(8);
        assert_eq!(
            screen_and_enqueue_dm(&queue, dm_identity.keys(), &wrap).await,
            Some(1),
            "the persistent subscription delivers it live"
        );
        let fetcher = StaticFetcher { wraps: vec![wrap] };
        let recovered = dm_backfill_sweep(&fetcher, dm_identity.keys(), dm_identity.public_key(), &queue).await;
        assert_eq!(recovered, 0, "a wrap already delivered live is not re-enqueued by the sweep");
        assert_eq!(queue.len(), 1, "still exactly one inbox event");
        cleanup(&dir);
    }

    #[tokio::test]
    async fn dm_exceeding_the_size_cap_is_dropped() {
        // A VALID, correctly-sealed DM whose content exceeds the dedicated DM cap is DROPPED at the
        // size-cap step. 20_000 bytes is constructible (< NIP-44's ~40 KB deliverable ceiling, so
        // the wrap actually builds) yet > MAX_INBOUND_DM_BYTES (16 KiB), so this cap genuinely
        // bites -- proving it is NOT dead code (unlike the general 65_535 cap on this path).
        let sender = Keys::generate();
        let dm = Keys::generate();
        let big = "x".repeat(20_000);
        assert!(big.len() > MAX_INBOUND_DM_BYTES, "the test message must exceed the DM cap");
        let wrap = make_dm_wrap(&sender, &dm.public_key(), &big).await;

        let queue = InboundQueue::with_capacity(8);
        assert!(
            screen_and_enqueue_dm(&queue, &dm, &wrap).await.is_none(),
            "a valid but oversized DM must be dropped at the size cap"
        );
        assert_eq!(queue.len(), 0, "nothing enqueued for an oversized DM");
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
        // None canonical_npub: the historical byte-identical shape (no social binding tag).
        let event = build_agent_state(&content, "node-1", None)
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
        // With canonical_npub None (a non-DM agent) there is NO social binding tag: byte-identical
        // to before (the P1 non-DM invariant).
        assert!(
            !event.tags.iter().any(|t| t.as_slice().first().map(String::as_str) == Some("social")),
            "a None canonical_npub must NOT add a social binding tag"
        );
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
        let no_runway = build_agent_state(&no_runway_content, "node-1", None)
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();
        let raw2: serde_json::Value = serde_json::from_str(&no_runway.content).unwrap();
        assert!(raw2["runway_secs"].is_null(), "no burn rate yet -> null runway");
        assert_eq!(raw2["backend"], "vz");

        // The final dead state at budget-death: treasury 0, lifecycle "dead".
        let dead_content = AgentStateContent::sovereign("agent-0", 0, None, "dead", "firecracker");
        let dead = build_agent_state(&dead_content, "node-1", None)
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

    // ---- S3e: the beacons sign through the FROST quorum key Q ("Q signs everything") ----
    //
    // These drive `frost_sign_beacon` -- the EXACT FROST-specific step each beacon
    // publisher (`publish_presence`/`publish_lifecycle`/`publish_agent_state`) runs before
    // `client.send_event`. Only the generic relay transport is not exercised (it needs a
    // relay); every load-bearing signing step is the production path. We verify the
    // aggregate as a raw BIP-340 schnorr sig under the TWEAKED group key Q (and that it
    // FAILS under the untweaked internal key P, proving the taproot tweak is real).

    use bitcoin::key::TapTweak as _;
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
    use bitcoin::KnownHrp;
    use kirby_custody::{generate_dealer_keyset, group_xonly_q, taproot_address};

    /// A fresh real 2-of-3 co-located quorum signer + the keyset it was built from.
    fn frost_signer() -> (kirby_custody::DealerKeyset, crate::quorum_signer::QuorumSigner) {
        let ks = generate_dealer_keyset(2, 3).expect("2-of-3 dealer keygen");
        let qs = crate::quorum_signer::local_quorum_from_keyset(&ks).expect("build quorum signer");
        (ks, qs)
    }

    /// Assert `event` (a nostr-sdk Event) is a valid kind-`kind` beacon under Q: pubkey ==
    /// Q, the NIP-01 id (over content AND tags) is correct, and the aggregate BIP-340 sig
    /// verifies under the tweaked Q (and FAILS under the untweaked P).
    fn assert_beacon_under_q(
        ks: &kirby_custody::DealerKeyset,
        qs: &crate::quorum_signer::QuorumSigner,
        event: &Event,
        kind: u16,
    ) {
        let q_bytes = qs.q_bytes();
        // pubkey == Q
        assert_eq!(event.pubkey.to_hex(), hex::encode(q_bytes), "beacon author must be Q");
        assert_eq!(event.kind, Kind::from(kind), "beacon kind");
        // Re-derive the NIP-01 id over content AND the event's tags (the signed shape).
        let tag_vecs: Vec<Vec<String>> =
            event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
        let expect_id = kirby_custody::cosign_net::nip01_event_id_with_tags(
            &hex::encode(q_bytes),
            event.created_at.as_secs(),
            kind as u32,
            &tag_vecs,
            &event.content,
        );
        assert_eq!(
            event.id.to_hex(),
            hex::encode(expect_id),
            "beacon id must be the NIP-01 id under Q over content+tags"
        );
        // Raw BIP-340: verifies under tweaked Q, fails under untweaked P.
        let (_addr, internal_p) = taproot_address(&ks.pubkeys, KnownHrp::Testnets).expect("addr");
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();
        let sig = schnorr::Signature::from_slice(event.sig.as_ref()).expect("64-byte sig");
        let msg = Message::from_digest(expect_id);
        assert!(
            secp.verify_schnorr(&sig, &msg, &q_xonly).is_ok(),
            "beacon must verify under the tweaked group key Q"
        );
        assert!(
            secp.verify_schnorr(&sig, &msg, &internal_p).is_err(),
            "beacon must NOT verify under the untweaked internal key P (taproot tweak is real)"
        );
        // The nostr-sdk Event itself verifies (id + sig consistency); frost_sign_beacon
        // already enforced this fail-closed, re-assert here.
        assert!(event.verify().is_ok(), "beacon event must self-verify");
    }

    /// G-PRESENCE-SIGNED-BY-Q: a FROST tenant's presence (10100) beacon verifies under Q.
    #[test]
    fn g_presence_signed_by_q() {
        let (ks, qs) = frost_signer();
        let (content, tags) =
            build_presence_parts("node-A", Some("1.2.3.4:5000")).expect("presence parts");
        let event =
            frost_sign_beacon(&qs, KIND_KIRBY_PRESENCE, &tags, &content, 1_750_000_000).expect("sign");
        assert_beacon_under_q(&ks, &qs, &event, KIND_KIRBY_PRESENCE);
        // The node_id tag survived into the signed event (beacon tags are signed).
        assert!(
            event.tags.iter().any(|t| t.as_slice() == ["node_id", "node-A"]),
            "the node_id tag must be present + signed"
        );
        // The content is the verbatim presence JSON (NOT mangled by the note sanitizer).
        let decoded: PresenceContent = serde_json::from_str(&event.content).expect("presence json");
        assert_eq!(decoded.node_id, "node-A");
        assert_eq!(decoded.status, "alive");
        println!("G-PRESENCE-SIGNED-BY-Q PASS: 10100 presence verifies under Q, pubkey==Q, JSON verbatim");
    }

    /// G-LIFECYCLE-SIGNED-BY-Q: a FROST tenant's lifecycle (9100) beacon verifies under Q.
    #[test]
    fn g_lifecycle_signed_by_q() {
        let (ks, qs) = frost_signer();
        let (content, tags) =
            build_lifecycle_parts("agent-0", "node-1", "born", 1_000_000, "funded").expect("parts");
        let event =
            frost_sign_beacon(&qs, KIND_KIRBY_LIFECYCLE, &tags, &content, 1_750_000_000).expect("sign");
        assert_beacon_under_q(&ks, &qs, &event, KIND_KIRBY_LIFECYCLE);
        let decoded: LifecycleContent = serde_json::from_str(&event.content).expect("lifecycle json");
        assert_eq!(decoded.event, "born");
        assert_eq!(decoded.treasury_sats, 1_000_000);
        assert!(event.tags.iter().any(|t| t.as_slice() == ["a", "agent-0"]));
        println!("G-LIFECYCLE-SIGNED-BY-Q PASS: 9100 lifecycle verifies under Q, pubkey==Q");
    }

    /// G-STATE-SIGNED-BY-Q: a FROST tenant's agent-state (31000) beacon verifies under Q.
    #[test]
    fn g_state_signed_by_q() {
        let (ks, qs) = frost_signer();
        let content =
            AgentStateContent::sovereign("agent-0", 1_234, Some(42), "running", "firecracker");
        let (json, tags) = build_agent_state_parts(&content, "node-1", None).expect("parts");
        let event =
            frost_sign_beacon(&qs, KIND_KIRBY_AGENT_STATE, &tags, &json, 1_750_000_000).expect("sign");
        assert_beacon_under_q(&ks, &qs, &event, KIND_KIRBY_AGENT_STATE);
        let decoded: AgentStateContent = serde_json::from_str(&event.content).expect("state json");
        assert_eq!(decoded.treasury_sats, 1_234);
        assert_eq!(decoded.lifecycle, "running");
        // The addressable `d` tag (= agent_id) survived into the signed event.
        assert!(event.tags.iter().any(|t| t.as_slice() == ["d", "agent-0"]));
        println!("G-STATE-SIGNED-BY-Q PASS: 31000 agent-state verifies under Q, pubkey==Q, d-tag signed");
    }

    /// G-STATE-SOCIAL-BINDING-UNDER-Q (P1, #76): a 31000 beacon built with `canonical_npub=Some`
    /// carries the `["social",<hex>]` binding tag AND STILL verifies under the sovereign Q. This is
    /// the plane separation: the SOCIAL identity is bound INTO the beacon, but the beacon itself is
    /// signed by CONTROL (Q) -- so the binding is forge-proof (a reader trusts it because Q, the key
    /// no single holder controls, vouched for it). RED-on-revert: drop the `["social",..]` push in
    /// `build_agent_state_parts` and the tag assertion fails; the Q-verify guards the plane split.
    #[test]
    fn g_state_social_binding_under_q() {
        let (ks, qs) = frost_signer();
        // The canonical social key is a SEPARATE plain key; its HEX pubkey is the binding value.
        let canonical = Keys::generate();
        let canonical_hex = canonical.public_key().to_hex();
        let content =
            AgentStateContent::sovereign("agent-0", 4_242, Some(7), "running", "firecracker");
        let (json, tags) =
            build_agent_state_parts(&content, "node-1", Some(&canonical_hex)).expect("parts");
        let event =
            frost_sign_beacon(&qs, KIND_KIRBY_AGENT_STATE, &tags, &json, 1_750_000_000).expect("sign");

        // (1) The beacon STILL verifies under Q (CONTROL signs it), pubkey == Q, id over content+tags.
        assert_beacon_under_q(&ks, &qs, &event, KIND_KIRBY_AGENT_STATE);
        // (2) The `["social",<canonical-hex>]` binding rode INTO the SIGNED event (part of the id).
        assert!(
            event.tags.iter().any(|t| t.as_slice() == ["social", canonical_hex.as_str()]),
            "the 31000 must carry the ['social', canonical-hex] binding tag"
        );
        // (3) The binding value is the SOCIAL key, NOT Q (the two planes are distinct).
        assert_ne!(
            canonical_hex,
            hex::encode(qs.q_bytes()),
            "the canonical social key MUST differ from the control key Q"
        );
        // (4) The d/t/a/node tags are still there (the binding is ADDITIVE).
        assert!(event.tags.iter().any(|t| t.as_slice() == ["d", "agent-0"]));
        println!(
            "G-STATE-SOCIAL-BINDING-UNDER-Q PASS: 31000 carries ['social',<hex>] AND verifies under \
             Q (plane separation: SOCIAL bound, CONTROL signs)"
        );
    }

    /// G-METADATA-PROFILE-SIGNED-BY-CANONICAL (P1, #76): the kind:0 profile is signed by the
    /// CANONICAL SOCIAL (DM) key -- the SAME npub that signs kind:1 posts, the kind:10050 inbox
    /// list, and NIP-17 DMs -- so a client that resolves the agent to its social npub sees the
    /// profile under that ONE identity. This DRIVES the production `build_metadata_profile_event`
    /// (the real signer line `publish_metadata_profile` publishes), so a future wrong-key
    /// regression in that signer trips this tooth; only the relay transport (`send_event` over a
    /// live relay) is not exercised. RED-on-revert: make the production builder sign with a
    /// different key (e.g. a fresh key or Q) and the `pubkey == canonical` assertion fails.
    #[tokio::test]
    async fn g_metadata_profile_signed_by_canonical() {
        // The canonical social (DM) identity: a plain keyfile, loaded exactly as boot does.
        let dir = tempdir();
        let dm_identity = NodeIdentity::load_or_create(&dir.join("social.dm.key")).expect("dm key");
        let canonical_hex = dm_identity.public_key().to_hex();

        // The EXACT event `publish_metadata_profile` builds + signs, via the production builder (the
        // relay send is the only part that needs a live relay; the signing is the load-bearing plane
        // assertion this tooth drives directly).
        let profile_json = serde_json::json!({ "name": "agent-0" }).to_string();
        let event = build_metadata_profile_event(&dm_identity, &profile_json)
            .expect("sign the kind:0 profile under the canonical social key");

        assert_eq!(event.kind, Kind::Metadata, "the profile is a kind:0 Metadata event");
        assert_eq!(
            event.pubkey.to_hex(),
            canonical_hex,
            "the kind:0 profile is signed by the CANONICAL social (DM) key"
        );
        assert_eq!(event.content, profile_json, "the profile content is the minimal name JSON");
        assert!(event.verify().is_ok(), "the profile self-verifies (id + sig under the canonical key)");
        // The content is the minimal {"name": <agent_id>} P1 shape.
        let decoded: serde_json::Value = serde_json::from_str(&event.content).expect("profile json");
        assert_eq!(decoded["name"], "agent-0", "P1 minimal profile carries the agent_id as name");
        cleanup(&dir);
        println!(
            "G-METADATA-PROFILE-SIGNED-BY-CANONICAL PASS: kind:0 profile signed by the canonical \
             social key (the ONE npub posts+DM+inbox share)"
        );
    }

    /// G-BEACON-MEMBRANE (nerve half): the guardian membrane gates beacon signing -- a
    /// quorum whose holders are fed a TAMPERED package refuses (no signature) -- AND the
    /// beacon JSON content is NOT mangled by the note-sanitizer (it round-trips byte-exact
    /// through the signed event even though it is not "canonical note" form).
    #[test]
    fn g_beacon_membrane() {
        use crate::quorum_signer::Holder as _;
        use kirby_custody::guardian::{self, CoSignRequest, RefuseReason, SignIntent};
        use std::collections::{BTreeMap, BTreeSet};

        let (ks, qs) = frost_signer();

        // (1) NOT MANGLED: build agent-state JSON (it has `{`,`:`,`"` and is clearly NOT a
        //     canonical free-text note) and confirm it round-trips byte-exact through the
        //     signed event content.
        let content =
            AgentStateContent::sovereign("agent-0", 9_999, None, "dying", "vz");
        let (json, tags) = build_agent_state_parts(&content, "node-1", None).expect("parts");
        let event =
            frost_sign_beacon(&qs, KIND_KIRBY_AGENT_STATE, &tags, &json, 1_750_000_000).expect("sign");
        assert_eq!(
            event.content, json,
            "beacon JSON content must be signed VERBATIM (the note sanitizer is kind:1-only)"
        );

        // (2) MEMBRANE GATES BEACONS: drive two LocalHolders directly with a TAMPERED
        //     package (its message is a DIFFERENT beacon's id). Each holder's
        //     guardian::validate MUST refuse MessageMismatch -> no share -> ceremony aborts.
        let kps = kirby_custody::key_packages(&ks).expect("kps");
        let mut kps_vec: Vec<frost_secp256k1_tr::keys::KeyPackage> = kps.into_values().collect();
        kps_vec.truncate(2);
        let h1 = crate::quorum_signer::LocalHolder::new(kps_vec[0].clone(), ks.pubkeys.clone());
        let h2 = crate::quorum_signer::LocalHolder::new(kps_vec[1].clone(), ks.pubkeys.clone());

        let session_id = 99u64;
        let c1 = h1.commit(session_id).expect("h1 commit");
        let c2 = h2.commit(session_id).expect("h2 commit");
        let i1 = frost_secp256k1_tr::Identifier::try_from(h1.id()).unwrap();
        let i2 = frost_secp256k1_tr::Identifier::try_from(h2.id()).unwrap();
        let mut commitments = BTreeMap::new();
        commitments.insert(i1, c1);
        commitments.insert(i2, c2);

        // The REAL beacon tags + content the request claims:
        let tag_vecs: Vec<Vec<String>> = tags.iter().map(|t| t.as_slice().to_vec()).collect();
        let q_hex = hex::encode(group_xonly_q(&ks.pubkeys).unwrap());
        // A TAMPERED package: signs the id of a DIFFERENT agent-state (treasury altered).
        let wrong_id = kirby_custody::cosign_net::nip01_event_id_with_tags(
            &q_hex,
            1_750_000_000,
            KIND_KIRBY_AGENT_STATE as u32,
            &tag_vecs,
            r#"{"agent_id":"agent-0","treasury_sats":1}"#,
        );
        let tampered = frost_secp256k1_tr::SigningPackage::new(commitments, &wrong_id);

        let signer_set: BTreeSet<u16> = [h1.id(), h2.id()].into_iter().collect();
        let req = CoSignRequest {
            session_id,
            intent: SignIntent::NostrEvent {
                kind: KIND_KIRBY_AGENT_STATE as u32,
                created_at: 1_750_000_000,
                tags: tag_vecs.clone(),
                content: json.clone(),
            },
            signer_set,
        };
        let r1 = h1.validate_and_sign(session_id, &req, &tampered);
        let r2 = h2.validate_and_sign(session_id, &req, &tampered);
        assert_eq!(r1, Err(RefuseReason::MessageMismatch), "holder 1 refuses tampered beacon");
        assert_eq!(r2, Err(RefuseReason::MessageMismatch), "holder 2 refuses tampered beacon");

        // A correctly-reconstructed request DOES pass validate (positive control).
        let good_id = kirby_custody::cosign_net::nip01_event_id_with_tags(
            &q_hex,
            1_750_000_000,
            KIND_KIRBY_AGENT_STATE as u32,
            &tag_vecs,
            &json,
        );
        let h3 = crate::quorum_signer::LocalHolder::new(kps_vec[0].clone(), ks.pubkeys.clone());
        let h4 = crate::quorum_signer::LocalHolder::new(kps_vec[1].clone(), ks.pubkeys.clone());
        let sid = 100u64;
        let mut good_commits = BTreeMap::new();
        good_commits.insert(i1, h3.commit(sid).unwrap());
        good_commits.insert(i2, h4.commit(sid).unwrap());
        let good_pkg = frost_secp256k1_tr::SigningPackage::new(good_commits, &good_id);
        assert!(
            guardian::validate(&req, &good_pkg, &ks.pubkeys, h3.id(), 2).is_ok(),
            "a correctly-reconstructed beacon request must validate (positive control)"
        );

        println!("G-BEACON-MEMBRANE (nerve) PASS: beacon JSON signed verbatim (not sanitized); tampered beacon package refused MessageMismatch by every holder; good package validates");
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
