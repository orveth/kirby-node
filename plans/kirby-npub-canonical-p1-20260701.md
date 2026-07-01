# Canonical Social npub — P1 Build Plan

## Status
Design LOCKED (gudnuf greenlit 2026-07-01: "do the npub fix because that's annoying"). Base = orveth/main **@03cd786**, branch `feat/npub-canonical-p1`, worktree `/srv/forge/worktrees/kirby-npub-canonical`. Cross-lane seam w/ money-cluster LOCKED (P2 keyring-derived SK_social deferred; **P1 uses the promoted local keyfile — NO keyring dep**). Keeper adversarial-verifies the PR.

## Goal (the "annoying" fix)
ONE canonical social npub per agent = the single answer to "who do I DM." Today an agent presents ≥2 unlinked npubs (Q signs voice + beacons; a separate `dm_keys` signs DM) → on his first live poke gudnuf saw **3 look-alike DM-able npubs (1 live + 2 dead runs)** and DM'd a dead one. P1: promote the plain `dm_keys` to be the canonical social key (signs posts + profile + DM), and bind the Q-signed presence beacon → the canonical npub so the UI can resolve `agent_id → the ONE live DM target`.

## Design (locked — 3 planes)
- **SOCIAL** = canonical npub = promoted `dm_keys` (plain/ECDH). Signs **kind:1 posts + kind:0 profile (NEW) + DM (1059/10050)**.
- **CONTROL** = Q (FROST). KEEPS lease + presence (31000) + lifecycle (9100); the 31000 beacon carries the forge-proof binding → canonical.
- **MONEY** = wallet key (#92). Separate. Canonical NEVER spends.

Q **STOPS signing kind:1** (posts move to canonical — the intended unification; **name this explicitly in the PR**). Quarantine holds: the DM tick still emits only `nostr.dm_reply` (#73); canonical signing posts is the separate capable/post path; neither tick gains a spend action. Q anchoring the binding = forge-proof (a self-signed-by-canonical binding would be circular/forgeable if the social key leaks).

## The binding tag (discovery spine, #76)
`["social", "<hex>"]` on kind:31000 — value = the canonical key's 32-byte HEX pubkey (= DM key = 10050/kind:0 signer = NIP-17 recipient). Const `TAG_SOCIAL = "social"`. dm-ui resolver: live 31000 (#d=agent_id) → read "social" tag → canonical npub → DM target; drop 10050s with no live 31000 binding. Spec handed to worker:dm-ui.

## P1 changes (exact anchors @03cd786)
### 1. kind:1 → canonical (rail.rs)
- `publish_note` (rail.rs:919-945): when `self.dm_keys.is_some()`, sign the (sanitized) kind:1 under `dm_keys` (plain) and publish; else current fallback (Frost→Q / SingleKey). PRESERVE `sanitize_note_for_publish` + cost/metering. Signing template = `build_dm_reply_event` (rail.rs:1019-1032) which pre-signs with `dm_keys` (EventBuilder → sign under dm_keys) → `send_event`. Ground the exact nostr-sdk 0.44 sign API from that working DM path; do NOT invent it.
- `NostrActuator` (rail.rs:802-817): `dm_keys: Option<Keys>` already present; `SigningMode {SingleKey, Frost}` (776-795).
- `frost_sign_event` (953-973): stays as the no-dm_keys fallback for kind:1 (beacons publish via nerve.rs, not here).

### 2. kind:0 profile (nerve.rs + boot.rs)
- New `publish_metadata_profile(dm_identity: &NodeIdentity, relays: &[String], profile_json: &str)` mirroring `publish_inbox_relay_list` (nerve.rs:1137-1171): `Client::builder().signer(dm_identity.keys().clone()).build()` → add relays → connect → `EventBuilder::new(Kind::Metadata, profile_json)` → `send_event_builder` → disconnect.
- Profile JSON (P1 minimal): `{"name":"<agent_id>"}` (+ optional `about`).
- Call in boot.rs after VM up, best-effort, alongside the existing 10050 publish call.

### 3. 31000 binding tag (nerve.rs)
- `build_agent_state_parts` (nerve.rs:1343-1355): add param `canonical_npub: Option<&str>`; when Some, push `Tag::parse([TAG_SOCIAL, hex])?`.
- `build_agent_state` (1358-1361) + `publish_agent_state` (1380-1425): thread `canonical_npub` through. Caller (run_agent.rs beacon cadence) passes the canonical (dm) pubkey hex; `None` for non-DM agents.
- Q STILL signs 31000 (`frost_sign_beacon` unchanged) — only the tag is added.

### 4. Guardian test rewrite (rail.rs + frost_quorum_publish.rs)
- `g_frost_actuator_publishes_quorum_signed_event` (rail.rs:2596-2664): rewrite → WITH dm_keys attached, `publish_note` signs kind:1 under dm_keys (pubkey==dm, NOT Q); WITHOUT dm_keys, kind:1 signs under Q (fallback preserved). RED-on-revert both directions.
- ADD teeth: (i) 31000 carries `["social", canonical-hex]` AND the beacon still verifies under Q (plane separation); (ii) kind:0 profile signs under canonical; (iii) DM still signs under dm_keys (existing `dm_reply_is_signed_by_the_dm_key_never_the_money_key` stays green).
- `frost_quorum_publish.rs` (28-114): update the gated e2e (kind:1 now canonical-signed; keep/repoint a Q-signed-BEACON e2e).

## Invariants (keeper adversarial-verify targets)
- **Promote-don't-replace:** the existing `dm_npub` is UNCHANGED (canonical = the existing dm_keys) → dm-ui + live agents don't churn; only the VOICE relocates onto it.
- **Q keeps** presence/lifecycle/lease; ONLY kind:1 moves off Q.
- **Quarantine:** DM tick → only nostr.dm_reply (unchanged, #73); no spend reachable from any social path.
- **Non-DM agents** (`dm_keys` None): behavior BYTE-IDENTICAL to today (Frost/SingleKey kind:1, no binding tag, no profile publish).

## Gauntlet
`cargo clippy --workspace --all-targets -- -D warnings` = EXIT 0; full suite green; all new teeth RED-on-revert. **NO workspace `cargo fmt`** (repaints ~71 unrelated files, wrecks the PR — hand-match fmt style; verify via clippy/tests).

## P2 handoff (deferred, not P1)
When the P2 keyring-derived SK_social path is the active build: ping worker:money-build to add the `social` subkey in `seed_keyring`/`hibernate::shamir::derive_subkeys` (additive, existing identity/state/wallet subkeys byte-identical). SK_social (a non-money master-sibling, HKDF distinct-INFO "kirby/social/v1") swaps in behind the SAME `with_dm_keys` seam. New agents born canonical+portable; existing agents keep the P1 keyfile unless they need x-machine portability.
