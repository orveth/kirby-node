//! SPLIT (true multi-machine) FROST -> Nostr co-signing transport (additive).
//!
//! This module is ADDITIVE and does NOT touch the C-1..C-6 crypto paths
//! (seam.rs / coordinator.rs / spend.rs). It provides a synchronous, length-prefixed
//! TCP carrier for the OPAQUE CoSignEvent frames (the same struct shape and the same
//! ROUND_COMMITMENT / ROUND_PACKAGE / ROUND_SHARE discriminants used by the in-memory
//! seam in seam.rs), plus the NIP-01 helpers (event id, npub) needed so a real
//! multi-machine 2-of-3 group can collectively sign a Nostr kind:1 event under the
//! group's tweaked taproot x-only key Q.
//!
//! Unlike coordinate_2of3_over_seam (a single-process driver that holds ALL
//! KeyPackages and commits/signs for every signer itself), here each guardian runs
//! frost::round1::commit and frost::round2::sign_with_tweak LOCALLY on its own box.
//! Only non-secret material crosses the wire: a serialized SigningCommitments, a
//! serialized SigningPackage, and a serialized SignatureShare. Secret nonces and
//! KeyPackages NEVER serialize onto the wire.

use std::io::{Read, Write};
use std::net::TcpStream;

use serde::{Deserialize, Serialize};

/// Round discriminants (mirror seam.rs so a relay transport drops in unchanged).
pub const ROUND_COMMITMENT: u8 = 1;
pub const ROUND_SHARE: u8 = 2;
pub const ROUND_PACKAGE: u8 = 3;

/// Reject oversize frames: a CoSignEvent payload is a few hundred bytes; anything
/// over 16 MiB is hostile or corrupt and is refused before allocation.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// The opaque co-sign envelope. The carrier reads only session_id + round for
/// routing/dedupe; `payload` is opaque serialized frost bytes (a SigningCommitments,
/// a SigningPackage, or a SignatureShare). `from` is the 16-bit FROST identifier as
/// a plain u16 on the wire (the wire form is transport-neutral; the binary maps it
/// to a frost::Identifier locally).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEvent {
    pub session_id: u64,
    pub from: u16,
    pub round: u8,
    /// Hex of the opaque serialized frost type (keeps the JSON ASCII-clean).
    pub payload_hex: String,
}

impl WireEvent {
    pub fn new(session_id: u64, from: u16, round: u8, payload: &[u8]) -> Self {
        Self {
            session_id,
            from,
            round,
            payload_hex: hex::encode(payload),
        }
    }

    pub fn payload(&self) -> Result<Vec<u8>, String> {
        hex::decode(&self.payload_hex).map_err(|e| format!("payload hex decode: {e}"))
    }
}

/// Send one length-prefixed (u32 BE) JSON-encoded WireEvent frame.
pub fn send_frame(stream: &mut TcpStream, event: &WireEvent) -> Result<(), String> {
    let json = serde_json::to_vec(event).map_err(|e| format!("encode: {e}"))?;
    if json.len() > MAX_FRAME_BYTES {
        return Err(format!("frame too large: {} bytes", json.len()));
    }
    let len = json.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| format!("write len: {e}"))?;
    stream
        .write_all(&json)
        .map_err(|e| format!("write body: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

/// Receive one length-prefixed (u32 BE) JSON-encoded WireEvent frame. Rejects an
/// oversize length prefix BEFORE allocating.
pub fn recv_frame(stream: &mut TcpStream) -> Result<WireEvent, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read len: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(format!("frame too large: {len} bytes (max {MAX_FRAME_BYTES})"));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("read body: {e}"))?;
    serde_json::from_slice(&body).map_err(|e| format!("decode: {e}"))
}

/// Compute the NIP-01 event id: sha256 of the compact JSON array
/// `[0, pubkey_hex, created_at, kind, tags, content]`. `pubkey_hex` is the 32-byte
/// x-only group key Q in lowercase hex. tags is the empty array for a plain kind:1
/// note. Returns the 32-byte id (this is the FROST `message`).
pub fn nip01_event_id(pubkey_hex: &str, created_at: u64, kind: u32, content: &str) -> [u8; 32] {
    // The empty-tags case (a plain kind:1 note). Delegates to the tag-aware form so
    // there is exactly ONE serialization implementation: empty tags must serialize as
    // `[]`, which `nip01_event_id_with_tags` produces for an empty slice.
    let empty_tags: Vec<Vec<String>> = Vec::new();
    nip01_event_id_with_tags(pubkey_hex, created_at, kind, &empty_tags, content)
}

/// Compute the NIP-01 event id WITH tags: sha256 of the compact JSON array
/// `[0, pubkey_hex, created_at, kind, tags, content]` where `tags` is the event's tag
/// array (each tag a `["name", "value", ...]` string array). This is the general form
/// the Kirby beacons (presence 10100 / lifecycle 9100 / agent-state 31000) need, since
/// those events carry tags that are part of the signed id. `nip01_event_id` is the
/// empty-tags special case (a plain kind:1 note). Returns the 32-byte id (the FROST
/// `message`).
pub fn nip01_event_id_with_tags(
    pubkey_hex: &str,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    // NIP-01 serialization: a compact (no-whitespace) UTF-8 JSON array. serde_json's
    // to_string already emits compact JSON, and it escapes the strings exactly as
    // NIP-01 requires (it is JSON-string escaping).
    let arr = serde_json::json!([0, pubkey_hex, created_at, kind, tags, content]);
    let serialized = serde_json::to_string(&arr).expect("serialize NIP-01 array");
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let out = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&out);
    id
}

/// Encode a 32-byte x-only pubkey as a NIP-19 `npub` bech32 string.
pub fn npub_encode(xonly: &[u8; 32]) -> Result<String, String> {
    use bech32::{Bech32, Hrp};
    let hrp = Hrp::parse("npub").map_err(|e| format!("hrp: {e}"))?;
    bech32::encode::<Bech32>(hrp, xonly).map_err(|e| format!("bech32 encode: {e}"))
}

/// A finished, signed Nostr event ready to serialize into a `["EVENT", {...}]`
/// relay message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The NIP-01 event id is the sha256 of the canonical compact array; check it is
    /// deterministic and 32 bytes (the value the coordinator uses as the FROST
    /// message and that an independent verifier re-derives).
    #[test]
    fn nip01_id_is_deterministic_sha256() {
        let pk = "a".repeat(64);
        let id1 = nip01_event_id(&pk, 1750000000, 1, "hello");
        let id2 = nip01_event_id(&pk, 1750000000, 1, "hello");
        assert_eq!(id1, id2);
        // A different content changes the id.
        let id3 = nip01_event_id(&pk, 1750000000, 1, "hello!");
        assert_ne!(id1, id3);
    }

    /// A known vector: the canonical serialized array for an empty-tag kind:1 note
    /// hashes to a fixed id (locks the serialization shape so it cannot silently
    /// drift away from what nostr-tools / clients compute).
    #[test]
    fn nip01_id_matches_known_serialization() {
        use sha2::{Digest, Sha256};
        let pk = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let content = "FROST co-sign test from kirby custody";
        let created_at = 1750000000u64;
        // Build the exact canonical string by hand and compare to the helper input.
        let expected_arr = format!("[0,\"{pk}\",{created_at},1,[],\"{content}\"]");
        let mut h = Sha256::new();
        h.update(expected_arr.as_bytes());
        let expected: [u8; 32] = h.finalize().into();
        let got = nip01_event_id(pk, created_at, 1, content);
        assert_eq!(got, expected, "helper must match the hand-built canonical array");
    }

    /// npub round-trips back to the 32 bytes.
    #[test]
    fn npub_encodes_xonly() {
        use bech32::Hrp;
        let key = [0x11u8; 32];
        let npub = npub_encode(&key).expect("encode");
        assert!(npub.starts_with("npub1"));
        let (hrp, data) = bech32::decode(&npub).expect("decode");
        assert_eq!(hrp, Hrp::parse("npub").unwrap());
        assert_eq!(data, key);
    }

    /// A WireEvent JSON-frames and round-trips through the same encode the TCP
    /// carrier uses (length-prefix is exercised by the same-host integration run).
    #[test]
    fn wire_event_round_trips() {
        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        let ev = WireEvent::new(7, 2, ROUND_COMMITMENT, &payload);
        let json = serde_json::to_vec(&ev).unwrap();
        let back: WireEvent = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.session_id, 7);
        assert_eq!(back.from, 2);
        assert_eq!(back.round, ROUND_COMMITMENT);
        assert_eq!(back.payload().unwrap(), payload);
    }
}
