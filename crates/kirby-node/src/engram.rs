//! NIP-AE engram crypto + addressing + LWW (durable mind-state Chunk-2).
//!
//! This is the PURE, network-free core of the [`crate::rail::EngramStore`]: the
//! key derivation, the per-slug addressing, the content sealing, and the
//! last-writer-wins reconcile. The store (`rail.rs`) layers the nostr-sdk relay
//! client on top; everything that decides WHAT an engram is lives here so it can
//! be unit-tested without a relay (F8 determinism, encrypt-to-self round-trip,
//! LWW tie-break -- the network round-trips are the e2e script's job).
//!
//! The model (design doc §2/§16, codex-SOUND):
//!   - ONE key roots identity + presence + memory (the slice-1 BIP340 keyfile).
//!   - `K_self` = the NIP-44 v2 conversation key of that key with its OWN pubkey
//!     (ECDH-to-self) -- a symmetric root derivable from the privkey alone, so
//!     every reborn instance of the agent derives the SAME root (portability).
//!   - HKDF-separate a d-tag key `K_dtag` from that root (codex C-low domain
//!     separation: the d-tag HMAC key is NOT the content key). The content key is
//!     NIP-44's own internally-HKDF'd sub-key from the same root, a distinct
//!     domain, so no key is reused across the two purposes.
//!   - addressable kind 30174; `d` = HMAC-SHA256(`K_dtag`, slug) so the slug never
//!     appears in plaintext on a relay; content = NIP-44(self, frame(slug,value)).
//!   - replaceable/addressable: a relay keeps only the latest per (kind, author,
//!     d-tag); a read unions the relay set and LWW-reconciles (greatest
//!     `created_at`, tie -> lowest id) then drops tombstones.
//!
//! BLAST-RADIUS (codex C-low): one identity key roots everything, so an
//! identity-key compromise IS a memory compromise. That is inherent to the
//! sovereign model (no owner, design doc §7) -- the keyfile stays 0600. The
//! domain separation here bounds cross-purpose key reuse, not key compromise.

use std::fmt::Write as _;

use anyhow::{anyhow, Context, Result};
// Leading `::` disambiguates the external crates from the `hkdf`/`hmac` modules the
// `nostr_sdk::prelude::*` glob also brings into scope (nostr's internal crypto util).
use ::hkdf::Hkdf;
use ::hmac::{Hmac, Mac};
use nostr_sdk::nips::nip44::{self, v2::ConversationKey, Version};
use nostr_sdk::prelude::*;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The addressable engram event kind (design doc §2). Addressable (30000-39999)
/// so a relay keeps only the latest per (kind, author, `d`-tag) -- the
/// replaceable semantics LWW relies on.
pub const KIND_ENGRAM: u16 = 30174;

/// The HKDF `info` label that domain-separates the d-tag key from the self-ECDH
/// root (codex C-low). Versioned so a future derivation change is unambiguous.
const HKDF_DTAG_INFO: &[u8] = b"kirby/agent-memory/v1/dtag";

/// Content-frame markers (the first plaintext byte). A tombstone (RM) carries an
/// empty value; a live engram (SET) carries the value. The marker lets a read
/// distinguish "removed" from "present" AFTER decrypt, so a tombstone is a real
/// signed event (not an absence), and LWW orders a RM against a SET correctly.
const FRAME_LIVE: u8 = 0x01;
const FRAME_TOMBSTONE: u8 = 0x00;

/// The decrypted plaintext of an engram event: the slug it addresses, its value,
/// and whether it is a tombstone. The slug travels INSIDE the sealed content (it
/// is never on the wire in plaintext -- the d-tag is its HMAC), so a read can
/// recover the slug after decrypt (the LS enumeration depends on this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngramFrame {
    pub tombstone: bool,
    pub slug: String,
    pub value: Vec<u8>,
}

impl EngramFrame {
    /// A live SET frame for `slug` carrying `value`.
    pub fn live(slug: impl Into<String>, value: Vec<u8>) -> Self {
        EngramFrame { tombstone: false, slug: slug.into(), value }
    }

    /// A tombstone (RM) frame for `slug` (no value).
    pub fn tombstone(slug: impl Into<String>) -> Self {
        EngramFrame { tombstone: true, slug: slug.into(), value: Vec::new() }
    }

    /// Encode to the plaintext byte frame: `[marker][slug_len: u16 BE][slug][value]`.
    /// The value is raw bytes (may be non-UTF-8), which is why the encrypted
    /// content is sealed/read as bytes (`nip44::decrypt_to_bytes`), not a string.
    pub fn encode(&self) -> Vec<u8> {
        let slug = self.slug.as_bytes();
        let mut out = Vec::with_capacity(3 + slug.len() + self.value.len());
        out.push(if self.tombstone { FRAME_TOMBSTONE } else { FRAME_LIVE });
        // A slug over u16::MAX is impossible under the NIP-AE grammar (segments are
        // <=64 bytes), but clamp defensively so encode never panics on a bad slug.
        let slug_len = u16::try_from(slug.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&slug_len.to_be_bytes());
        out.extend_from_slice(&slug[..slug_len as usize]);
        out.extend_from_slice(&self.value);
        out
    }

    /// Decode a plaintext byte frame produced by [`EngramFrame::encode`]. A frame
    /// that is truncated or carries an unknown marker is a corrupt/foreign engram;
    /// it is rejected (the store treats it as unreadable rather than guessing).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 3 {
            return Err(anyhow!("engram frame too short ({} bytes)", bytes.len()));
        }
        let tombstone = match bytes[0] {
            FRAME_LIVE => false,
            FRAME_TOMBSTONE => true,
            other => return Err(anyhow!("unknown engram frame marker 0x{other:02x}")),
        };
        let slug_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        let slug_end = 3 + slug_len;
        if bytes.len() < slug_end {
            return Err(anyhow!("engram frame slug truncated"));
        }
        let slug = String::from_utf8(bytes[3..slug_end].to_vec())
            .context("engram frame slug is not UTF-8")?;
        Ok(EngramFrame { tombstone, slug, value: bytes[slug_end..].to_vec() })
    }
}

/// The per-key engram crypto + addressing. Cheap to clone (a `Keys` over an `Arc`
/// secret + the 32-byte derived d-tag key). Construct once per node from the
/// identity keyfile; every method is deterministic in the key, so two instances
/// from the SAME key are interchangeable (the F8 portability property).
#[derive(Clone)]
pub struct EngramCrypto {
    keys: Keys,
    /// HKDF-derived d-tag HMAC key (32 bytes), domain-separated from the content
    /// key (codex C-low). Held so `dtag` is a cheap HMAC, not a re-derivation.
    k_dtag: [u8; 32],
}

impl EngramCrypto {
    /// Derive the crypto from the node identity keys. Computes the self-ECDH root
    /// (`K_self` = NIP-44 conversation key with the OWN pubkey) and HKDF-expands
    /// the d-tag key from it. The F8 gate: this self-pubkey ECDH is the SAME path
    /// cdk's NUT-27 wallet-backup exercises in-tree, so the lib supports it; a
    /// failure here would be a lib regression, surfaced as an error (not a panic).
    pub fn new(keys: Keys) -> Result<Self> {
        let secret = keys.secret_key();
        let pubkey = keys.public_key();
        // K_self: the self-ECDH conversation-key root (derivable from the privkey
        // alone -> portable across every reborn instance of this agent).
        let root = ConversationKey::derive(secret, &pubkey)
            .map_err(|e| anyhow!("derive self-ECDH conversation key (NIP-44 self-encrypt): {e}"))?;
        // Domain-separate the d-tag key from the root (C-low). HKDF-SHA256 with a
        // labeled info; 32 bytes is always a valid OKM length for SHA-256.
        let hk = Hkdf::<Sha256>::new(None, root.as_bytes());
        let mut k_dtag = [0u8; 32];
        hk.expand(HKDF_DTAG_INFO, &mut k_dtag)
            .expect("32-byte OKM is within HKDF-SHA256's 255*32 limit");
        Ok(EngramCrypto { keys, k_dtag })
    }

    /// This agent's public key (the engram event author + the `#p` self-tag).
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// The addressable `d` tag for a slug: `hex(HMAC-SHA256(K_dtag, slug))`. The
    /// slug never appears in plaintext on a relay; this HMAC is its stable,
    /// re-derivable address. Deterministic in the key -> a reborn agent computes
    /// the SAME `d` for the same slug and can fetch its own past memory.
    pub fn dtag(&self, slug: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.k_dtag)
            .expect("HMAC-SHA256 accepts a 32-byte key");
        mac.update(slug.as_bytes());
        to_hex(mac.finalize().into_bytes().as_slice())
    }

    /// Seal a frame into NIP-44 (v2) self-encrypted content (encrypt to the OWN
    /// pubkey). The returned base64 string is the event content.
    pub fn encrypt(&self, frame: &EngramFrame) -> Result<String> {
        nip44::encrypt(self.keys.secret_key(), &self.keys.public_key(), frame.encode(), Version::V2)
            .context("NIP-44 self-encrypt the engram content")
    }

    /// Open NIP-44 self-encrypted content back into a frame. Reads as BYTES (the
    /// value may be non-UTF-8), then decodes the frame.
    pub fn decrypt(&self, content: &str) -> Result<EngramFrame> {
        let bytes = nip44::decrypt_to_bytes(self.keys.secret_key(), &self.keys.public_key(), content)
            .context("NIP-44 self-decrypt the engram content")?;
        EngramFrame::decode(&bytes)
    }

    /// Build the (unsigned) addressable engram [`EventBuilder`] for a slug: kind
    /// 30174, `d` = the slug's HMAC tag, `#p` = self, content = the sealed frame,
    /// `created_at` = the caller's monotonic logical clock (so LWW orders writes
    /// in issue order even within one wall-clock second). The store signs +
    /// publishes it to the relay set.
    pub fn event_builder(&self, frame: &EngramFrame, created_at: Timestamp) -> Result<EventBuilder> {
        let content = self.encrypt(frame)?;
        let tags = vec![
            Tag::identifier(self.dtag(&frame.slug)),
            Tag::public_key(self.keys.public_key()),
        ];
        Ok(EventBuilder::new(Kind::from(KIND_ENGRAM), content)
            .tags(tags)
            .custom_created_at(created_at))
    }
}

/// Lowercase-hex encode (dep-free; the d-tag is the only hex this crate needs).
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// LWW head-select over a set of replaceable events that share one `d`-tag
/// (design doc §4 / NIP-01 addressable tie-break): the winner is the greatest
/// `created_at`; on a tie, the LOWEST event id. Returns `None` for an empty set.
///
/// The caller passes the union of the relay set already filtered to ONE d-tag (a
/// GET) or groups by d-tag first (an LS). This is the reconcile that makes a
/// partial/divergent relay set converge to a single head.
pub fn lww_head(events: &[Event]) -> Option<&Event> {
    events.iter().max_by(|a, b| {
        a.created_at
            .as_secs()
            .cmp(&b.created_at.as_secs())
            // Tie -> lowest id wins: make the lower-id event compare "greater" so
            // `max_by` selects it (reverse the id comparison).
            .then_with(|| b.id.cmp(&a.id))
    })
}

/// The `d`-tag value of an event (the first `d` tag), if any. Used to group an LS
/// union by address before LWW-reconciling each group.
pub fn event_dtag(event: &Event) -> Option<String> {
    event
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            if s.first().map(String::as_str) == Some("d") {
                s.get(1).cloned()
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_from_byte(b: u8) -> Keys {
        // A deterministic, valid secret key for tests (32 bytes, non-zero).
        let mut sk = [b.wrapping_add(1); 32];
        sk[31] = 0x01;
        Keys::new(SecretKey::from_slice(&sk).expect("valid 32-byte secret key"))
    }

    #[test]
    fn frame_encode_decode_round_trips_including_tombstone_and_binary_value() {
        let live = EngramFrame::live("mem/note-1", vec![0x00, 0xff, 0x10, b'h', b'i']);
        let decoded = EngramFrame::decode(&live.encode()).unwrap();
        assert_eq!(decoded, live);

        let tomb = EngramFrame::tombstone("core");
        let decoded = EngramFrame::decode(&tomb.encode()).unwrap();
        assert_eq!(decoded, tomb);
        assert!(decoded.tombstone);
        assert!(decoded.value.is_empty());
    }

    #[test]
    fn frame_decode_rejects_truncated_and_unknown_marker() {
        assert!(EngramFrame::decode(&[]).is_err());
        assert!(EngramFrame::decode(&[FRAME_LIVE, 0x00]).is_err()); // < 3 bytes
        // slug_len says 5 but no slug bytes follow.
        assert!(EngramFrame::decode(&[FRAME_LIVE, 0x00, 0x05]).is_err());
        // unknown marker byte.
        assert!(EngramFrame::decode(&[0x42, 0x00, 0x00]).is_err());
    }

    #[test]
    fn k_self_is_deterministic_in_the_key_f8_determinism_vector() {
        // F8: two independent backends from the SAME key derive identical d-tags
        // for a slug (the portability property a reborn agent depends on).
        let a = EngramCrypto::new(keys_from_byte(7)).unwrap();
        let b = EngramCrypto::new(keys_from_byte(7)).unwrap();
        for slug in ["core", "mem/note-1", "mem/a/b/c"] {
            assert_eq!(a.dtag(slug), b.dtag(slug), "d-tag must be key-deterministic");
        }
        // A DIFFERENT key derives DIFFERENT d-tags (the HMAC is keyed).
        let c = EngramCrypto::new(keys_from_byte(9)).unwrap();
        assert_ne!(a.dtag("core"), c.dtag("core"));
        // The d-tag is a 64-char lowercase hex SHA-256 HMAC.
        assert_eq!(a.dtag("core").len(), 64);
        assert!(a.dtag("core").bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn encrypt_to_self_round_trips_and_two_instances_interchange() {
        // F8: encrypt-to-self round-trips, and an instance built from the SAME key
        // can open another's sealed content (portability).
        let a = EngramCrypto::new(keys_from_byte(3)).unwrap();
        let b = EngramCrypto::new(keys_from_byte(3)).unwrap();
        let frame = EngramFrame::live("mem/secret", b"runway is finite".to_vec());
        let sealed = a.encrypt(&frame).unwrap();
        // The slug/value are NOT in the sealed content in plaintext.
        assert!(!sealed.contains("secret") && !sealed.contains("runway"));
        let opened = b.decrypt(&sealed).unwrap();
        assert_eq!(opened, frame);
    }

    #[test]
    fn encrypt_to_self_is_opaque_to_a_different_key() {
        // A different agent's key cannot open the content (encrypt-to-self privacy).
        let a = EngramCrypto::new(keys_from_byte(3)).unwrap();
        let other = EngramCrypto::new(keys_from_byte(4)).unwrap();
        let sealed = a.encrypt(&EngramFrame::live("core", b"v".to_vec())).unwrap();
        assert!(other.decrypt(&sealed).is_err());
    }

    #[test]
    fn lww_head_picks_greatest_created_at_then_lowest_id_and_handles_tombstones() {
        let crypto = EngramCrypto::new(keys_from_byte(5)).unwrap();
        let signer = keys_from_byte(5);
        let build = |frame: &EngramFrame, ts: u64| {
            crypto
                .event_builder(frame, Timestamp::from_secs(ts))
                .unwrap()
                .sign_with_keys(&signer)
                .unwrap()
        };

        // Same slug, three versions across "relays": a later SET wins over earlier.
        let v_old = build(&EngramFrame::live("mem/x", b"old".to_vec()), 1_000);
        let v_new = build(&EngramFrame::live("mem/x", b"new".to_vec()), 2_000);
        let set_union = [v_old.clone(), v_new.clone()];
        let head = lww_head(&set_union).unwrap();
        assert_eq!(head.id, v_new.id);
        assert_eq!(crypto.decrypt(&head.content).unwrap().value, b"new");

        // A tombstone at a LATER created_at wins -> the head is a tombstone.
        let tomb = build(&EngramFrame::tombstone("mem/x"), 3_000);
        let tomb_union = [v_old, v_new, tomb.clone()];
        let head = lww_head(&tomb_union).unwrap();
        assert_eq!(head.id, tomb.id);
        assert!(crypto.decrypt(&head.content).unwrap().tombstone);

        let empty: [Event; 0] = [];
        assert!(lww_head(&empty).is_none());
    }

    #[test]
    fn lww_tie_break_is_lowest_id() {
        // Two distinct events at the SAME created_at (different content -> different
        // ids): the LOWEST id must win, deterministically, on every relay.
        let crypto = EngramCrypto::new(keys_from_byte(6)).unwrap();
        let signer = keys_from_byte(6);
        let e1 = crypto
            .event_builder(&EngramFrame::live("mem/y", b"aaa".to_vec()), Timestamp::from_secs(50))
            .unwrap()
            .sign_with_keys(&signer)
            .unwrap();
        let e2 = crypto
            .event_builder(&EngramFrame::live("mem/y", b"bbb".to_vec()), Timestamp::from_secs(50))
            .unwrap()
            .sign_with_keys(&signer)
            .unwrap();
        let expected = if e1.id < e2.id { e1.id } else { e2.id };
        // Order of the input slice must not change the winner.
        assert_eq!(lww_head(&[e1.clone(), e2.clone()]).unwrap().id, expected);
        assert_eq!(lww_head(&[e2, e1]).unwrap().id, expected);
    }

    #[test]
    fn event_dtag_extracts_the_d_tag_matching_the_crypto() {
        let crypto = EngramCrypto::new(keys_from_byte(8)).unwrap();
        let signer = keys_from_byte(8);
        let ev = crypto
            .event_builder(&EngramFrame::live("mem/z", b"v".to_vec()), Timestamp::from_secs(1))
            .unwrap()
            .sign_with_keys(&signer)
            .unwrap();
        assert_eq!(event_dtag(&ev).as_deref(), Some(crypto.dtag("mem/z").as_str()));
    }
}
