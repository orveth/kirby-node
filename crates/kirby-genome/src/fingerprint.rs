//! The entropy fingerprint (spec 3.4, 4.4, gate G7): the spike instrument that
//! proves a resumed genome RE-DERIVED its ephemeral secrets instead of reusing
//! pre-snapshot PRNG state.
//!
//! The genome derives `fingerprint = H(nonce || vm_generation)` from a fresh
//! host-CSPRNG nonce (fetched via `GetEntropyNonce`) and the VMGenID generation
//! that call is tagged with. In the real system the "ephemeral secret" would be a
//! FROST signing nonce; here the fingerprint is a stand-in: a resumed clone that
//! skips the re-derive (reuses the pre-snapshot nonce + generation) produces an
//! IDENTICAL fingerprint, which is exactly the catastrophic nonce-reuse the gate
//! catches. A clone that re-derives gets a fresh nonce (and a bumped generation),
//! so its fingerprint DIFFERS. The G7 test asserts the correct genome's pre/post
//! fingerprints differ and the negative-control genome's match.
//!
//! `H` is SHA-256, implemented here with no external crate so the static musl
//! genome stays lean (the crate deliberately carries no crypto dependency) and the
//! reproducible genome-image build pulls in no new cross-compiled subtree. The
//! fingerprint only needs a real hash with good avalanche so distinct inputs
//! reliably differ; SHA-256 is deterministic and self-contained.

/// Derive the entropy fingerprint `H(nonce || vm_generation)` as a lowercase hex
/// string. The generation is appended as its 8 big-endian bytes so the
/// pre-snapshot generation and the post-resume (bumped) generation feed distinct
/// inputs even if a nonce somehow repeated. Distinct `(nonce, gen)` inputs yield a
/// distinct digest (SHA-256), so a re-derived fingerprint differs from a reused one.
pub fn derive(nonce: &[u8], vm_generation: u64) -> String {
    let mut input = Vec::with_capacity(nonce.len() + 8);
    input.extend_from_slice(nonce);
    input.extend_from_slice(&vm_generation.to_be_bytes());
    to_hex(&sha256(&input))
}

/// Lowercase-hex encode a byte slice (no external crate). `pub(crate)` so other genome modules
/// (e.g. the oracle's content-addressed charge key) reuse the SAME dependency-free hex encoder.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// SHA-256 (FIPS 180-4), self-contained, no dependency. Returns the 32-byte digest.
/// This is the spike's `H`: a deterministic hash with strong avalanche so the
/// fingerprint reliably differs whenever the input `(nonce, generation)` differs.
/// `pub(crate)` so the oracle's content-addressed charge key hashes request identity with the
/// SAME vetted hasher (no new crypto dependency, F5).
pub(crate) fn sha256(message: &[u8]) -> [u8; 32] {
    // Initial hash values: the fractional parts of the square roots of the first
    // eight primes (FIPS 180-4 5.3.3).
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Round constants: the fractional parts of the cube roots of the first
    // sixty-four primes (FIPS 180-4 4.2.2).
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // Pre-processing (padding, FIPS 180-4 5.1.1): append 0x80, then zero bytes
    // until the length is 56 mod 64, then the 64-bit big-endian bit length.
    let bit_len = (message.len() as u64).wrapping_mul(8);
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit block.
    for block in padded.chunks_exact(64) {
        // Message schedule W[0..64].
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *word = u32::from_be_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Working variables.
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut digest = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::{derive, sha256, to_hex};

    /// SHA-256 must match the FIPS 180-4 published vectors, so `H` is a real,
    /// correct hash (the fingerprint's avalanche depends on it).
    #[test]
    fn sha256_known_vectors() {
        // The empty string.
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // "abc" (the canonical FIPS example).
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // A 56-byte message that exercises the two-block padding boundary.
        assert_eq!(
            to_hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// A re-derived fingerprint (fresh nonce, bumped generation) DIFFERS from the
    /// reused one. This is the property G7 leans on: different `(nonce, gen)` ->
    /// different fingerprint, so a resumed clone that re-derives cannot collide
    /// with its pre-snapshot fingerprint.
    #[test]
    fn fingerprint_differs_on_fresh_nonce_or_bumped_generation() {
        let nonce_pre = [7u8; 32];
        let nonce_post = [9u8; 32];
        // Same nonce, bumped generation => different fingerprint.
        assert_ne!(derive(&nonce_pre, 0), derive(&nonce_pre, 1));
        // Fresh nonce, bumped generation (the real re-derive) => different.
        assert_ne!(derive(&nonce_pre, 0), derive(&nonce_post, 1));
        // The reuse case (identical nonce AND generation) => identical (the
        // negative control's fingerprint collision the gate catches).
        assert_eq!(derive(&nonce_pre, 0), derive(&nonce_pre, 0));
    }
}
