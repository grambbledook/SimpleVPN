use blake2::{Blake2s256, Digest};

use crate::protocol::consts::BLAKE2B_HASH_SIZE;

pub fn hash(data: &[&[u8]]) -> [u8; BLAKE2B_HASH_SIZE] {
    let mut hasher = Blake2s256::new();
    for worf in data {
        hasher.update(worf);
    }
    let mut hash = [0u8; BLAKE2B_HASH_SIZE];
    hasher.finalize_into((&mut hash).into());
    hash
}

/// HKDF extract, RFC 5869 section 2.2: `PRK = HMAC(salt, ikm)`.
///
/// `salt` is the HMAC key, not the secret. In the handshake it is the running
/// chaining key C. `ikm` is the secret being mixed in: a DH output, an
/// ephemeral public key, or the pre-shared key.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; BLAKE2B_HASH_SIZE] {
    todo!()
}

/// HKDF expand, RFC 5869 section 2.3. Computes one block:
/// `T(n) = HMAC(prk, prev | n)`.
///
/// `prev` is `T(n-1)`; pass an empty slice for the first block. `counter` is
/// `n` itself, one byte. RFC 5869's `info` is always empty in WireGuard, so
/// there is no argument for it.
pub fn hkdf_expand(prk: &[u8], prev: &[u8], counter: u8) -> [u8; BLAKE2B_HASH_SIZE] {
    todo!()
}

/// Extract once, then expand one block.
///
/// Returns `T(1)`.
pub fn kdf1(salt: &[u8], ikm: &[u8]) -> [u8; BLAKE2B_HASH_SIZE] {
    todo!()
}

/// Extract once, then expand two chained blocks.
///
/// Returns `(T(1), T(2))`. In the handshake the first is the new chaining
/// key, the second an AEAD key.
pub fn kdf2(salt: &[u8], ikm: &[u8]) -> ([u8; BLAKE2B_HASH_SIZE], [u8; BLAKE2B_HASH_SIZE]) {
    todo!()
}

/// Extract once, then expand three chained blocks.
///
/// Returns `(T(1), T(2), T(3))`. Used only for the pre-shared key step:
/// chaining key, tau, AEAD key.
pub fn kdf3(
    salt: &[u8],
    ikm: &[u8],
) -> (
    [u8; BLAKE2B_HASH_SIZE],
    [u8; BLAKE2B_HASH_SIZE],
    [u8; BLAKE2B_HASH_SIZE],
) {
    todo!()
}
