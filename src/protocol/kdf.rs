use blake2::{Blake2s256, Digest};
use hmac::{KeyInit, Mac, SimpleHmac};

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
    let mut mac = <SimpleHmac<Blake2s256>>::new_from_slice(salt).unwrap();
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

/// HKDF expand, RFC 5869 section 2.3. Computes one block:
/// `T(n) = HMAC(prk, prev | n)`.
///
/// `prev` is `T(n-1)`; pass an empty slice for the first block. `counter` is
/// `n` itself, one byte. RFC 5869's `info` is always empty in WireGuard, so
/// there is no argument for it.
pub fn hkdf_expand(prk: &[u8], prev: &[u8], counter: u8) -> [u8; BLAKE2B_HASH_SIZE] {
    let mut mac = <SimpleHmac<Blake2s256>>::new_from_slice(prk).unwrap();
    mac.update(prev);
    mac.update(&[counter]);
    mac.finalize().into_bytes().into()
}

/// Extract once, then expand one block.
///
/// Returns `T(1)`.
pub fn kdf1(salt: &[u8], ikm: &[u8]) -> [u8; BLAKE2B_HASH_SIZE] {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, &[], 1)
}

/// Extract once, then expand two chained blocks.
///
/// Returns `(T(1), T(2))`. In the handshake the first is the new chaining
/// key, the second an AEAD key.
pub fn kdf2(salt: &[u8], ikm: &[u8]) -> ([u8; BLAKE2B_HASH_SIZE], [u8; BLAKE2B_HASH_SIZE]) {
    let prk = hkdf_extract(salt, ikm);
    let t0 = hkdf_expand(&prk, &[], 1);
    let t1 = hkdf_expand(&prk, &t0, 2);
    return (t0, t1);
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
    let prk = hkdf_extract(salt, ikm);
    let t0 = hkdf_expand(&prk, &[], 1);
    let t1 = hkdf_expand(&prk, &t0, 2);
    let t2 = hkdf_expand(&prk, &t1, 3);
    return (t0, t1, t2);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct KdfTest {
        key: &'static str,
        input: &'static str,
        t0: &'static str,
        t1: &'static str,
        t2: &'static str,
    }

    const KDF_TESTS: [KdfTest; 3] = [
        KdfTest {
            key: "746573742d6b6579",
            input: "746573742d696e707574",
            t0: "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633",
            t1: "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a",
            t2: "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24",
        },
        KdfTest {
            key: "776972656775617264",
            input: "776972656775617264",
            t0: "491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8",
            t1: "1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f",
            t2: "31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160",
        },
        KdfTest {
            key: "",
            input: "",
            t0: "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0",
            t1: "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e",
            t2: "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e",
        },
    ];

    #[test]
    fn test_kdf() {
        for (i, test) in KDF_TESTS.iter().enumerate() {
            let key = hex::decode(test.key).unwrap();
            let input = hex::decode(test.input).unwrap();

            let t0 = kdf1(&key, &input);
            assert_eq!(hex::encode(t0), test.t0, "kdf1 t0, test {i}");

            let (t0, t1) = kdf2(&key, &input);
            assert_eq!(hex::encode(t0), test.t0, "kdf2 t0, test {i}");
            assert_eq!(hex::encode(t1), test.t1, "kdf2 t1, test {i}");

            let (t0, t1, t2) = kdf3(&key, &input);
            assert_eq!(hex::encode(t0), test.t0, "kdf3 t0, test {i}");
            assert_eq!(hex::encode(t1), test.t1, "kdf3 t1, test {i}");
            assert_eq!(hex::encode(t2), test.t2, "kdf3 t2, test {i}");
        }
    }
}
