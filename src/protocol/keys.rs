use std::io::ErrorKind;

use crate::protocol::consts::{
    COOKIE_NONCE_SIZE, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, SHARED_SECRET_SIZE,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekStaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct PrivateKey([u8; PRIVATE_KEY_SIZE]);
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct SharedSecret([u8; SHARED_SECRET_SIZE]);
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct CookieNonce([u8; COOKIE_NONCE_SIZE]);

pub type KeyError = std::io::Error;

impl From<[u8; PRIVATE_KEY_SIZE]> for PrivateKey {
    fn from(bytes: [u8; PRIVATE_KEY_SIZE]) -> Self {
        PrivateKey::clamped(bytes)
    }
}

fn decode_key<const N: usize>(s: &str, what: &str) -> Result<[u8; N], KeyError> {
    STANDARD
        .decode(s)
        .map_err(|e| KeyError::new(ErrorKind::InvalidData, e))?
        .as_slice()
        .try_into()
        .map_err(|_| KeyError::new(ErrorKind::InvalidData, format!("{what} must be {N} bytes")))
}

pub trait Base64: Sized {
    fn to_base64(&self) -> String;
    fn from_base64(s: &str) -> Result<Self, KeyError>;
}

impl Base64 for PublicKey {
    fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }
    fn from_base64(s: &str) -> Result<Self, KeyError> {
        Ok(PublicKey(decode_key(s, "public key")?))
    }
}

impl Base64 for PrivateKey {
    fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }
    fn from_base64(s: &str) -> Result<Self, KeyError> {
        Ok(PrivateKey(decode_key(s, "private key")?))
    }
}

impl From<[u8; PUBLIC_KEY_SIZE]> for PublicKey {
    fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey(bytes)
    }
}

impl PrivateKey {
    /// Curve25519 clamping (RFC 7748 §5, `decodeScalar25519`).
    ///
    /// x25519-dalek clamps internally on every scalar multiplication, so this
    /// affects neither the derived public key nor the shared secret. It runs on
    /// the two paths that mint a key from arbitrary bytes — `generate` and
    /// `From<[u8; PRIVATE_KEY_SIZE]>` — so that what we store is the scalar the
    /// key will actually be used as, the same point at which Go clamps.
    ///
    /// `from_base64` deliberately skips it, so a parsed key re-encodes to the
    /// string it came from. Go's `FromBase64` does not clamp either.
    fn clamped(mut sk: [u8; PRIVATE_KEY_SIZE]) -> Self {
        sk[0] &= 248;
        sk[31] = (sk[31] & 127) | 64;
        PrivateKey(sk)
    }

    pub fn generate() -> Self {
        let mut sk = [0u8; PRIVATE_KEY_SIZE];
        getrandom::fill(&mut sk).expect("failed to genersate the key");
        Self::clamped(sk)
    }

    pub fn public_key(&self) -> PublicKey {
        let sk = DalekStaticSecret::from(self.0);
        PublicKey(DalekPublicKey::from(&sk).to_bytes())
    }

    pub fn shared_secret(&self, public_key: &PublicKey) -> Result<SharedSecret, KeyError> {
        let sk = DalekStaticSecret::from(self.0);
        let ss = sk.diffie_hellman(&DalekPublicKey::from(public_key.0));

        if !ss.was_contributory() {
            return Err(KeyError::new(
                std::io::ErrorKind::InvalidData,
                "bad input point: low order point",
            ));
        }
        Result::Ok(SharedSecret(ss.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh() {
        let alice_sk = PrivateKey::generate();
        let bob_sk = PrivateKey::generate();

        println!("Alice's private key: {:02x?}", alice_sk);
        println!("Bob's private key: {:02x?}", bob_sk);

        let alice_pk = alice_sk.public_key();
        let bob_pk = bob_sk.public_key();

        println!("Alice's public key: {:02x?}", alice_pk);
        println!("Bob's public key: {:02x?}", bob_pk);

        let alice_ss = alice_sk.shared_secret(&bob_pk).unwrap();
        let bob_ss = bob_sk.shared_secret(&alice_pk).unwrap();

        println!("Alice's shared secret: {:02x?}", alice_ss);
        println!("Bob's shared secret: {:02x?}", bob_ss);

        assert_eq!(alice_ss, bob_ss, "Shared secrets do not match");
    }

    #[test]
    fn test_private_key_parsing_and_derivation() -> Result<(), Box<dyn std::error::Error>> {
        let original_sk = "WEGlnZqW7a3J+AmKoDg+/L95sSIutu9ApEp3AY+l30o=";
        let original_pk = "pMo33VR8Lwi0nmi3sAFTFttomPI71LSMkEjFXws94wU=";

        let sk = PrivateKey::from_base64(original_sk)?;
        let pk = PublicKey::from_base64(original_pk)?;

        assert_eq!(sk.public_key(), pk, "Public keys do not match");
        assert_eq!(sk.to_base64(), original_sk, "SKeys does not match");
        assert_eq!(
            sk.public_key().to_base64(),
            original_pk,
            "PKeys does not match"
        );

        Ok(())
    }
}
