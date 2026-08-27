use crate::protocol::consts::{
    COOKIE_NONCE_SIZE, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, SHARED_SECRET_SIZE,
};
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

impl From<[u8; PUBLIC_KEY_SIZE]> for PublicKey {
    fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey(bytes)
    }
}

impl PrivateKey {
    /// Curve25519 clamping (RFC 7748 §5, `decodeScalar25519`).
    ///
    /// x25519-dalek clamps internally on every multiplication, so this does not
    /// change the derived public key or the shared secret. It is done here so
    /// the stored bytes are always a valid scalar, matching the Go
    /// implementation, whose PrivateKey is clamped at construction.
    fn clamped(mut sk: [u8; PRIVATE_KEY_SIZE]) -> Self {
        sk[0] &= 248;
        sk[31] = (sk[31] & 127) | 64;
        PrivateKey(sk)
    }

    pub fn generate() -> Self {
        let mut sk = [0u8; PRIVATE_KEY_SIZE];
        getrandom::fill(&mut sk).expect("failed to genersate the token");
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
        return Result::Ok(SharedSecret(ss.to_bytes()));
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::base64::from_64;

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

        let sk_bytes: [u8; PRIVATE_KEY_SIZE] = from_64(original_sk)?[..].try_into()?;
        let pk_bytes: [u8; PUBLIC_KEY_SIZE] = from_64(original_pk)?[..].try_into()?;

        let sk = PrivateKey::from(sk_bytes);
        let pk = PublicKey::from(pk_bytes);

        assert_eq!(sk.public_key(), pk, "Public keys do not match");

        Ok(())
    }
}
