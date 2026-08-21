use crate::protocol::consts::{
    COOKIE_NONCE_SIZE, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, SHARED_SECRET_SIZE,
};
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekStaticSecret};

#[cfg_attr(test, derive(Debug))]
pub struct PrivateKey([u8; PRIVATE_KEY_SIZE]);
#[cfg_attr(test, derive(Debug))]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct SharedSecret([u8; SHARED_SECRET_SIZE]);
#[cfg_attr(test, derive(Debug))]
pub struct CookieNonce([u8; COOKIE_NONCE_SIZE]);

pub type KeyError = std::io::Error;

impl PrivateKey {
    pub fn generate() -> Self {
        let mut sk = [0u8; PRIVATE_KEY_SIZE];
        getrandom::fill(&mut sk).expect("failed to genersate the token");
        PrivateKey(sk)
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
}
