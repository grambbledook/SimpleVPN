use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekStaticSecret};
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const PRIVATE_KEY_SIZE: usize = 32;
pub const SHARED_SECRET_SIZE: usize = 32;
pub const RESERVED_SPACE_SIZE: usize = 3;
pub const TAI_64_NANO_TIMESTAMP_SIZE: usize = 12;
pub const COOKIE_NONCE_SIZE: usize = 24;
pub const COOKIE_SIZE: usize = 16;

pub struct PrivateKey([u8; PRIVATE_KEY_SIZE]);
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);
pub struct SharedSecret([u8; SHARED_SECRET_SIZE]);
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
