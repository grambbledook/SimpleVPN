use x25519_dalek::{PublicKey as X25519PublicKey, PrivateKey as X25519PrivateKey, StaticSecret as X25519SharedSecret};
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const PRIVATE_KEY_SIZE: usize = 32;
pub const SHARED_SECRET_SIZE: usize = 32;
pub const RESERVED_SPACE_SIZE: usize = 3;
pub const TAI_64_NANO_TIMESTAMP_SIZE: usize = 12;
pub const COOKIE_NONCE_SIZE: usize = 24;
pub const COOKIE_SIZE: usize = 16;

pub struct Privatekey([u8; PRIVATE_KEY_SIZE]);
pub struct Publickey([u8; PUBLIC_KEY_SIZE]);
pub struct SharedSecret([u8; SHARED_SECRET_SIZE]);
pub struct CookieNonce([u8; COOKIE_NONCE_SIZE]);

pub type KeyError = std::io::Error;

impl Privatekey {
    pub fn generate() -> Self {
        let mut sk = [0u8; PRIVATE_KEY_SIZE];
        getrandom::fill(&mut sk).expect("failed to genersate the token");
        Privatekey(sk)
    }

    pub fn public_key(&self) -> Publickey {
       let sk =
        Publickey([0u8; PUBLIC_KEY_SIZE])
    }

    pub fn shared_secret(&self, public_key: &Publickey) -> Result<SharedSecret, KeyError> {
        return Result::Ok(SharedSecret([0u8; SHARED_SECRET_SIZE]));
    }
}
 