use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub fn from_64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(s)
}

pub fn to_64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
