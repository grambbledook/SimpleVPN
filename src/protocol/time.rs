use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocol::consts::{TAI_64_NANO_TIMESTAMP_OFFSET, TAI_64_NANO_TIMESTAMP_SIZE};

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Tai64n([u8; TAI_64_NANO_TIMESTAMP_SIZE]);

impl Tai64n {
    pub fn now(t: SystemTime) -> Self {
        let since_epoch = t
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before the Unix epoch");

        let seconds = TAI_64_NANO_TIMESTAMP_OFFSET + since_epoch.as_secs();
        let nanos = since_epoch.subsec_nanos() & !0x00FF_FFFF;

        let mut bytes = [0u8; TAI_64_NANO_TIMESTAMP_SIZE];
        bytes[..8].copy_from_slice(&seconds.to_be_bytes());
        bytes[8..12].copy_from_slice(&nanos.to_be_bytes());

        Tai64n(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn known_epoch_produces_known_bytes() {
        let t = UNIX_EPOCH + Duration::new(1, 123_456_789);

        let ts = Tai64n::now(t);

        assert_eq!(
            ts,
            Tai64n([
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x07, 0x00, 0x00, 0x00
            ])
        );
    }

    #[test]
    fn ordering_holds_across_two_calls() {
        let first = Tai64n::now(SystemTime::now());
        let second = Tai64n::now(SystemTime::now());

        assert!(second.as_bytes() >= first.as_bytes());
    }
}
