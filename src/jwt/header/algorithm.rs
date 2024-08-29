use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::Result;

pub(super) trait Algorithm {
    fn init(secret: &[u8], data: String) -> Result<Self>
    where
        Self: Sized;
    fn verify(self, signature: &[u8]) -> bool;
    fn sign(self) -> Vec<u8>;
}

pub(super) struct HS256(Hmac<Sha256>);

impl Algorithm for HS256 {
    fn init(secret: &[u8], data: String) -> Result<Self> {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
        mac.update(data.as_bytes());
        Ok(Self(mac))
    }

    fn verify(self, signature: &[u8]) -> bool {
        let result = self.0.verify_slice(signature);
        result.is_ok()
    }

    fn sign(self) -> Vec<u8> {
        self.0.finalize().into_bytes().to_vec()
    }
}
