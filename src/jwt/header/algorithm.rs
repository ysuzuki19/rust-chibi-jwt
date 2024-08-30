use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::Result;

pub(super) trait Algorithm {
    fn init<T: AsRef<[u8]>>(secret: &[u8], data: T) -> Result<Self>
    where
        Self: Sized;
    fn verify(self, signature: &[u8]) -> bool;
    fn sign(self) -> Vec<u8>;
}

#[derive(Clone)]
pub(super) struct HS256(Hmac<Sha256>);

impl Algorithm for HS256 {
    fn init<T: AsRef<[u8]>>(secret: &[u8], data: T) -> Result<Self> {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
        mac.update(data.as_ref());
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

#[cfg(test)]
mod tests {
    use crate::jwt::base64::Base64;

    use super::*;

    #[test]
    fn sign_verify() -> Result<()> {
        const VALID_DATA:&str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        const TAMPERED_DATA : &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkxIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        let signature = Base64::decode("mpHl842O7xEZjgQ8CyX8xYLDoEORGVMnAxULkW-u8Ek")?;
        const SECRET: &[u8; 11] = b"test-secret";

        let hs256 = HS256::init(SECRET, VALID_DATA)?;
        assert!(hs256.verify(&signature));

        let hs256 = HS256::init(SECRET, TAMPERED_DATA)?;
        assert!(!hs256.clone().verify(&signature));

        let hs256 = HS256::init(SECRET, TAMPERED_DATA)?;
        let signature = hs256.clone().sign();
        assert!(hs256.verify(&signature));
        Ok(())
    }
}
