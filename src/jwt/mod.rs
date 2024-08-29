mod base64;
mod convert;
pub mod header;
#[cfg(test)]
mod tests;

use base64::Base64;
use header::Header;

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct Jwt<P>
where
    P: Clone + serde::ser::Serialize + serde::de::DeserializeOwned,
{
    header: Header,
    payload: P,
    signature: Vec<u8>,
}

impl<P> Jwt<P>
where
    P: Clone + serde::ser::Serialize + serde::de::DeserializeOwned,
{
    pub fn new(alg: header::Alg, payload: P) -> Self {
        Self {
            header: Header::new(alg),
            payload,
            signature: Vec::new(),
        }
    }

    pub fn decode<S: AsRef<str>>(token: S) -> Result<Self> {
        let parts = token.as_ref().split('.').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(Error::DecodeInvalidParts);
        }
        Ok(Self {
            header: Base64::deserialize(parts[0])?,
            payload: Base64::deserialize(parts[1])?,
            signature: Base64::decode(parts[2])?,
        })
    }

    pub fn encode(self) -> Result<String> {
        if self.signature.is_empty() {
            return Err(Error::EncodeUnsigned);
        }
        Ok(dot_join(&[
            Base64::serialize(&self.header)?,
            Base64::serialize(&self.payload)?,
            Base64::encode(self.signature),
        ]))
    }

    pub fn sign(&mut self, secret: &[u8]) -> Result<()> {
        let data = dot_join(&[
            Base64::serialize(&self.header)?,
            Base64::serialize(&self.payload)?,
        ]);
        self.signature = self.header.alg.sign(secret, data)?;
        Ok(())
    }

    pub fn verify(&self, secret: &[u8]) -> Result<bool> {
        let data = dot_join(&[
            Base64::serialize(&self.header)?,
            Base64::serialize(&self.payload)?,
        ]);
        self.header.alg.verify(secret, data, &self.signature)
    }
}

#[inline(always)]
fn dot_join(parts: &[String]) -> String {
    parts.join(".")
}
