mod algorithm;

use algorithm::Algorithm;

use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Alg {
    HS256,
}

impl Alg {
    pub(super) fn sign(&self, secret: &[u8], data: String) -> Result<Vec<u8>> {
        Ok(match self {
            Self::HS256 => algorithm::HS256::init(secret, data)?.sign(),
        })
    }

    pub(super) fn verify(&self, secret: &[u8], data: String, signature: &[u8]) -> Result<bool> {
        Ok(match self {
            Self::HS256 => algorithm::HS256::init(secret, data)?.verify(signature),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Typ {
    Jwt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub(super) alg: Alg,
    typ: Typ,
}

impl Header {
    pub fn new(alg: Alg) -> Self {
        Self { alg, typ: Typ::Jwt }
    }
}
