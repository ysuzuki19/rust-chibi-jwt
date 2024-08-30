use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};

use crate::error::Result;

pub(crate) struct Base64;
impl Base64 {
    pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(input)
    }

    pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> {
        Ok(BASE64_URL_SAFE_NO_PAD.decode(input)?)
    }

    /// Serialize a value to a base64 string
    pub fn serialize<T: serde::ser::Serialize>(input: &T) -> Result<String> {
        let serialized = serde_json::to_string(input)?;
        Ok(Base64::encode(serialized))
    }

    /// Deserialize a value from a base64 string
    pub fn deserialize<T: serde::de::DeserializeOwned>(input: &str) -> Result<T> {
        let decoded = Base64::decode(input)?;
        Ok(serde_json::from_slice(decoded.as_slice())?)
    }
}

#[cfg(test)]
mod tests {
    use crate::{jwt::header::Header, Alg};

    use super::*;

    #[test]
    fn encode_decode() -> Result<()> {
        let cases = vec![
            (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                r#"{"alg":"HS256","typ":"JWT"}"#,
            ),
            (
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
                r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#,
            ),
        ];
        for (input, expected) in cases {
            let decoded = String::from_utf8(Base64::decode(input)?)?;
            println!("decoded: {:?}", decoded);
            assert_eq!(decoded, expected);
            let reencoded = Base64::encode(decoded);
            assert_eq!(input, reencoded);
        }
        Ok(())
    }

    #[test]
    fn deserialize_serialize() -> Result<()> {
        let input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}
        let v: Header = Base64::deserialize(input)?;
        matches!(v.alg, Alg::HS256);
        let reencoded = Base64::serialize(&v)?;
        assert_eq!(input, reencoded);

        Ok(())
    }
}
