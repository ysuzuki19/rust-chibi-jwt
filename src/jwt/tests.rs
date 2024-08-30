use serde::{Deserialize, Serialize};

use crate::error::Result;

use super::Jwt;

// Define for Testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestPayload {
    sub: String,
    name: String,
    iat: u64,
}
pub type TestJwt = Jwt<TestPayload>;

const VALID_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.mpHl842O7xEZjgQ8CyX8xYLDoEORGVMnAxULkW-u8Ek";
const TAMPERED_TOKEN : &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkxIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.mpHl842O7xEZjgQ8CyX8xYLDoEORGVMnAxULkW-u8Ek";
const SECRET: &[u8; 11] = b"test-secret";

#[test]
fn encode_decode() -> Result<()> {
    let jwt = TestJwt::decode(VALID_TOKEN)?;
    let reencoded = jwt.encode()?;
    assert_eq!(VALID_TOKEN, reencoded);
    Ok(())
}

#[test]
fn verify() -> Result<()> {
    let jwt = TestJwt::decode(VALID_TOKEN)?;
    assert!(jwt.verify(SECRET)?);
    assert!(!jwt.verify(b"dummy-secret")?);
    Ok(())
}

#[test]
fn sign() -> Result<()> {
    let mut jwt = TestJwt::decode(VALID_TOKEN)?;
    assert!(jwt.verify(SECRET)?);
    jwt.sign(b"")?;
    assert!(!jwt.verify(SECRET)?);
    jwt.sign(SECRET)?;
    assert!(jwt.verify(SECRET)?);
    Ok(())
}

#[test]
fn tampering() -> Result<()> {
    let mut jwt = TestJwt::decode(TAMPERED_TOKEN)?;
    assert!(!jwt.verify(SECRET)?);
    jwt.sign(b"")?;
    assert!(!jwt.verify(SECRET)?);
    jwt.sign(SECRET)?;
    assert!(jwt.verify(SECRET)?);
    Ok(())
}
