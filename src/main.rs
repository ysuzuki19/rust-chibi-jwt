use serde::{Deserialize, Serialize};

use rust_chibi_jwt::Jwt;

// Define payload as sample
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    sub: String,
    name: String,
    iat: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // dummy token with secret "my-secret"
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.EpM5XBzTJZ4J8AfoJEcJrjth8pfH28LWdjLo90sYb9g";
    println!("Input:  {}", token);
    let mut jwt = Jwt::<Payload>::try_from(token)?;
    println!("{:?}", jwt);

    let secret: &[u8; 9] = b"my-secret";
    assert!(jwt.verify(secret)?);
    jwt.sign(secret)?;

    assert!(jwt.verify(secret)?);
    let reencoded: String = jwt.try_into()?;
    println!("Output: {}", reencoded);
    Ok(())
}
