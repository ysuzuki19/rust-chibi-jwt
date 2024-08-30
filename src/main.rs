use serde::{Deserialize, Serialize};

use rust_chibi_jwt::{Alg, Jwt};

// Define payload for sample
// `PartialEq` is unnecessary, but it's using for assert_eq! in main
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Payload {
    sub: String,
    name: String,
    iat: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // dummy token with secret "my-secret"
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.EpM5XBzTJZ4J8AfoJEcJrjth8pfH28LWdjLo90sYb9g";
    let secret: &[u8; 9] = b"my-secret";
    let payload = Payload {
        sub: "1234567890".to_string(),
        name: "John Doe".to_string(),
        iat: 1516239022,
    };

    {
        // Decode and Encode
        let jwt = Jwt::<Payload>::decode(token)?;

        assert!(jwt.verify(secret)?);
        assert_eq!(jwt.payload(), &payload);

        let reencoded: String = jwt.encode()?;
        assert_eq!(token, reencoded);

        println!("Jwt Decode/Encode is OK");
    }

    {
        // Sign and Encode
        let mut jwt = Jwt::new(Alg::HS256, payload);
        jwt.sign(secret)?;
        let encoded: String = jwt.encode()?;
        assert_eq!(token, encoded);

        println!("Jwt Sign/Encode is OK");
    }

    Ok(())
}
