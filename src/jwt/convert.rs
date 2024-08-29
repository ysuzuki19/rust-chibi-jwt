use crate::error::Error;

use super::Jwt;

impl<P> TryFrom<&str> for Jwt<P>
where
    P: serde::ser::Serialize + serde::de::DeserializeOwned,
{
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::decode(value)
    }
}

impl<P> TryFrom<String> for Jwt<P>
where
    P: serde::ser::Serialize + serde::de::DeserializeOwned,
{
    type Error = Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::decode(value)
    }
}

impl<P> TryFrom<Jwt<P>> for String
where
    P: serde::ser::Serialize + serde::de::DeserializeOwned,
{
    type Error = Error;

    fn try_from(value: Jwt<P>) -> std::result::Result<Self, Self::Error> {
        value.encode()
    }
}

#[cfg(test)]
mod tests {
    use crate::jwt::tests::TestJwt;

    const VALID_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.mpHl842O7xEZjgQ8CyX8xYLDoEORGVMnAxULkW-u8Ek";

    #[test]
    fn try_from_try_into() -> crate::error::Result<()> {
        let jwt = TestJwt::try_from(VALID_TOKEN)?;
        let reencoded: String = jwt.try_into()?;
        assert_eq!(VALID_TOKEN, reencoded);
        let jwt = TestJwt::try_from(String::from(VALID_TOKEN))?;
        let reencoded: String = jwt.try_into()?;
        assert_eq!(VALID_TOKEN, reencoded);
        Ok(())
    }
}
