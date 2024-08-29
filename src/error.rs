pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("utf8 decode error {0}")]
    Utf8Decode(#[from] std::string::FromUtf8Error),

    #[error("base64 decode error {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("json decode error {0}")]
    JsonDecode(#[from] serde_json::Error),

    #[error("hmac error {0}")]
    HmacDigestInvalidLength(#[from] hmac::digest::InvalidLength),

    #[error("decode error: jwt must have 3 parts separated by '.'")]
    DecodeInvalidParts,

    #[error("encode error: jwt must be signed")]
    EncodeUnsigned,
}
