#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("Protobuf encode error: {0}")]
    Encode(#[from] prost::EncodeError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Registration failed: {0}")]
    Registration(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("MCS Protocol error: {0}")]
    Protocol(String),

    #[error("System time error: {0}")]
    Time(#[from] std::time::SystemTimeError),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
