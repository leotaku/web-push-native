use thiserror::Error;

/// Result with this crate's error.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for the crate.
#[derive(Error, Debug)]
pub enum Error {
    #[error("could not encrypt using ECE")]
    Encryption(#[from] ece_native::Error),

    #[error("could not build request")]
    Http(#[from] http::Error),

    #[cfg(feature = "vapid")]
    #[error("invalid subscription endpoint: {0}")]
    InvalidSubscriptionEndpoint(&'static str),

    #[cfg(feature = "vapid")]
    #[error("VAPID signing failed")]
    VapidSignature(#[from] jwt_simple::Error),
}
