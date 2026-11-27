//! Typed errors for the Blindbit tweak endpoints.
//!
//! A failing tweak fetch must surface as an error — an `{"error": ...}`
//! body, a non-success HTTP status, or a body that does not parse as the
//! expected JSON shape is never silently coerced into an empty result.

use reqwest::StatusCode;

/// Error surfaces from the Blindbit tweak endpoints (`/tweaks`,
/// `/tweak-index`).
#[derive(Debug)]
pub enum BlindbitError {
    /// The server answered (any status) with a structured error body:
    /// `{"error": "..."}`.
    ServerError {
        endpoint: String,
        status: StatusCode,
        message: String,
    },
    /// The server answered with a non-success status and a body that is
    /// not a structured `{"error": ...}` object.
    HttpError {
        endpoint: String,
        status: StatusCode,
        body: String,
    },
    /// The body could not be parsed as the expected JSON shape (e.g. not
    /// a sequence of public keys).
    MalformedBody {
        endpoint: String,
        body: String,
        source: serde_json::Error,
    },
}

impl std::fmt::Display for BlindbitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerError {
                endpoint,
                status,
                message,
            } => {
                write!(f, "{endpoint} returned {status} with error body: {message}")
            }
            Self::HttpError {
                endpoint,
                status,
                body,
            } => {
                write!(f, "{endpoint} returned {status}: {body}")
            }
            Self::MalformedBody { endpoint, body, .. } => {
                write!(
                    f,
                    "{endpoint} returned a body that is not a tweak list: {body}"
                )
            }
        }
    }
}

impl std::error::Error for BlindbitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MalformedBody { source, .. } => Some(source),
            _ => None,
        }
    }
}
