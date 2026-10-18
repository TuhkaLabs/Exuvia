use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, ExuviaError>;

/// Errors surfaced by Exuvia. Every variant maps to a documented CLI exit code.
#[derive(Debug, Error)]
pub enum ExuviaError {
    #[error("no installed application matches '{0}'")]
    AppNotFound(String),

    #[error("multiple applications match '{query}': {candidates}")]
    AmbiguousApp { query: String, candidates: String },

    #[error("blocked by safety policy: {0}")]
    Safety(String),

    #[error("permission denied: {0}")]
    Permission(String),

    #[error("operation partially failed: {0}")]
    Partial(String),

    #[error("invalid usage: {0}")]
    Usage(String),

    #[error("{0}")]
    Other(String),
}

impl ExuviaError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Partial(_) => 3,
            Self::Permission(_) => 4,
            Self::Safety(_) => 5,
            Self::AppNotFound(_) | Self::AmbiguousApp { .. } | Self::Other(_) => 1,
        }
    }

    pub fn io(context: impl std::fmt::Display, error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::PermissionDenied {
            Self::Permission(format!("{context}: {error}"))
        } else {
            Self::Other(format!("{context}: {error}"))
        }
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }
}

impl From<io::Error> for ExuviaError {
    fn from(error: io::Error) -> Self {
        Self::io("I/O error", error)
    }
}

impl From<serde_json::Error> for ExuviaError {
    fn from(error: serde_json::Error) -> Self {
        Self::Other(format!("JSON error: {error}"))
    }
}
