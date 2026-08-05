use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum IssuerServiceError {
    #[error("SD-JWT VC type metadata `{0}` not found")]
    MissingSdJwtVcTypeMetadata(String),
    #[error("Protocol `{0}` not found")]
    MissingProtocol(String),

    #[error("Input validation error")]
    InvalidInput,
    #[error("Format validation error")]
    InvalidFormat,

    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for IssuerServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingSdJwtVcTypeMetadata(_) => ErrorCode::BR_0172,
            Self::MissingProtocol(_) => ErrorCode::BR_0046,
            Self::InvalidInput => ErrorCode::BR_0084,
            Self::InvalidFormat => ErrorCode::BR_0323,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
