use shared_types::OrganisationId;
use thiserror::Error;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum KeyServiceError {
    #[error("Organisation `{0}` is deactivated")]
    OrganisationDeactivated(OrganisationId),
    #[error("Key already exists")]
    KeyAlreadyExists,
    #[error("Invalid key storage: `{0}`")]
    InvalidKeyStorage(String),
    #[error("Invalid key algorithm: `{0}`")]
    InvalidKeyAlgorithm(String),
    #[error("Unsupported key type: `{key_type}`")]
    UnsupportedKeyType { key_type: KeyAlgorithmType },
    #[error("Mapping error: {0}")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for KeyServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::OrganisationDeactivated(_) => ErrorCode::BR_0241,
            Self::KeyAlreadyExists => ErrorCode::BR_0066,
            Self::InvalidKeyStorage(_) => ErrorCode::BR_0041,
            Self::InvalidKeyAlgorithm(_) => ErrorCode::BR_0043,
            Self::UnsupportedKeyType { .. } => ErrorCode::BR_0039,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
