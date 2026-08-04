use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum EcosystemError {
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for EcosystemError {
    fn error_code(&self) -> ErrorCode {
        match self {
            EcosystemError::Nested(nested) => nested.error_code(),
        }
    }
}
