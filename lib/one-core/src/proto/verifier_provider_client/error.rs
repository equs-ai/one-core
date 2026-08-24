use thiserror::Error;

use one_core_portable::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, Error)]
pub enum VerifierProviderClientError {
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for VerifierProviderClientError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
