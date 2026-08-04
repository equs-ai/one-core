use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(thiserror::Error, Debug)]
pub enum HistoryServiceError {
    #[error("Invalid history source")]
    InvalidSource,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HistoryServiceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidSource => ErrorCode::BR_0315,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
