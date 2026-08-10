use std::sync::Arc;

use standardized_types::openid4vp::dcql::CredentialQueryId;
use thiserror::Error;

use crate::config::core_config::IdentifierType;
use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::proto::session_provider::SessionProvider;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::repository::history_repository::HistoryRepository;

mod mapper;
mod resolver;

#[derive(Debug, Error)]
pub(crate) enum HolderProofError {
    #[error("Missing registry URL")]
    MissingRegistryUrl,
    #[error("Query not allowed: `{0}`")]
    DisallowedQuery(CredentialQueryId),
    #[error("Missing identifier")]
    MissingIdentifier,
    #[error("Invalid identifier type: {0}")]
    InvalidIdentifierType(IdentifierType),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderProofError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingRegistryUrl | Self::MissingIdentifier | Self::InvalidIdentifierType(_) => {
                ErrorCode::BR_0477
            }
            Self::DisallowedQuery(_) => ErrorCode::BR_0411,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

pub(crate) struct HolderProofResolver {
    history_repository: Arc<dyn HistoryRepository>,
    wrp_validator: Arc<dyn WRPValidator>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
}
