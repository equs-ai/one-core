use shared_types::{OrganisationId, ProofId};
use standardized_types::openid4vp::VerifierInfoAttestation;
use standardized_types::openid4vp::dcql::{CredentialQueryId, DcqlQuery};
use thiserror::Error;
use time::Duration;

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::provider::credential_formatter::model::IdentifierDetails;

mod mapper;
pub(crate) mod resolver;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait HolderTrustResolver: Send + Sync {
    /// resolve trust on holder-side during verification
    async fn resolve_verification_trust<'a>(
        &self,
        verifier_details: Option<&'a IdentifierDetails>,
        proof_id: ProofId,
        organisation_id: OrganisationId,
        dcql_query: &DcqlQuery,
        verifier_info: &[VerifierInfoAttestation],
        leeway: Duration,
    ) -> Result<(), HolderTrustResolverError>;
}

#[derive(Debug, Error)]
pub(crate) enum HolderTrustResolverError {
    #[error("Invalid request: `{0}`")]
    InvalidRequest(String),
    #[error("Query not allowed by trust ecosystem: `{0}`")]
    DisallowedQuery(CredentialQueryId),
    #[error("Interaction not allowed - untrusted")]
    Untrusted,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for HolderTrustResolverError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::Untrusted => ErrorCode::BR_0433,
            Self::DisallowedQuery(_) => ErrorCode::BR_0411,
            Self::InvalidRequest(_) => ErrorCode::BR_0085,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
