use shared_types::CredentialId;
use uuid::Uuid;

use super::OID4VCIFinal1_0Service;
use super::error::OID4VCIFinal1_0ServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    TrustResolutionMetadata, TrustResolutionResult,
};
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::model::PublicKeySource;

impl OID4VCIFinal1_0Service {
    /// Issuer-side wallet provider trust resolution: checks whether the wallet
    /// attestation (WIA/WUA) is signed by a wallet provider trusted in the
    /// issuer organisation and records a `TrustResolved` history event.
    pub(super) async fn resolve_wallet_provider_trust(
        &self,
        key_source: PublicKeySource<'_>,
        organisation: &Organisation,
        credential_id: CredentialId,
        credential_schema_name: &str,
    ) -> Result<TrustResolutionResult, OID4VCIFinal1_0ServiceError> {
        let result = match self
            .wrp_validator
            .validate_wallet_provider(key_source, organisation.id)
            .await
        {
            Ok(Some(_trust_entity)) => TrustResolutionResult::Trusted,
            // check completed, wallet provider absent from all subscribed trust lists
            Ok(None) => TrustResolutionResult::Untrusted,
            // check could not be performed
            Err(err) => {
                tracing::info!(%err, "Wallet provider trust could not be resolved");
                TrustResolutionResult::Unknown
            }
        };

        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                action: HistoryAction::TrustResolved,
                name: credential_schema_name.to_owned(),
                target: None,
                source: HistorySource::Core,
                entity_id: Some(credential_id.into()),
                entity_type: HistoryEntityType::Credential,
                metadata: Some(HistoryMetadata::TrustResolution(TrustResolutionMetadata {
                    result,
                })),
                metadata_blob_id: None,
                organisation_id: Some(organisation.id),
                user: None,
            })
            .await
            .error_while("storing history")?;

        Ok(result)
    }
}
