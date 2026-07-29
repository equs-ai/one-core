use one_core::service::organisation::dto::UpsertOrganisationRequestDTO;
use shared_types::{IdentifierId, OrganisationId};

use super::dto::{
    CreateOrganisationResponseRestDTO, UpsertOrganisationRequestRestDTO,
    UpsertProviderRequestRestDTO,
};

impl From<OrganisationId> for CreateOrganisationResponseRestDTO {
    fn from(value: OrganisationId) -> Self {
        Self { id: value }
    }
}

/// Unpacks a nested, double-optional provider update into the flat double-optional
/// name/issuer pair the service layer expects: omitted key -> no change to either
/// sub-field; `null` -> clear both; an object -> set name/issuer independently (each
/// `None` inside the object clears just that one).
fn unpack_provider(
    provider: Option<Option<UpsertProviderRequestRestDTO>>,
) -> (Option<Option<String>>, Option<Option<IdentifierId>>) {
    match provider {
        None => (None, None),
        Some(None) => (Some(None), Some(None)),
        Some(Some(provider)) => (Some(provider.name), Some(provider.issuer)),
    }
}

pub(crate) fn upsert_request_from_request(
    id: OrganisationId,
    request: UpsertOrganisationRequestRestDTO,
) -> UpsertOrganisationRequestDTO {
    let (wallet_provider, wallet_provider_issuer) = unpack_provider(request.wallet_provider);
    let (verifier_provider, verifier_provider_issuer) = unpack_provider(request.verifier_provider);

    UpsertOrganisationRequestDTO {
        id,
        deactivate: request.deactivate,
        wallet_provider,
        wallet_provider_issuer,
        verifier_provider,
        verifier_provider_issuer,
        configuration: request.configuration.map(Into::into),
        trust_collections: request.trust_collections,
        parent_organisation: request.parent_organisation,
    }
}
