use one_dto_mapper::convert_inner;
use shared_types::KeyId;

use super::dto::HolderInstanceResponseDTO;
use super::service::ProviderMetadata;
use crate::model::instance::Instance;
use crate::model::key::Key;
use crate::model::managed_instance::InstanceStatus;
use crate::model::organisation::Organisation;
use crate::proto::trust_collection::dto::RemoteTrustCollectionInfoDTO;
use crate::provider::key_storage::model::StorageGeneratedKey;
use crate::service::managed_instance::dto::{
    ProviderTrustCollectionDTO, WalletProviderMetadataResponseDTO,
};
use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;

impl From<WalletProviderMetadataResponseDTO> for ProviderMetadata {
    fn from(value: WalletProviderMetadataResponseDTO) -> Self {
        Self {
            name: value.name,
            attestation: value.wallet_unit_attestation,
            user_authentication: value.user_authentication,
            trust_collections: convert_inner(value.trust_collections),
            credential_schemas: vec![],
            proof_schemas: vec![],
            access_certificate_provisioning_enabled: false,
        }
    }
}

impl From<VerifierProviderMetadataResponseDTO> for ProviderMetadata {
    fn from(value: VerifierProviderMetadataResponseDTO) -> Self {
        Self {
            name: value.name,
            attestation: value.verifier_app_attestation,
            user_authentication: value.user_authentication,
            trust_collections: convert_inner(value.trust_collections),
            credential_schemas: value.credential_schemas.unwrap_or_default(),
            proof_schemas: value.proof_schemas.unwrap_or_default(),
            access_certificate_provisioning_enabled: value
                .feature_flags
                .access_certificate_provisioning_enabled,
        }
    }
}

pub(super) fn key_from_generated_key(
    key_id: KeyId,
    key_storage_id: &str,
    key_type: &str,
    organisation: Organisation,
    generated_key: StorageGeneratedKey,
) -> Key {
    let now = crate::clock::now_utc();

    Key {
        id: key_id,
        created_date: now,
        last_modified: now,
        public_key: generated_key.public_key,
        name: format!("Wallet unit key {key_id}"),
        key_reference: generated_key.key_reference,
        storage_type: key_storage_id.to_string(),
        key_type: key_type.to_string(),
        organisation: organisation.into(),
    }
}

impl From<Instance> for HolderInstanceResponseDTO {
    fn from(value: Instance) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            role: value.role,
            provider_instance_id: value.provider_instance_id,
            provider_url: value.provider_url,
            provider_type: value.provider_type,
            provider_name: value.provider_name,
            status: value.status,
            authentication_key: convert_inner(value.authentication_key),
            user_nonce: (value.status == InstanceStatus::Pending)
                .then_some(value.user_nonce)
                .flatten(),
        }
    }
}

impl From<ProviderTrustCollectionDTO> for RemoteTrustCollectionInfoDTO {
    fn from(value: ProviderTrustCollectionDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}
