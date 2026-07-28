use serde::Serialize;
use shared_types::{IdentifierId, InstanceId, ManagedInstanceId, OrganisationId};
use time::OffsetDateTime;

use crate::model::instance::{InstanceRole, InstanceStatus, WalletProviderType};
use crate::service::key::dto::KeyListItemResponseDTO;

#[derive(Debug, Clone)]
pub struct HolderRegisterInstanceRequestDTO {
    pub organisation_id: OrganisationId,
    pub key_type: String,
    pub role: InstanceRole,
    pub provider: InstanceProviderDTO,
}

#[derive(Debug, Clone)]
pub struct InstanceProviderDTO {
    pub r#type: WalletProviderType,
    pub url: String,
}

#[derive(Serialize)]
pub(super) struct NoncePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HolderInstanceResponseDTO {
    pub id: InstanceId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub role: InstanceRole,
    pub provider_instance_id: ManagedInstanceId,
    pub provider_url: String,
    pub provider_type: WalletProviderType,
    pub provider_name: String,
    pub status: InstanceStatus,
    pub authentication_key: Option<KeyListItemResponseDTO>,
    pub user_nonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HolderRegisterInstanceResponseDTO {
    pub id: InstanceId,
    pub status: InstanceStatus,
    pub user_nonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HolderActivateInstanceRequestDTO {
    pub key_type: String,
    pub user_id_token: Option<String>,
    pub user_access_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HolderActivateInstanceResponseDTO {
    pub access_certificate_identifier_id: Option<IdentifierId>,
}
