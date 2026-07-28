use one_core::model::instance::WalletProviderType;
use one_core::service::error::ServiceError;
use one_core::service::instance::dto;
use one_dto_mapper::{From, Into, TryFrom, TryInto, try_convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{IdentifierId, InstanceId, ManagedInstanceId, OrganisationId};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::key::dto::KeyListItemResponseRestDTO;
use crate::endpoint::managed_instance::dto::{InstanceRoleRestEnum, InstanceStatusRestEnum};
use crate::mapper::MapperError;
use crate::serialize::front_time;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T = dto::HolderRegisterInstanceRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegisterManagedInstanceRequestRestDTO {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Role of the instance being registered.
    #[try_into(infallible)]
    pub role: InstanceRoleRestEnum,
    /// Provider details.
    #[try_into(infallible)]
    pub provider: InstanceProviderRestDTO,
    /// Choose a key type and the system will generate a key to use for
    /// registration.
    #[try_into(infallible)]
    pub key_type: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::HolderRegisterInstanceResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterInstanceResponseRestDTO {
    pub id: InstanceId,
    pub status: InstanceStatusRestEnum,
    pub user_nonce: Option<String>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into, From)]
#[into(dto::InstanceProviderDTO)]
#[from(dto::InstanceProviderDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstanceProviderRestDTO {
    /// Full URL for the GET provider metadata endpoint, for example:
    /// <domain>/ssi/wallet-provider/v1/<provider> or
    /// <domain>/ssi/verifier-provider/v1/<provider>
    pub url: String,
    /// Choose the provider implementation.
    pub r#type: WalletProviderTypeRestEnum,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From, Into)]
#[from(WalletProviderType)]
#[into(WalletProviderType)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WalletProviderTypeRestEnum {
    ProcivisOne,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, TryFrom)]
#[try_from(T = dto::HolderInstanceResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstanceDetailRestDTO {
    #[try_from(infallible)]
    pub id: InstanceId,
    #[serde(serialize_with = "front_time")]
    #[try_from(infallible)]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[try_from(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub role: InstanceRoleRestEnum,
    #[try_from(infallible)]
    pub provider_instance_id: ManagedInstanceId,
    #[try_from(infallible)]
    pub provider_url: String,
    #[try_from(infallible)]
    pub provider_type: WalletProviderTypeRestEnum,
    #[try_from(infallible)]
    pub provider_name: String,
    #[try_from(infallible)]
    pub status: InstanceStatusRestEnum,
    #[try_from(with_fn = try_convert_inner)]
    pub authentication_key: Option<KeyListItemResponseRestDTO>,
    #[try_from(infallible)]
    pub user_nonce: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::HolderActivateInstanceRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActivateInstanceRequestRestDTO {
    /// Key type for the new authentication key generated during activation.
    pub key_type: String,
    /// Identity token obtained from the identity provider after user authentication.
    pub user_id_token: Option<String>,
    /// Access token obtained from the identity provider after user authentication.
    pub user_access_token: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(dto::HolderActivateInstanceResponseDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActivateInstanceResponseRestDTO {
    /// IdentifierId with provisioned access certificate (if any)
    pub access_certificate_identifier_id: Option<IdentifierId>,
}
