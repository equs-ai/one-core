use one_core::service::managed_instance::dto;
use one_dto_mapper::Into;
use proc_macros::options_not_nullable;
use serde::Deserialize;
use standardized_types::jwk::PublicJwk;
use utoipa::ToSchema;

use crate::endpoint::managed_instance::dto::{InstanceRoleRestEnum, ManagedInstanceOsRestEnum};

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(dto::RegisterWalletUnitRequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegisterInstanceRequestRestDTO {
    pub provider: String,
    pub role: InstanceRoleRestEnum,
    pub os: ManagedInstanceOsRestEnum,
    pub public_key: Option<PublicJwk>,
    pub proof: Option<String>,
}
