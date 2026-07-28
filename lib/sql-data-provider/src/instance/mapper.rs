use std::sync::Arc;

use entity::instance;
use one_core::model::instance::{
    CreateInstanceRequest, Instance, InstanceFilterValue, SortableInstanceColumn,
    WalletProviderType,
};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::Related;
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, Condition, Set};

use crate::entity;
use crate::entity::instance::{ActiveModel, Model};
use crate::list_query_generic::{IntoFilterCondition, IntoSortingColumn, get_equals_condition};

pub(crate) fn instance_from_model(
    value: Model,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> Instance {
    Instance {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        provider_type: WalletProviderType::from(value.provider_type),
        provider_name: value.provider_name,
        provider_url: value.provider_url,
        provider_instance_id: value.provider_instance_id,
        status: value.status.into(),
        role: value.role.into(),
        nonce: value.nonce,
        user_nonce: value.user_nonce,
        organisation: Related::new(value.organisation_id, organisation_repository.clone()),
        authentication_key: None,
        wallet_unit_attestations: None,
    }
}

impl From<CreateInstanceRequest> for ActiveModel {
    fn from(value: CreateInstanceRequest) -> Self {
        let now = one_core::clock::now_utc();
        Self {
            id: Set(value.id),
            created_date: Set(now),
            last_modified: Set(now),
            status: Set(value.status.into()),
            role: Set(value.role.into()),
            provider_name: Set(value.provider_name),
            provider_type: Set(value.provider_type.into()),
            provider_url: Set(value.provider_url),
            provider_instance_id: Set(value.provider_instance_id),
            organisation_id: Set(value.organisation.id),
            authentication_key_id: Set(value.authentication_key.map(|key| key.id)),
            nonce: Set(value.nonce),
            user_nonce: Set(value.user_nonce),
        }
    }
}

impl IntoSortingColumn for SortableInstanceColumn {
    fn get_column(&self) -> SimpleExpr {
        match *self {}
    }
}

impl IntoFilterCondition for InstanceFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {
            Self::OrganisationIds(organisation_ids) => instance::Column::OrganisationId
                .is_in(organisation_ids)
                .into_condition(),
            Self::Role(role) => {
                get_equals_condition(instance::Column::Role, instance::InstanceRole::from(role))
            }
            Self::Status(status) => get_equals_condition(
                instance::Column::Status,
                instance::InstanceStatus::from(status),
            ),
        }
    }
}
