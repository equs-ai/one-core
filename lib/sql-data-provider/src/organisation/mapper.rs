use std::sync::Arc;

use one_core::model::list_filter::ListFilterCondition;
use one_core::model::organisation::{
    Organisation, OrganisationConfiguration, OrganisationFilterValue, SortableOrganisationColumn,
    UpdateOrganisationRequest,
};
use one_core::model::relation::Related;
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::sea_query::{IntoCondition, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr, Set, Unchanged};

use crate::entity::organisation::{self, Configuration};
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_nullability_condition,
};

pub(crate) fn organisation_from_model(
    value: organisation::Model,
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> Organisation {
    Organisation {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        deactivated_at: value.deactivated_at,
        wallet_provider: value.wallet_provider,
        wallet_provider_issuer: value.wallet_provider_issuer,
        parent_organisation: value.parent_organisation.map(|organisation_id| {
            Related::new(organisation_id, organisation_repository.to_owned())
        }),
        verifier_provider: value.verifier_provider,
        verifier_provider_issuer: value.verifier_provider_issuer,
        configuration: value.configuration.map(Into::into).unwrap_or_default(),
    }
}

impl From<Organisation> for organisation::ActiveModel {
    fn from(value: Organisation) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            deactivated_at: Set(value.deactivated_at),
            wallet_provider: Set(value.wallet_provider),
            wallet_provider_issuer: Set(value.wallet_provider_issuer),
            parent_organisation: Set(value
                .parent_organisation
                .map(|parent_organisation| parent_organisation.id())),
            configuration: Set(Some(value.configuration.into())),
            verifier_provider: Set(value.verifier_provider),
            verifier_provider_issuer: Set(value.verifier_provider_issuer),
        }
    }
}

impl From<UpdateOrganisationRequest> for organisation::ActiveModel {
    fn from(value: UpdateOrganisationRequest) -> Self {
        Self {
            id: Set(value.id),
            last_modified: Set(one_core::clock::now_utc()),
            deactivated_at: match value.deactivate {
                Some(true) => Set(Some(one_core::clock::now_utc())),
                Some(false) => Set(None),
                _ => Unchanged(Default::default()),
            },
            wallet_provider: match value.wallet_provider {
                None => Unchanged(Default::default()),
                Some(None) => Set(None),
                Some(Some(value)) => Set(Some(value)),
            },
            wallet_provider_issuer: match value.wallet_provider_issuer {
                None => Unchanged(Default::default()),
                Some(None) => Set(None),
                Some(Some(value)) => Set(Some(value)),
            },
            parent_organisation: match value.parent_organisation {
                None => Unchanged(Default::default()),
                Some(None) => Set(None),
                Some(Some(value)) => Set(Some(value)),
            },
            configuration: match value.configuration {
                None => Unchanged(Default::default()),
                Some(value) => Set(Some(value.into())),
            },
            verifier_provider: match value.verifier_provider {
                None => Unchanged(Default::default()),
                Some(None) => Set(None),
                Some(Some(value)) => Set(Some(value)),
            },
            verifier_provider_issuer: match value.verifier_provider_issuer {
                None => Unchanged(Default::default()),
                Some(None) => Set(None),
                Some(Some(value)) => Set(Some(value)),
            },
            ..Default::default()
        }
    }
}

impl From<Configuration> for OrganisationConfiguration {
    fn from(value: Configuration) -> Self {
        Self {
            trusted_rp_required: value.trusted_rp_required.unwrap_or_default(),
            trusted_issuer_required: value.trusted_issuer_required.unwrap_or_default(),
            trusted_wallet_provider_required: value
                .trusted_wallet_provider_required
                .unwrap_or(true),
        }
    }
}

impl From<OrganisationConfiguration> for Configuration {
    fn from(value: OrganisationConfiguration) -> Self {
        Self {
            trusted_rp_required: Some(value.trusted_rp_required),
            trusted_issuer_required: Some(value.trusted_issuer_required),
            trusted_wallet_provider_required: Some(value.trusted_wallet_provider_required),
        }
    }
}

impl IntoSortingColumn for SortableOrganisationColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => organisation::Column::CreatedDate,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for OrganisationFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::CreatedDate(value) => {
                get_comparison_condition(organisation::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(organisation::Column::LastModified, value)
            }
            Self::HasParentOrganisation(value) => {
                get_nullability_condition(organisation::Column::ParentOrganisation, !value)
            }
            Self::ParentOrganisations(value) => organisation::Column::ParentOrganisation
                .is_in(value)
                .into_condition(),
        }
    }
}
