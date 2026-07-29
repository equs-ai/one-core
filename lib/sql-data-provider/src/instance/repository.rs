use async_trait::async_trait;
use futures::FutureExt;
use one_core::model::instance::{
    Instance, InstanceList, InstanceListQuery, InstanceRelations, InstanceRole,
    UpdateInstanceRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::instance_repository::InstanceRepository;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set, Unchanged,
};
use shared_types::{InstanceId, OrganisationId};

use crate::common::list_query_with_custom_model;
use crate::entity::instance;
use crate::instance::InstanceProvider;
use crate::instance::mapper::instance_from_model;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[async_trait]
impl InstanceRepository for InstanceProvider {
    async fn create(&self, request: Instance) -> Result<InstanceId, DataLayerError> {
        let model = instance::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(model.id)
    }

    async fn get(
        &self,
        id: &InstanceId,
        relations: &InstanceRelations,
    ) -> Result<Option<Instance>, DataLayerError> {
        let model = instance::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        let Some(model) = model else { return Ok(None) };

        Ok(Some(self.fill_relations(model, relations).await?))
    }

    async fn get_by_role(
        &self,
        role: InstanceRole,
        organisation_id: OrganisationId,
        relations: &InstanceRelations,
    ) -> Result<Option<Instance>, DataLayerError> {
        let model = instance::Entity::find()
            .filter(instance::Column::Role.eq(instance::InstanceRole::from(role)))
            .filter(instance::Column::OrganisationId.eq(organisation_id))
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        let Some(model) = model else { return Ok(None) };

        Ok(Some(self.fill_relations(model, relations).await?))
    }

    async fn update(
        &self,
        id: &InstanceId,
        request: UpdateInstanceRequest,
    ) -> Result<(), DataLayerError> {
        let action = async {
            let update_model = instance::ActiveModel {
                id: Unchanged(*id),
                last_modified: Set(one_core::clock::now_utc()),
                status: request
                    .status
                    .map(|status| Set(status.into()))
                    .unwrap_or_default(),
                authentication_key_id: request
                    .authentication_key_id
                    .map(|key_id| Set(Some(key_id)))
                    .unwrap_or_default(),
                ..Default::default()
            };
            update_model
                .update(&self.db)
                .await
                .map_err(to_update_data_layer_error)?;

            let Some(attestations) = request.wallet_unit_attestations else {
                return Ok(());
            };

            for attestation in attestations {
                let result = self
                    .wallet_unit_attestation_repository
                    .create_wallet_instance_attestation(attestation.clone())
                    .await;
                if let Err(err) = result {
                    match err {
                        DataLayerError::AlreadyExists => {
                            let attestation_id = attestation.id;
                            self.wallet_unit_attestation_repository
                                .update_wallet_attestation(&attestation_id, attestation.into())
                                .await?
                        }
                        err => return Err(err),
                    }
                }
            }
            Ok(())
        }
        .boxed();
        self.db.tx(action).await?
    }

    async fn list(&self, query_params: InstanceListQuery) -> Result<InstanceList, DataLayerError> {
        let query = instance::Entity::find()
            .with_list_query(&query_params)
            .order_by_desc(instance::Column::CreatedDate)
            .order_by_desc(instance::Column::Id);

        list_query_with_custom_model(query, query_params, &self.db, |m| {
            Ok(instance_from_model(m, &self.organisation_repository))
        })
        .await
    }

    async fn delete(&self, id: &InstanceId) -> Result<(), DataLayerError> {
        instance::Entity::delete_by_id(*id)
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }
}

impl InstanceProvider {
    async fn fill_relations(
        &self,
        model: instance::Model,
        relations: &InstanceRelations,
    ) -> Result<Instance, DataLayerError> {
        let id = model.id;
        let auth_key_id = model.authentication_key_id;
        let mut holder_wallet_unit = instance_from_model(model, &self.organisation_repository);
        if let (Some(_key_relations), Some(auth_key_id)) =
            (&relations.authentication_key, &auth_key_id)
        {
            let key = self.key_repository.get_key(auth_key_id).await?.ok_or(
                DataLayerError::MissingRequiredRelation {
                    relation: "holder_wallet_unit-authentication_key",
                    id: auth_key_id.to_string(),
                },
            )?;
            holder_wallet_unit.authentication_key = Some(key)
        }

        if let Some(_wallet_unit_attestation_relations) = &relations.wallet_unit_attestations {
            let attestations = self
                .wallet_unit_attestation_repository
                .get_wallet_instance_attestations_by_holder_wallet_unit(&id)
                .await?;
            holder_wallet_unit.wallet_unit_attestations = Some(attestations)
        }

        Ok(holder_wallet_unit)
    }
}
