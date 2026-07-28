use autometrics::autometrics;
use futures::FutureExt;
use futures::future::join_all;
use one_core::model::managed_instance::{
    ManagedInstance, ManagedInstanceList, ManagedInstanceListQuery, ManagedInstanceRelations,
    UpdateManagedInstanceRequest,
};
use one_core::proto::transaction_manager::TransactionManager;
use one_core::repository::error::DataLayerError;
use one_core::repository::managed_instance_repository::ManagedInstanceRepository;
use one_dto_mapper::try_convert_inner;
use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, QueryOrder, Set, Unchanged};
use shared_types::ManagedInstanceId;

use super::ManagedInstanceProvider;
use crate::common::calculate_pages_count;
use crate::entity::managed_instance;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl ManagedInstanceRepository for ManagedInstanceProvider {
    async fn create(&self, request: ManagedInstance) -> Result<ManagedInstanceId, DataLayerError> {
        let attested_keys = request.attested_keys.clone();
        self.db
            .tx(async {
                let wallet_unit = managed_instance::ActiveModel::try_from(request)?
                    .insert(&self.db)
                    .await
                    .map_err(to_data_layer_error)?;
                if let Some(attested_keys) = attested_keys {
                    for key in attested_keys {
                        self.wallet_instance_attested_key_repository
                            .create_attested_key(key.clone())
                            .await?;
                    }
                }
                Ok(wallet_unit.id)
            }
            .boxed())
            .await?
    }

    async fn get(
        &self,
        id: &ManagedInstanceId,
        relations: &ManagedInstanceRelations,
    ) -> Result<Option<ManagedInstance>, DataLayerError> {
        let Some(wallet_unit) = managed_instance::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
        else {
            return Ok(None);
        };
        let organisation_id = wallet_unit.organisation_id;
        let mut wallet_unit = ManagedInstance::try_from(wallet_unit)?;

        if let Some(_org_relations) = &relations.organisation {
            let org = self
                .organisation_repository
                .get_organisation(&organisation_id)
                .await?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "wallet_unit-organisation",
                    id: organisation_id.to_string(),
                })?;
            wallet_unit.organisation = Some(org);
        }

        if let Some(attested_key_relations) = &relations.attested_keys {
            let attested_keys = self
                .wallet_instance_attested_key_repository
                .get_by_instance_id(&wallet_unit.id, attested_key_relations)
                .await?;
            wallet_unit.attested_keys = Some(attested_keys);
        }

        Ok(Some(wallet_unit))
    }

    async fn get_list(
        &self,
        query_params: ManagedInstanceListQuery,
    ) -> Result<ManagedInstanceList, DataLayerError> {
        let mut query = managed_instance::Entity::find();

        query = query.with_list_query(&query_params);

        if query_params.sorting.is_some() || query_params.pagination.is_some() {
            // fallback ordering
            query = query
                .order_by_desc(managed_instance::Column::CreatedDate)
                .order_by_desc(managed_instance::Column::Id);
        }

        let wallet_units = query.all(&self.db).await.map_err(to_data_layer_error)?;

        let total_items = managed_instance::Entity::find()
            .with_list_query(&query_params)
            .count(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let page_size = query_params
            .pagination
            .as_ref()
            .map(|p| p.page_size as u64)
            .unwrap_or(total_items);

        let total_pages = calculate_pages_count(total_items, page_size);

        Ok(ManagedInstanceList {
            values: try_convert_inner(wallet_units)?,
            total_pages,
            total_items,
        })
    }

    async fn update(
        &self,
        id: &ManagedInstanceId,
        request: UpdateManagedInstanceRequest,
    ) -> Result<(), DataLayerError> {
        let authentication_key_jwk = request
            .authentication_key_jwk
            .map(|pk| serde_json::to_string(&pk))
            .transpose()
            .map_err(|_| DataLayerError::MappingError)?;
        let update_model = managed_instance::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(one_core::clock::now_utc()),
            status: request
                .status
                .map(|status| Set(status.into()))
                .unwrap_or_default(),
            last_issuance: request
                .last_issuance
                .map(|last_issuance| Set(last_issuance.into()))
                .unwrap_or_default(),
            authentication_key_jwk: authentication_key_jwk
                .map(|key| Set(Some(key)))
                .unwrap_or_default(),
            user_sub: request
                .user_sub
                .map(|sub| Set(Some(sub)))
                .unwrap_or_default(),
            verifier_csr: request.verifier_csr.map(Set).unwrap_or_default(),
            verifier_signature_ids: request
                .verifier_signature_ids
                .map(|ids| Set(Some(ids.into())))
                .unwrap_or_default(),
            ..Default::default()
        };

        self.db
            .transaction(
                async {
                    update_model
                        .update(&self.db)
                        .await
                        .map_err(to_update_data_layer_error)?;

                    if let Some(attested_keys) = request.attested_keys {
                        // Currently deletion is not supported. New entries are inserted, or updated if already
                        // existing.
                        join_all(attested_keys.into_iter().map(|key| {
                            self.wallet_instance_attested_key_repository
                                .upsert_attested_key(key.into())
                        }))
                        .await
                        .into_iter()
                        .collect::<Result<Vec<_>, _>>()?;
                    }
                    Ok(())
                }
                .boxed(),
            )
            .await?
            .map_err(|err| DataLayerError::TransactionError(err.to_string()))?;
        Ok(())
    }

    async fn delete(&self, id: &ManagedInstanceId) -> Result<(), DataLayerError> {
        managed_instance::Entity::delete_by_id(id)
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }
}
