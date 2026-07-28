use async_trait::async_trait;
use one_core::model::managed_instance_attested_key::{
    ManagedInstanceAttestedKey, ManagedInstanceAttestedKeyRelations,
    ManagedInstanceAttestedKeyRevocationInfo, ManagedInstanceAttestedKeyUpsertRequest,
};
use one_core::model::revocation_list::RevocationListRelations;
use one_core::repository::error::DataLayerError;
use one_core::repository::managed_instance_attested_key_repository::ManagedInstanceAttestedKeyRepository;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryTrait, Set,
    Unchanged,
};
use shared_types::{ManagedInstanceAttestedKeyId, ManagedInstanceId};

use crate::entity::{managed_instance_attested_key, revocation_list_entry};
use crate::managed_instance_attested_key::ManagedInstanceAttestedKeyProvider;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[async_trait]
impl ManagedInstanceAttestedKeyRepository for ManagedInstanceAttestedKeyProvider {
    async fn create_attested_key(
        &self,
        request: ManagedInstanceAttestedKey,
    ) -> Result<ManagedInstanceAttestedKeyId, DataLayerError> {
        let model: managed_instance_attested_key::ActiveModel = request.try_into()?;
        let result = model.insert(&self.db).await.map_err(to_data_layer_error)?;
        Ok(result.id)
    }

    async fn update_attested_key(
        &self,
        request: ManagedInstanceAttestedKey,
    ) -> Result<(), DataLayerError> {
        let id = request.id;
        let mut model = managed_instance_attested_key::ActiveModel::try_from(request)?;
        model.id = Unchanged(id);
        model.last_modified = Set(one_core::clock::now_utc());
        managed_instance_attested_key::Entity::update(model)
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn upsert_attested_key(
        &self,
        request: ManagedInstanceAttestedKeyUpsertRequest,
    ) -> Result<ManagedInstanceAttestedKeyId, DataLayerError> {
        let id = request.id;
        let model = managed_instance_attested_key::ActiveModel::try_from(request)?;
        let stmt = managed_instance_attested_key::Entity::insert(model)
            .on_conflict(
                OnConflict::column(managed_instance_attested_key::Column::Id)
                    .update_column(managed_instance_attested_key::Column::LastModified)
                    .update_column(managed_instance_attested_key::Column::ExpirationDate)
                    .update_column(managed_instance_attested_key::Column::PublicKeyJwk)
                    .update_column(managed_instance_attested_key::Column::ManagedInstanceId)
                    .to_owned(),
            )
            .build(self.db.get_database_backend());
        self.db
            .execute(stmt)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(id)
    }

    async fn get_attested_key(
        &self,
        id: &ManagedInstanceAttestedKeyId,
        relations: &ManagedInstanceAttestedKeyRelations,
    ) -> Result<Option<ManagedInstanceAttestedKey>, DataLayerError> {
        let model = managed_instance_attested_key::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(match model {
            Some(model) => Some(self.convert_model(model, relations).await?),
            None => None,
        })
    }

    async fn get_by_instance_id(
        &self,
        id: &ManagedInstanceId,
        relations: &ManagedInstanceAttestedKeyRelations,
    ) -> Result<Vec<ManagedInstanceAttestedKey>, DataLayerError> {
        let models = managed_instance_attested_key::Entity::find()
            .filter(managed_instance_attested_key::Column::ManagedInstanceId.eq(id))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let mut results = vec![];
        for model in models {
            results.push(self.convert_model(model, relations).await?);
        }
        Ok(results)
    }
}

impl ManagedInstanceAttestedKeyProvider {
    async fn convert_model(
        &self,
        model: managed_instance_attested_key::Model,
        relations: &ManagedInstanceAttestedKeyRelations,
    ) -> Result<ManagedInstanceAttestedKey, DataLayerError> {
        let revocation = if let Some(revocation_relations) = &relations.revocation {
            self.get_revocation(&model, revocation_relations).await?
        } else {
            None
        };

        let mut result = ManagedInstanceAttestedKey::try_from(model)?;
        result.revocation = revocation;

        Ok(result)
    }

    async fn get_revocation(
        &self,
        model: &managed_instance_attested_key::Model,
        relations: &RevocationListRelations,
    ) -> Result<Option<ManagedInstanceAttestedKeyRevocationInfo>, DataLayerError> {
        let Some(revocation_list_entry_id) = &model.revocation_list_entry_id else {
            return Ok(None);
        };

        let revocation_list_entry =
            revocation_list_entry::Entity::find_by_id(revocation_list_entry_id)
                .one(&self.db)
                .await
                .map_err(to_data_layer_error)?
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "wallet_unit_attested_key-revocation_list_entry",
                    id: revocation_list_entry_id.to_string(),
                })?;

        let revocation_list_index =
            revocation_list_entry
                .index
                .ok_or(DataLayerError::MissingRequiredRelation {
                    relation: "wallet_unit_attested_key-revocation_list_entry-index",
                    id: revocation_list_entry_id.to_string(),
                })? as _;

        let revocation_list = self
            .revocation_list_repository
            .get_revocation_list(&revocation_list_entry.revocation_list_id, relations)
            .await?
            .ok_or(DataLayerError::MissingRequiredRelation {
                relation: "wallet_unit_attested_key-revocation_list",
                id: revocation_list_entry.revocation_list_id.to_string(),
            })?;

        Ok(Some(ManagedInstanceAttestedKeyRevocationInfo {
            revocation_list,
            revocation_list_index,
        }))
    }
}
