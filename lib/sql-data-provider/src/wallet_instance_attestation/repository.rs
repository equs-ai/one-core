use one_core::model::wallet_instance_attestation::{
    UpdateWalletInstanceAttestationRequest, WalletInstanceAttestation,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::wallet_instance_attestation_repository::WalletInstanceAttestationRepository;
use sea_orm::sea_query::IntoCondition;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, Unchanged};
use shared_types::{InstanceId, KeyId, WalletInstanceAttestationId};

use super::mapper::wallet_instance_attestation_from_model;
use crate::entity::wallet_instance_attestation;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::wallet_instance_attestation::WalletInstanceAttestationProvider;

#[async_trait::async_trait]
impl WalletInstanceAttestationRepository for WalletInstanceAttestationProvider {
    async fn create_wallet_instance_attestation(
        &self,
        request: WalletInstanceAttestation,
    ) -> Result<WalletInstanceAttestationId, DataLayerError> {
        let wallet_unit_attestation = wallet_instance_attestation::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(wallet_unit_attestation.id)
    }

    async fn get_wallet_instance_attestation_by_key_id(
        &self,
        key_id: &KeyId,
    ) -> Result<Option<WalletInstanceAttestation>, DataLayerError> {
        Ok(wallet_instance_attestation::Entity::find()
            .filter(
                wallet_instance_attestation::Column::AttestedKeyId
                    .eq(key_id)
                    .into_condition(),
            )
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .map(|model| wallet_instance_attestation_from_model(model, &self.key_repository)))
    }

    async fn get_wallet_instance_attestations_by_holder_wallet_unit(
        &self,
        holder_wallet_unit_id: &InstanceId,
    ) -> Result<Vec<WalletInstanceAttestation>, DataLayerError> {
        let entity_models: Vec<wallet_instance_attestation::Model> =
            wallet_instance_attestation::Entity::find()
                .filter(
                    wallet_instance_attestation::Column::InstanceId
                        .eq(holder_wallet_unit_id)
                        .into_condition(),
                )
                .all(&self.db)
                .await
                .map_err(to_data_layer_error)?;

        if entity_models.is_empty() {
            return Ok(vec![]);
        };

        Ok(entity_models
            .into_iter()
            .map(|model| wallet_instance_attestation_from_model(model, &self.key_repository))
            .collect())
    }

    async fn update_wallet_attestation(
        &self,
        id: &WalletInstanceAttestationId,
        request: UpdateWalletInstanceAttestationRequest,
    ) -> Result<(), DataLayerError> {
        let update_model = wallet_instance_attestation::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(one_core::clock::now_utc()),
            expiration_date: request.expiration_date.map(Set).unwrap_or_default(),
            attestation: request
                .attestation
                .map(String::into_bytes)
                .map(Set)
                .unwrap_or_default(),
            ..Default::default()
        };

        update_model
            .update(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }
}
