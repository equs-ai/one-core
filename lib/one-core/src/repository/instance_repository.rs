use std::sync::Arc;

use shared_types::{InstanceId, OrganisationId};

use crate::model::instance::{
    Instance, InstanceList, InstanceListQuery, InstanceRole, UpdateInstanceRequest,
};
use crate::model::relation::AsyncVecLoader;
use crate::model::wallet_instance_attestation::WalletInstanceAttestation;
use crate::repository::WalletInstanceAttestationRepository;
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait InstanceRepository: Send + Sync {
    async fn create(&self, request: Instance) -> Result<InstanceId, DataLayerError>;

    async fn get(&self, id: &InstanceId) -> Result<Instance, DataLayerError>;

    async fn get_by_role(
        &self,
        role: InstanceRole,
        organisation_id: OrganisationId,
    ) -> Result<Option<Instance>, DataLayerError>;

    async fn update(
        &self,
        id: &InstanceId,
        request: UpdateInstanceRequest,
    ) -> Result<(), DataLayerError>;

    async fn list(&self, query: InstanceListQuery) -> Result<InstanceList, DataLayerError>;

    async fn delete(&self, id: &InstanceId) -> Result<(), DataLayerError>;
}

pub struct InstanceWalletInstanceAttestationsLoader {
    pub id: InstanceId,
    pub wallet_instance_attestation_repository: Arc<dyn WalletInstanceAttestationRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<WalletInstanceAttestation> for InstanceWalletInstanceAttestationsLoader {
    async fn load(&self) -> Result<Vec<WalletInstanceAttestation>, DataLayerError> {
        self.wallet_instance_attestation_repository
            .get_wallet_instance_attestations_by_holder_wallet_unit(&self.id)
            .await
    }
}
