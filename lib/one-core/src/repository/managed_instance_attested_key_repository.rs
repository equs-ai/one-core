use std::sync::Arc;

use shared_types::{ManagedInstanceAttestedKeyId, ManagedInstanceId};

use crate::model::managed_instance_attested_key::{
    ManagedInstanceAttestedKey, ManagedInstanceAttestedKeyUpsertRequest,
};
use crate::model::relation::{AsyncModelLoader, AsyncVecLoader};
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ManagedInstanceAttestedKeyRepository: Send + Sync {
    async fn create_attested_key(
        &self,
        request: ManagedInstanceAttestedKey,
    ) -> Result<ManagedInstanceAttestedKeyId, DataLayerError>;

    async fn update_attested_key(
        &self,
        request: ManagedInstanceAttestedKey,
    ) -> Result<(), DataLayerError>;

    async fn upsert_attested_key(
        &self,
        request: ManagedInstanceAttestedKeyUpsertRequest,
    ) -> Result<ManagedInstanceAttestedKeyId, DataLayerError>;

    async fn get_attested_key(
        &self,
        id: &ManagedInstanceAttestedKeyId,
    ) -> Result<Option<ManagedInstanceAttestedKey>, DataLayerError>;

    async fn get_by_instance_id(
        &self,
        id: &ManagedInstanceId,
    ) -> Result<Vec<ManagedInstanceAttestedKey>, DataLayerError>;
}

#[async_trait::async_trait]
impl AsyncModelLoader<ManagedInstanceAttestedKey>
    for Arc<dyn ManagedInstanceAttestedKeyRepository>
{
    async fn load(
        &self,
        id: &ManagedInstanceAttestedKeyId,
    ) -> Result<ManagedInstanceAttestedKey, DataLayerError> {
        self.get_attested_key(id)
            .await?
            .ok_or_else(|| DataLayerError::MissingRequiredRelation {
                relation: "managed-instance-attested-key",
                id: id.to_string(),
            })
    }
}

pub struct ManagedInstanceAttestedKeysLoader {
    pub id: ManagedInstanceId,
    pub managed_instance_repository: Arc<dyn ManagedInstanceAttestedKeyRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<ManagedInstanceAttestedKey> for ManagedInstanceAttestedKeysLoader {
    async fn load(&self) -> Result<Vec<ManagedInstanceAttestedKey>, DataLayerError> {
        self.managed_instance_repository
            .get_by_instance_id(&self.id)
            .await
    }
}
