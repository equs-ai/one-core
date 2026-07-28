use shared_types::{ManagedInstanceAttestedKeyId, ManagedInstanceId};

use crate::model::managed_instance_attested_key::{
    ManagedInstanceAttestedKey, ManagedInstanceAttestedKeyRelations,
    ManagedInstanceAttestedKeyUpsertRequest,
};
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
        relations: &ManagedInstanceAttestedKeyRelations,
    ) -> Result<Option<ManagedInstanceAttestedKey>, DataLayerError>;

    async fn get_by_instance_id(
        &self,
        id: &ManagedInstanceId,
        relations: &ManagedInstanceAttestedKeyRelations,
    ) -> Result<Vec<ManagedInstanceAttestedKey>, DataLayerError>;
}
