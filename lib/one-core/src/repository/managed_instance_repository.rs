use shared_types::ManagedInstanceId;

use super::error::DataLayerError;
use crate::model::managed_instance::{
    ManagedInstance, ManagedInstanceList, ManagedInstanceListQuery, ManagedInstanceRelations,
    UpdateManagedInstanceRequest,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ManagedInstanceRepository: Send + Sync {
    async fn create(&self, request: ManagedInstance) -> Result<ManagedInstanceId, DataLayerError>;

    async fn get(
        &self,
        id: &ManagedInstanceId,
        relations: &ManagedInstanceRelations,
    ) -> Result<Option<ManagedInstance>, DataLayerError>;

    async fn get_list(
        &self,
        query_params: ManagedInstanceListQuery,
    ) -> Result<ManagedInstanceList, DataLayerError>;

    async fn update(
        &self,
        id: &ManagedInstanceId,
        request: UpdateManagedInstanceRequest,
    ) -> Result<(), DataLayerError>;

    async fn delete(&self, id: &ManagedInstanceId) -> Result<(), DataLayerError>;
}
