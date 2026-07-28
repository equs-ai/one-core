use shared_types::{InstanceId, OrganisationId};

use crate::model::instance::{
    CreateInstanceRequest, Instance, InstanceList, InstanceListQuery, InstanceRelations,
    UpdateInstanceRequest,
};
use crate::model::managed_instance::ManagedInstanceRole;
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait InstanceRepository: Send + Sync {
    async fn create(&self, request: CreateInstanceRequest) -> Result<InstanceId, DataLayerError>;

    async fn get(
        &self,
        id: &InstanceId,
        relations: &InstanceRelations,
    ) -> Result<Option<Instance>, DataLayerError>;

    async fn get_by_role(
        &self,
        role: ManagedInstanceRole,
        organisation_id: OrganisationId,
        relations: &InstanceRelations,
    ) -> Result<Option<Instance>, DataLayerError>;

    async fn update(
        &self,
        id: &InstanceId,
        request: UpdateInstanceRequest,
    ) -> Result<(), DataLayerError>;

    async fn list(&self, query: InstanceListQuery) -> Result<InstanceList, DataLayerError>;

    async fn delete(&self, id: &InstanceId) -> Result<(), DataLayerError>;
}
