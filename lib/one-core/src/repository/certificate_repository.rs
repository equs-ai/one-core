use std::sync::Arc;

use async_trait::async_trait;
use shared_types::CertificateId;

use crate::model::certificate::{
    Certificate, CertificateListQuery, GetCertificateList, UpdateCertificateRequest,
};
use crate::model::relation::AsyncModelLoader;
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait CertificateRepository: Send + Sync {
    async fn create(&self, request: Certificate) -> Result<CertificateId, DataLayerError>;

    /// Returns the certificate by id, including soft-deleted ones — callers that must treat
    /// soft-deleted certificates as not-found (e.g. public-facing lookups) need to check
    /// `deleted_at` explicitly.
    async fn get(&self, id: CertificateId) -> Result<Certificate, DataLayerError>;

    async fn update(
        &self,
        id: &CertificateId,
        request: UpdateCertificateRequest,
    ) -> Result<(), DataLayerError>;

    async fn delete(&self, certificate: &Certificate) -> Result<(), DataLayerError>;

    async fn list(
        &self,
        query_params: CertificateListQuery,
    ) -> Result<GetCertificateList, DataLayerError>;
}

#[async_trait]
impl AsyncModelLoader<Certificate> for Arc<dyn CertificateRepository> {
    async fn load(&self, id: &CertificateId) -> Result<Certificate, DataLayerError> {
        self.get(*id).await
    }
}
