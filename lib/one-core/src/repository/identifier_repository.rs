use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidId, IdentifierId};

use crate::model::certificate::{
    Certificate, CertificateFilterValue, CertificateListQuery, SortableCertificateColumn,
};
use crate::model::common::SortDirection;
use crate::model::identifier::{
    GetIdentifierList, Identifier, IdentifierListQuery, IdentifierRelations,
    UpdateIdentifierRequest,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListSorting;
use crate::model::relation::AsyncVecLoader;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait IdentifierRepository: Send + Sync {
    async fn create(&self, request: Identifier) -> Result<IdentifierId, DataLayerError>;
    async fn get(
        &self,
        id: IdentifierId,
        relations: &IdentifierRelations,
    ) -> Result<Option<Identifier>, DataLayerError>;
    async fn get_from_did_id(
        &self,
        did_id: DidId,
        relations: &IdentifierRelations,
    ) -> Result<Option<Identifier>, DataLayerError>;
    async fn update(
        &self,
        id: &IdentifierId,
        request: UpdateIdentifierRequest,
    ) -> Result<(), DataLayerError>;
    async fn delete(&self, id: &IdentifierId) -> Result<(), DataLayerError>;
    async fn get_identifier_list(
        &self,
        query_params: IdentifierListQuery,
    ) -> Result<GetIdentifierList, DataLayerError>;
}

pub struct IdentifierCertificatesLoader {
    pub id: IdentifierId,
    pub certificate_repository: Arc<dyn CertificateRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<Certificate> for IdentifierCertificatesLoader {
    async fn load(&self) -> Result<Vec<Certificate>, DataLayerError> {
        let certificates = self
            .certificate_repository
            .list(CertificateListQuery {
                pagination: None,
                sorting: Some(ListSorting {
                    column: SortableCertificateColumn::ExpiryDate,
                    direction: Some(SortDirection::Descending),
                }),
                filtering: Some(CertificateFilterValue::IdentifierId(self.id).condition()),
                include: None,
            })
            .await?
            .values;
        Ok(certificates)
    }
}
