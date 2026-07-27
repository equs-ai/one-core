use std::sync::Arc;

use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::trust_list_publication_repository::TrustListPublicationRepository;

use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;

mod entities;
#[cfg(test)]
mod test;

pub(crate) struct TrustEntryProvider {
    pub db: TransactionManagerImpl,
    pub trust_list_publication_repository: Arc<dyn TrustListPublicationRepository>,
    pub identifier_repository: Arc<dyn IdentifierRepository>,
    pub did_repository: Arc<dyn DidRepository>,
    pub key_repository: Arc<dyn KeyRepository>,
    pub certificate_repository: Arc<dyn CertificateRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}
