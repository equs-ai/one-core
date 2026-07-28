use std::sync::Arc;

use one_core::repository::managed_instance_attested_key_repository::ManagedInstanceAttestedKeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod repository;

#[cfg(test)]
mod test;

pub(crate) struct ManagedInstanceProvider {
    pub db: TransactionManagerImpl,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub wallet_instance_attested_key_repository: Arc<dyn ManagedInstanceAttestedKeyRepository>,
}
