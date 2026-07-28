use std::sync::Arc;

use one_core::model::instance::{
    CreateInstanceRequest, Instance, InstanceRelations, WalletProviderType,
};
use one_core::model::key::Key;
use one_core::model::managed_instance::{InstanceStatus, ManagedInstanceRole};
use one_core::model::organisation::Organisation;
use one_core::repository::instance_repository::InstanceRepository;
use shared_types::{InstanceId, ManagedInstanceId};
use uuid::Uuid;

pub struct HolderWalletInstancesDB {
    repository: Arc<dyn InstanceRepository>,
}

#[derive(Default)]
pub struct TestHolderWalletInstanceParams {
    pub status: Option<InstanceStatus>,
    pub provider_type: Option<WalletProviderType>,
    pub provider_name: Option<String>,
    pub provider_url: Option<String>,
    pub provider_wallet_unit_id: Option<ManagedInstanceId>,
    pub role: Option<ManagedInstanceRole>,
}

impl HolderWalletInstancesDB {
    pub fn new(repository: Arc<dyn InstanceRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: Organisation,
        authentication_key: Option<Key>,
        test_holder_wallet_instance: TestHolderWalletInstanceParams,
    ) -> Instance {
        let wallet_instance = CreateInstanceRequest {
            id: Uuid::new_v4().into(),
            status: test_holder_wallet_instance
                .status
                .unwrap_or(InstanceStatus::Active),
            role: test_holder_wallet_instance
                .role
                .unwrap_or(ManagedInstanceRole::Wallet),
            provider_type: test_holder_wallet_instance
                .provider_type
                .unwrap_or(WalletProviderType::ProcivisOne),
            provider_name: test_holder_wallet_instance
                .provider_name
                .unwrap_or("PROCIVIS_ONE".to_string()),
            provider_url: test_holder_wallet_instance
                .provider_url
                .unwrap_or("https://wallet.provider".to_string()),
            organisation,
            authentication_key,
            provider_instance_id: test_holder_wallet_instance
                .provider_wallet_unit_id
                .unwrap_or(Uuid::new_v4().into()),
            nonce: None,
            user_nonce: None,
        };

        let id = self.repository.create(wallet_instance).await.unwrap();

        self.repository
            .get(&id, &InstanceRelations::default())
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn get(
        &self,
        id: impl Into<InstanceId>,
        relations: &InstanceRelations,
    ) -> Option<Instance> {
        self.repository.get(&id.into(), relations).await.unwrap()
    }
}
