use shared_types::{InstanceId, WalletInstanceAttestationId};

use super::error::DataLayerError;
use crate::model::wallet_instance_attestation::{
    UpdateWalletInstanceAttestationRequest, WalletInstanceAttestation,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletInstanceAttestationRepository: Send + Sync + 'static {
    async fn create_wallet_instance_attestation(
        &self,
        wallet_unit_attestation: WalletInstanceAttestation,
    ) -> Result<WalletInstanceAttestationId, DataLayerError>;

    async fn get_wallet_instance_attestations_by_holder_wallet_unit(
        &self,
        holder_wallet_unit_id: &InstanceId,
    ) -> Result<Vec<WalletInstanceAttestation>, DataLayerError>;

    async fn update_wallet_attestation(
        &self,
        id: &WalletInstanceAttestationId,
        request: UpdateWalletInstanceAttestationRequest,
    ) -> Result<(), DataLayerError>;
}
