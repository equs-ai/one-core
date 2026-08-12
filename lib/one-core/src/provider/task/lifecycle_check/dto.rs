use serde::{Deserialize, Serialize};
use shared_types::CredentialId;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct LifecycleCheckResultDTO {
    pub reactivated_credential_ids: Vec<CredentialId>,
    pub total_reactivation_checks: u64,
    pub expired_credential_ids: Vec<CredentialId>,
    pub total_expiration_checks: u64,
}
