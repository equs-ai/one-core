use serde_json::json;
use shared_types::{InstanceId, OrganisationId};

use crate::utils::api_clients::{HttpClient, Response};

pub struct HolderWalletInstancesApi {
    client: HttpClient,
}

#[derive(Debug, Default)]
pub struct TestHolderActivateRequest {
    pub key_type: Option<String>,
    pub user_id_token: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct TestHolderRegisterRequest {
    pub organization_id: Option<OrganisationId>,
    pub role: Option<String>,
    pub wallet_provider_url: Option<String>,
    pub wallet_provider_type: Option<String>,
    pub key_type: Option<String>,
}

impl HolderWalletInstancesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn holder_get_wallet_instance_details(
        &self,
        wallet_unit_id: &InstanceId,
    ) -> Response {
        self.client
            .get(&format!("/api/instance/v1/{}", wallet_unit_id))
            .await
    }

    pub async fn holder_register(&self, request: TestHolderRegisterRequest) -> Response {
        let body = json!(
            {
            "organisationId": request.organization_id,
            "role": request.role.unwrap_or("WALLET".to_string()),
            "provider": {
                "url": request.wallet_provider_url.unwrap_or("http://localhost:3000".to_string()),
                "type": request.wallet_provider_type.unwrap_or("PROCIVIS_ONE".to_string()),
            },
            "keyType": request.key_type.unwrap_or("ECDSA".to_string()),
            }
        );

        self.client.post("/api/instance/v1", body).await
    }

    pub async fn holder_activate(
        &self,
        wallet_unit_id: &InstanceId,
        request: TestHolderActivateRequest,
    ) -> Response {
        let mut body = json!({
            "keyType": request.key_type.unwrap_or("ECDSA".to_string()),
        });
        if let Some(token) = request.user_id_token {
            body["userIdToken"] = json!(token);
        }
        self.client
            .post(&format!("/api/instance/v1/{wallet_unit_id}/activate"), body)
            .await
    }

    pub async fn holder_wallet_instance_status(&self, wallet_unit_id: &InstanceId) -> Response {
        self.client
            .post(&format!("/api/instance/v1/{}/status", wallet_unit_id), None)
            .await
    }
}
