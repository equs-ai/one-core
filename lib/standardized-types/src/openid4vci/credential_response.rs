//! Credential Response
//!
//! Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialResponse {
    pub credentials: Option<Vec<CredentialResponseEntry>>,
    /// Present instead of `credentials` when issuance is deferred.
    pub transaction_id: Option<String>,
    /// Minimum amount of seconds the Wallet needs to wait before the next Deferred Credential
    /// Request.
    pub interval: Option<u64>,
    pub notification_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CredentialResponseEntry {
    pub credential: String,
}
