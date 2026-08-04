//! Nonce Endpoint
//!
//! Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint>

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct NonceResponse {
    pub c_nonce: String,
}
