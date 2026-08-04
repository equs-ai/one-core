//! Authorization Endpoint
//!
//! Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-endpoint>

use serde::{Deserialize, Serialize};

/// Entry of the `authorization_details` Authorization Request parameter, defined by
/// [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) and profiled by OpenID4VCI with the
/// `openid_credential` type.
///
/// Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-authorization-details>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDetail {
    pub r#type: String,
    pub credential_configuration_id: String,
}
