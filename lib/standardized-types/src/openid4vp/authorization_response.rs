//! Authorization Response
//!
//! Spec https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Unencrypted Authorization Response, keyed by DCQL credential query id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpTokenResponse {
    pub vp_token: HashMap<String, Vec<String>>,
}

/// Encrypted Authorization Response, where the response parameters are conveyed as a JWE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedResponse {
    pub response: String,
}

/// Response of the Verifier to an Authorization Response sent to the `response_uri`.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DirectPostResponse {
    pub redirect_uri: Option<String>,
}
