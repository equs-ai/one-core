//! OAuth 2.0 Attestation-Based Client Authentication
//!
//! Spec: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07>
//!
//! The corresponding token endpoint authentication method is
//! [`super::dynamic_client_registration::TokenEndpointAuthMethod::AttestJwtClientAuth`].

use serde::{Deserialize, Serialize};

/// Response of the challenge endpoint.
///
/// Spec: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-8>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub attestation_challenge: String,
}
