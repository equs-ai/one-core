//! OAuth 2.0 Pushed Authorization Requests (PAR)
//!
//! Spec: [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html)

use serde::{Deserialize, Serialize};

/// Response of the pushed authorization request endpoint.
///
/// Spec: [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html#section-2.2)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushedAuthorizationResponse {
    pub request_uri: String,
    /// Lifetime of the `request_uri`, in seconds from the time of the response.
    pub expires_in: i32,
}

/// Authorization Request parameters once the request itself has been pushed: the client sends only
/// the reference returned by the PAR endpoint.
///
/// Spec: [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html#section-4)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushedAuthorizationReference {
    pub request_uri: String,
    pub client_id: String,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_pushed_authorization_reference_form_encoding() {
        assert_eq!(
            "request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A6esc&client_id=wallet",
            serde_urlencoded::to_string(PushedAuthorizationReference {
                request_uri: "urn:ietf:params:oauth:request_uri:6esc".to_string(),
                client_id: "wallet".to_string(),
            })
            .unwrap()
        );
    }
}
