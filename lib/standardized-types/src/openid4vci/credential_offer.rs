//! Credential Offer
//!
//! Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use strum::Display;

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: Grants,
}

/// Grant types the Credential Issuer's Authorization Server is prepared to process for this
/// Credential Offer.
///
/// Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum Grants {
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode(PreAuthorizedCodeGrant),
    #[serde(rename = "authorization_code")]
    AuthorizationCode(AuthorizationCodeGrant),
}

impl Grants {
    pub fn tx_code(&self) -> Option<&TxCode> {
        match self {
            Grants::PreAuthorizedCode(pre_authorized_code) => pre_authorized_code.tx_code.as_ref(),
            Grants::AuthorizationCode(_authorization_code) => None,
        }
    }

    pub fn authorization_server(&self) -> Option<&String> {
        match self {
            Grants::PreAuthorizedCode(pre_authorized_code) => {
                pre_authorized_code.authorization_server.as_ref()
            }
            Grants::AuthorizationCode(authorization_code) => {
                authorization_code.authorization_server.as_ref()
            }
        }
    }
}

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PreAuthorizedCodeGrant {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(default)]
    pub tx_code: Option<TxCode>,
    pub authorization_server: Option<String>,
}

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AuthorizationCodeGrant {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<String>,
}

/// Transaction Code the Wallet has to collect from the End-User and send with the Token Request.
#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TxCode {
    #[serde(default)]
    pub input_mode: TxCodeInputMode,
    #[serde(default)]
    pub length: Option<i64>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Display, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[strum(serialize_all = "snake_case")]
pub enum TxCodeInputMode {
    #[default]
    Numeric,
    Text,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_pre_authorized_code_offer_round_trip() {
        let json = serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["UniversityDegree"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "adhjhdjajkdkhjhdj",
                    "tx_code": { "input_mode": "numeric", "length": 4, "description": "Please enter the PIN" }
                }
            }
        });

        let offer: CredentialOffer = serde_json::from_value(json.clone()).unwrap();
        let Grants::PreAuthorizedCode(ref grant) = offer.grants else {
            panic!("expected pre-authorized code grant");
        };
        assert_eq!("adhjhdjajkdkhjhdj", grant.pre_authorized_code);
        assert_eq!(
            TxCodeInputMode::Numeric,
            offer.grants.tx_code().unwrap().input_mode
        );
        assert_eq!(None, offer.grants.authorization_server());

        assert_eq!(json, serde_json::to_value(&offer).unwrap());
    }

    #[test]
    fn test_authorization_code_offer_round_trip() {
        let json = serde_json::json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["UniversityDegree"],
            "grants": {
                "authorization_code": {
                    "issuer_state": "eyJhbGciOiJSU0Et",
                    "authorization_server": "https://as.example.com"
                }
            }
        });

        let offer: CredentialOffer = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(None, offer.grants.tx_code());
        assert_eq!(
            Some(&"https://as.example.com".to_string()),
            offer.grants.authorization_server()
        );

        assert_eq!(json, serde_json::to_value(&offer).unwrap());
    }

    #[test]
    fn test_tx_code_defaults_to_numeric_input_mode() {
        let tx_code: TxCode = serde_json::from_value(serde_json::json!({ "length": 6 })).unwrap();
        assert_eq!(TxCodeInputMode::Numeric, tx_code.input_mode);
    }

    #[test]
    fn test_tx_code_input_mode_serde_and_display() {
        assert_eq!("numeric", TxCodeInputMode::default().to_string());
        assert_eq!("text", TxCodeInputMode::Text.to_string());
        assert_eq!(
            TxCodeInputMode::Text,
            serde_json::from_value(serde_json::json!("text")).unwrap()
        );
        assert_eq!(
            serde_json::json!("numeric"),
            serde_json::to_value(TxCodeInputMode::Numeric).unwrap()
        );
    }
}
