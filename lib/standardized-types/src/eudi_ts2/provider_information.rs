//! Clause 2.8.6 — Policy
//!
//! Spec: <https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts2-notification-publication-provider-information.md#286-policy>

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub r#type: PolicyType,
    #[serde(rename = "policyURI")]
    pub policy_uri: Url,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyType {
    #[serde(rename = "http://data.europa.eu/eudi/policy/trust-service-practice-statement")]
    TrustServicePracticeStatement,
    #[serde(rename = "http://data.europa.eu/eudi/policy/terms-and-conditions")]
    TermsAndConditions,
    #[serde(rename = "http://data.europa.eu/eudi/policy/privacy-statement")]
    PrivacyStatement,
    #[serde(rename = "http://data.europa.eu/eudi/policy/privacy-policy")]
    PrivacyPolicy,
    #[serde(rename = "http://data.europa.eu/eudi/policy/registration-policy")]
    RegistrationPolicy,
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn serialize_deserialize_policy() {
        let json = json!({
            "type": "http://data.europa.eu/eudi/policy/privacy-policy",
            "policyURI": "https://example.com/privacy-policy"
        });

        let policy: Policy = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(PolicyType::PrivacyPolicy, policy.r#type);
        assert_eq!(json, serde_json::to_value(&policy).unwrap());
    }

    #[test]
    fn deserialize_all_policy_types() {
        for (uri, expected) in [
            (
                "http://data.europa.eu/eudi/policy/trust-service-practice-statement",
                PolicyType::TrustServicePracticeStatement,
            ),
            (
                "http://data.europa.eu/eudi/policy/terms-and-conditions",
                PolicyType::TermsAndConditions,
            ),
            (
                "http://data.europa.eu/eudi/policy/privacy-statement",
                PolicyType::PrivacyStatement,
            ),
            (
                "http://data.europa.eu/eudi/policy/privacy-policy",
                PolicyType::PrivacyPolicy,
            ),
            (
                "http://data.europa.eu/eudi/policy/registration-policy",
                PolicyType::RegistrationPolicy,
            ),
        ] {
            let parsed: PolicyType = serde_json::from_value(json!(uri)).unwrap();
            assert_eq!(expected, parsed);
        }
    }
}
