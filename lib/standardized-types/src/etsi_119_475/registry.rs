//! Annex B — data model published by the wallet-relying party registry.
//!
//! Spec: <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>

use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as};
use url::Url;

use super::Credential;
use crate::etsi_119_602;
use crate::eudi_ts2::Policy;

/// B.2.1
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletRelyingParty {
    pub trade_name: Option<String>,
    #[serde(rename = "supportURI")]
    pub support_uri: Vec<Url>,
    pub srv_description: Vec<MultiLangString>,
    #[serde(default)]
    pub intended_use: Vec<IntendedUse>,
    #[serde(rename = "isPSB")]
    pub is_psb: bool,
    pub entitlement: Vec<String>,
    #[serde(default)]
    pub provides_attestations: Vec<Credential>,
    pub supervisory_authority: LegalEntity,
    #[serde(rename = "registryURI")]
    pub registry_uri: Url,
    pub uses_intermediary: Option<Vec<WalletRelyingParty>>,
}

/// B.2.2
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LegalEntity {
    pub legal_person: Option<LegalPerson>,
    pub natural_person: Option<NaturalPerson>,
    #[serde(default)]
    pub identifier: Vec<Identifier>,
    #[serde(default)]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub postal_address: Option<Vec<String>>,
    pub country: String,
    #[serde(default)]
    pub email: Vec<String>,
    #[serde(default)]
    pub phone: Vec<String>,
    #[serde(default, rename = "infoURI")]
    pub info_uri: Vec<String>,
}

/// B.2.3
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LegalPerson {
    pub legal_name: Vec<String>,
    #[serde(default)]
    pub established_by_law: Vec<Law>,
}

/// B.2.4
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NaturalPerson {
    pub given_name: String,
    pub family_name: String,
    pub date_of_birth: Option<String>,
    pub place_of_birth: Option<String>,
}

/// B.2.5
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Identifier {
    pub r#type: String,
    pub identifier: String,
}

/// B.2.6, a language-tagged string as used by the registry data model.
///
/// The text is carried in `content` here, whereas the WRPRC payload of clause
/// 5.2.4 names the same thing `value`, see [`super::MultiLangString`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MultiLangString {
    /// BCP 47 language tag
    pub lang: String,
    pub content: String,
}

impl From<MultiLangString> for etsi_119_602::json::MultiLangString {
    fn from(value: MultiLangString) -> Self {
        Self {
            lang: value.lang,
            value: value.content,
        }
    }
}

/// B.2.7
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IntendedUse {
    pub purpose: Vec<MultiLangString>,
    pub privacy_policy: Vec<Policy>,

    // timestamp parsing workaround, in ETSI standard these should be ISO 8601-1 encoded
    pub created_at: String,
    pub revoked_at: Option<String>,
    pub credential: Vec<Credential>,
    pub intended_use_identifier: String,
}

/// B.2.11
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Law {
    // workaround, should be mandatory
    pub lang: Option<String>,
    pub legal_basis: String,
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn deserialize_wallet_relying_party() {
        let json = json!({
            "tradeName": "Example Company",
            "supportURI": ["https://example.com/support"],
            "srvDescription": [{ "lang": "en-US", "content": "Awesome Service" }],
            "isPSB": false,
            "entitlement": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
            "supervisoryAuthority": {
                "legalPerson": { "legalName": ["Data Protection Authority"] },
                "naturalPerson": null,
                "country": "DE",
                "email": ["supervisory@dpa.com"]
            },
            "registryURI": "https://registrar.com",
            "usesIntermediary": null
        });

        let wrp: WalletRelyingParty = serde_json::from_value(json).unwrap();
        assert_eq!(wrp.supervisory_authority.country, "DE");
        assert_eq!(wrp.srv_description[0].content, "Awesome Service");
    }

    #[test]
    fn deserialize_intended_use() {
        let json = json!({
            "purpose": [{ "lang": "en-US", "content": "Age verification" }],
            "privacyPolicy": [{
                "type": "http://data.europa.eu/eudi/policy/privacy-policy",
                "policyURI": "https://example.com/privacy-policy"
            }],
            "createdAt": "2026-01-01T00:00:00Z",
            "revokedAt": null,
            "credential": [{
                "format": "mso_mdoc",
                "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" }
            }],
            "intendedUseIdentifier": "use-1"
        });

        let intended_use: IntendedUse = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(json, serde_json::to_value(&intended_use).unwrap());
    }
}
