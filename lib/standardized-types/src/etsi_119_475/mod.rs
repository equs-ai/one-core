//! ETSI TS 119 475 — Electronic Signatures and Trust Infrastructures;
//! Relying party attributes supporting EUDI Wallet user's authorisation.
//!
//! Spec: <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
//!
//! The submodules cover the three surfaces the standard defines, and are
//! deliberately *not* glob re-exported: they contain intentionally colliding
//! short names (`Payload`, `MultiLangString`, `LegalPerson`, `NaturalPerson`),
//! so import them submodule-qualified.

pub mod access_certificate;
pub mod registration_certificate;
pub mod registry;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::etsi_119_602;
use crate::openid4vp::dcql;

/// Clause 5.2.4, a language-tagged string as used by the WRPRC payload.
///
/// Note the registry data model of annex B uses a different field name for the
/// text, see [`registry::MultiLangString`].
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MultiLangString {
    /// BCP 47 language tag
    pub lang: String,
    pub value: String,
}

impl From<MultiLangString> for etsi_119_602::json::MultiLangString {
    fn from(value: MultiLangString) -> Self {
        Self {
            lang: value.lang,
            value: value.value,
        }
    }
}

/// Clause 4.2, wallet-relying party roles.
///
/// The entitlements may be expressed as OIDs or structured URIs in certificate
/// profiles and registration data formats, which is why the wire format is
/// carried alongside the role: re-serializing an entitlement has to reproduce
/// the representation it was received in.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entitlement {
    pub format: EntitlementFormat,
    pub role: EntitlementRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntitlementFormat {
    Oid,
    Uri,
}

/// Annex A.2
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntitlementRole {
    ServiceProvider,
    QeaaProvider,
    NonQeaaProvider,
    PubEaaProvider,
    PidProvider,
    QCertForESealProvider,
    QCertForESigProvider,
    RQSealCDsProvider,
    RQSigCDsProvider,
    ESigESealCreationProvider,
}

impl EntitlementRole {
    pub fn get_oid(&self) -> &'static str {
        match self {
            EntitlementRole::ServiceProvider => "id-etsi-wrpa-entitlement 1",
            EntitlementRole::QeaaProvider => "id-etsi-wrpa-entitlement 2",
            EntitlementRole::NonQeaaProvider => "id-etsi-wrpa-entitlement 3",
            EntitlementRole::PubEaaProvider => "id-etsi-wrpa-entitlement 4",
            EntitlementRole::PidProvider => "id-etsi-wrpa-entitlement 5",
            EntitlementRole::QCertForESealProvider => "id-etsi-wrpa-entitlement 6",
            EntitlementRole::QCertForESigProvider => "id-etsi-wrpa-entitlement 7",
            EntitlementRole::RQSealCDsProvider => "id-etsi-wrpa-entitlement 8",
            EntitlementRole::RQSigCDsProvider => "id-etsi-wrpa-entitlement 9",
            EntitlementRole::ESigESealCreationProvider => "id-etsi-wrpa-entitlement 10",
        }
    }

    pub fn get_uri(&self) -> &'static str {
        match self {
            EntitlementRole::ServiceProvider => {
                "https://uri.etsi.org/19475/Entitlement/Service_Provider"
            }
            EntitlementRole::QeaaProvider => "https://uri.etsi.org/19475/Entitlement/QEAA_Provider",
            EntitlementRole::NonQeaaProvider => {
                "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
            }
            EntitlementRole::PubEaaProvider => {
                "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider"
            }
            EntitlementRole::PidProvider => "https://uri.etsi.org/19475/Entitlement/PID_Provider",
            EntitlementRole::QCertForESealProvider => {
                "https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider"
            }
            EntitlementRole::QCertForESigProvider => {
                "https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider"
            }
            EntitlementRole::RQSealCDsProvider => {
                "https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider"
            }
            EntitlementRole::RQSigCDsProvider => {
                "https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider"
            }
            EntitlementRole::ESigESealCreationProvider => {
                "https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider"
            }
        }
    }
}

impl Serialize for Entitlement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str = match self.format {
            EntitlementFormat::Oid => self.role.get_oid(),
            EntitlementFormat::Uri => self.role.get_uri(),
        };
        serializer.serialize_str(str)
    }
}

impl<'de> Deserialize<'de> for Entitlement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        let result = {
            if let Some(oid_number) = str.strip_prefix("id-etsi-wrpa-entitlement ") {
                let role = match oid_number {
                    "1" => Some(EntitlementRole::ServiceProvider),
                    "2" => Some(EntitlementRole::QeaaProvider),
                    "3" => Some(EntitlementRole::NonQeaaProvider),
                    "4" => Some(EntitlementRole::PubEaaProvider),
                    "5" => Some(EntitlementRole::PidProvider),
                    "6" => Some(EntitlementRole::QCertForESealProvider),
                    "7" => Some(EntitlementRole::QCertForESigProvider),
                    "8" => Some(EntitlementRole::RQSealCDsProvider),
                    "9" => Some(EntitlementRole::RQSigCDsProvider),
                    "10" => Some(EntitlementRole::ESigESealCreationProvider),
                    _ => None,
                };
                role.map(|role| Self {
                    format: EntitlementFormat::Oid,
                    role,
                })
            } else if let Some(url_path) =
                str.strip_prefix("https://uri.etsi.org/19475/Entitlement/")
            {
                let role = match url_path {
                    "Service_Provider" => Some(EntitlementRole::ServiceProvider),
                    "QEAA_Provider" => Some(EntitlementRole::QeaaProvider),
                    "Non_Q_EAA_Provider" => Some(EntitlementRole::NonQeaaProvider),
                    "PUB_EAA_Provider" => Some(EntitlementRole::PubEaaProvider),
                    "PID_Provider" => Some(EntitlementRole::PidProvider),
                    "QCert_for_ESeal_Provider" => Some(EntitlementRole::QCertForESealProvider),
                    "QCert_for_ESig_Provider" => Some(EntitlementRole::QCertForESigProvider),
                    "rQSealCDs_Provider" => Some(EntitlementRole::RQSealCDsProvider),
                    "rQSigCDs_Provider" => Some(EntitlementRole::RQSigCDsProvider),
                    "ESig_ESeal_Creation_Provider" => {
                        Some(EntitlementRole::ESigESealCreationProvider)
                    }
                    _ => None,
                };
                role.map(|role| Self {
                    format: EntitlementFormat::Uri,
                    role,
                })
            } else {
                None
            }
        };

        // TODO: Return a list of expected variants
        result.ok_or(D::Error::unknown_variant(str.as_str(), &[]))
    }
}

/// Clause 5.2.4 `credentials` / `provides_attestations` entry, also used as the
/// annex B.2.9 registry credential.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    #[serde(flatten)]
    pub format: dcql::CredentialFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim: Option<Vec<Claim>>,
}

/// Clause 5.2.4, a single requested claim of a [`Credential`].
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub path: dcql::ClaimPath,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<dcql::ClaimValue>>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn deserialize_serialize_entitlement() {
        const ENTITLEMENTS: &[&str] = &[
            "\"id-etsi-wrpa-entitlement 1\"",
            "\"https://uri.etsi.org/19475/Entitlement/Service_Provider\"",
            "\"id-etsi-wrpa-entitlement 2\"",
            "\"https://uri.etsi.org/19475/Entitlement/QEAA_Provider\"",
            "\"id-etsi-wrpa-entitlement 3\"",
            "\"https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider\"",
            "\"id-etsi-wrpa-entitlement 4\"",
            "\"https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider\"",
            "\"id-etsi-wrpa-entitlement 5\"",
            "\"https://uri.etsi.org/19475/Entitlement/PID_Provider\"",
            "\"id-etsi-wrpa-entitlement 6\"",
            "\"https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider\"",
            "\"id-etsi-wrpa-entitlement 7\"",
            "\"https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider\"",
            "\"id-etsi-wrpa-entitlement 8\"",
            "\"https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider\"",
            "\"id-etsi-wrpa-entitlement 9\"",
            "\"https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider\"",
            "\"id-etsi-wrpa-entitlement 10\"",
            "\"https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider\"",
        ];

        for input in ENTITLEMENTS {
            let deserialized: Entitlement = serde_json::from_str(input).unwrap();
            let serialized = serde_json::to_string(&deserialized).unwrap();
            similar_asserts::assert_eq!(serialized.as_str(), *input);
        }
    }

    #[test]
    fn deserialize_unknown_entitlement() {
        assert!(
            serde_json::from_str::<Entitlement>("\"id-etsi-wrpa-entitlement 11\"")
                .unwrap_err()
                .is_data()
        );
    }

    #[test]
    fn deserialize_claim_value_ok() {
        const DOCUMENT: &str =
            r#"{"path": ["first", "second"], "values": ["string", 10, -40, false]}"#;
        serde_json::from_str::<Claim>(DOCUMENT).unwrap();
    }

    #[test]
    fn deserialize_claim_value_invalid() {
        const DOCUMENT: &str = r#"{"path": [], "values": [21.37]}"#;
        assert!(
            serde_json::from_str::<Claim>(DOCUMENT)
                .unwrap_err()
                .is_data()
        );
    }
}
