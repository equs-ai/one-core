//! Clause 5.1 — Wallet-Relying Party Access Certificate (WRPAC) X.509 profile.
//!
//! Spec: <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
//!
//! Object identifiers are given as arc slices so that both the certificate
//! builder (`rcgen` / `yasna`, which want `&[u64]`) and the parser
//! (`x509-parser` / `asn1-rs`, which want an owned `Oid`) can consume them
//! without this crate taking an ASN.1 dependency.

use serde::{Deserialize, Serialize};

/// Clause 5.1, the certificate policy the WRPAC is issued under.
///
/// It determines where the relying party identifier is found in the subject
/// distinguished name: table 3 puts it in `serialNumber` for a natural person,
/// table 1 in `organizationIdentifier` for a legal person.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificatePolicy {
    NaturalPerson,
    LegalPerson,
}

impl CertificatePolicy {
    /// The certificate policy identifier asserted in the certificate policies
    /// extension.
    pub fn oid(&self) -> &'static [u64] {
        const NATURAL_PERSON: &[u64] = &[0, 4, 0, 194112, 1, 0];
        const LEGAL_PERSON: &[u64] = &[0, 4, 0, 194112, 1, 1];

        match self {
            CertificatePolicy::NaturalPerson => NATURAL_PERSON,
            CertificatePolicy::LegalPerson => LEGAL_PERSON,
        }
    }

    /// The inverse of [`Self::oid`], for identifying a parsed certificate.
    pub fn from_oid(oid: &[u64]) -> Option<Self> {
        [Self::NaturalPerson, Self::LegalPerson]
            .into_iter()
            .find(|policy| policy.oid() == oid)
    }
}

/// Clause 5.1, extended key usage for mDL reader authentication (ISO/IEC 18013-5).
pub const OID_MDL_READER_AUTH: &[u64] = &[1, 0, 18013, 5, 1, 6];

/// Clause 5.1, extended key usage for mdoc reader authentication (ISO/IEC 23220-4).
pub const OID_MDOC_READER_AUTH: &[u64] = &[1, 0, 23220, 4, 1, 6];

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn certificate_policy_oid_round_trip() {
        for policy in [
            CertificatePolicy::NaturalPerson,
            CertificatePolicy::LegalPerson,
        ] {
            assert_eq!(Some(policy), CertificatePolicy::from_oid(policy.oid()));
        }
    }

    #[test]
    fn certificate_policy_from_unknown_oid() {
        assert_eq!(None, CertificatePolicy::from_oid(&[0, 4, 0, 194112, 1, 2]));
    }

    #[test]
    fn certificate_policy_serde() {
        assert_eq!(
            CertificatePolicy::NaturalPerson,
            serde_json::from_str(r#""NATURAL_PERSON""#).unwrap()
        );
        assert_eq!(
            CertificatePolicy::LegalPerson,
            serde_json::from_str(r#""LEGAL_PERSON""#).unwrap()
        );
    }
}
