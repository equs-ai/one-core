use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::{Deserialize, Serialize, de, ser};
use uuid::Uuid;

/// Object identifiers of the attribute types and extensions used when building
/// or parsing certificates.
///
/// Given as arc slices so that both the certificate builder (`rcgen` /
/// `yasna`, which want `&[u64]`) and the parser (`x509-parser` / `asn1-rs`,
/// which want an owned `Oid`) can consume them without this crate taking an
/// ASN.1 dependency.
pub mod oid {
    /// ITU-T X.520 attribute types, `joint-iso-itu-t(2) ds(5) attributeType(4)`
    pub mod attribute {
        pub const SURNAME: &[u64] = &[2, 5, 4, 4];
        pub const SERIAL_NUMBER: &[u64] = &[2, 5, 4, 5];
        pub const TELEPHONE_NUMBER: &[u64] = &[2, 5, 4, 20];
        pub const GIVEN_NAME: &[u64] = &[2, 5, 4, 42];
        pub const CONTENT_URL: &[u64] = &[2, 5, 4, 81];
        pub const ORGANIZATION_IDENTIFIER: &[u64] = &[2, 5, 4, 97];
    }

    /// Certificate extensions, `joint-iso-itu-t(2) ds(5) certificateExtension(29)`
    /// and RFC 5280 private extensions.
    pub mod extension {
        pub const ISSUER_ALTERNATIVE_NAME: &[u64] = &[2, 5, 29, 18];
        pub const CERTIFICATE_POLICIES: &[u64] = &[2, 5, 29, 32];
        pub const EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37];
        /// RFC 5280 clause 4.2.2.1
        pub const AUTHORITY_INFORMATION_ACCESS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];
    }

    /// RFC 5280 access descriptors, `id-ad`
    pub mod access_description {
        pub const CA_ISSUERS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 2];
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertificateSerial(Vec<u8>);

impl TryFrom<Vec<u8>> for CertificateSerial {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() > 20 {
            return Err(anyhow::anyhow!("Certificate serial too long"));
        }
        Ok(Self(value))
    }
}

impl From<CertificateSerial> for Vec<u8> {
    fn from(value: CertificateSerial) -> Self {
        value.0
    }
}

impl CertificateSerial {
    /// Generate a random serial
    pub fn new_random() -> Self {
        let mut random_bytes = Uuid::new_v4().as_bytes().to_vec();
        random_bytes.insert(0, 0x01); // to make sure it is a positive value
        Self(random_bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Used for the Authority Key Identifier or Subject Key Identifier extensions
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct KeyIdentifier(Vec<u8>);

impl From<Vec<u8>> for KeyIdentifier {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl KeyIdentifier {
    pub fn from_base64url(value: &str) -> Result<Self, ct_codecs::Error> {
        Ok(Self(Base64UrlSafeNoPadding::decode_to_vec(value, None)?))
    }
}

impl core::fmt::LowerHex for KeyIdentifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes: Vec<_> = self.0.iter().map(|b| format!("{b:02x}")).collect();
        f.write_str(&bytes.join(":"))
    }
}

// serialization from/into base64url string
impl Serialize for KeyIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Base64UrlSafeNoPadding::encode_to_string(&self.0)
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for KeyIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_base64url(&value).map_err(de::Error::custom)
    }
}
