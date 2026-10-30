//! ETSI EN 319 132-1 XAdES Qualifying Properties (B-B level).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::xmldsig::{AlgorithmIdentifier, XMLDSIG_NS};

// EN 319 132-1 §4.4.2
pub const SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
pub const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";

fn default_xmldsig_ns() -> String {
    XMLDSIG_NS.to_string()
}
fn default_xades_ns() -> String {
    XADES_NS.to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualifyingProperties {
    #[serde(rename = "@xmlns:xades", default = "default_xades_ns")]
    pub xmlns_xades: String,
    #[serde(rename = "@Target")]
    pub target: String,
    #[serde(rename = "xades:SignedProperties", alias = "SignedProperties")]
    pub signed_properties: SignedProperties,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename = "xades:SignedProperties")]
pub struct SignedProperties {
    #[serde(rename = "@xmlns:xades", default = "default_xades_ns")]
    pub xmlns_xades: String,
    #[serde(rename = "@xmlns:ds", default = "default_xmldsig_ns")]
    pub xmlns_ds: String,
    #[serde(rename = "@Id")]
    pub id: String,
    #[serde(
        rename = "xades:SignedSignatureProperties",
        alias = "SignedSignatureProperties"
    )]
    pub signed_signature_properties: SignedSignatureProperties,
    #[serde(
        rename = "xades:SignedDataObjectProperties",
        alias = "SignedDataObjectProperties"
    )]
    pub signed_data_object_properties: SignedDataObjectProperties,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedSignatureProperties {
    #[serde(
        rename = "xades:SigningTime",
        alias = "SigningTime",
        with = "time::serde::rfc3339"
    )]
    pub signing_time: OffsetDateTime,
    #[serde(rename = "xades:SigningCertificateV2", alias = "SigningCertificateV2")]
    pub signing_certificate_v2: SigningCertificateV2,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SigningCertificateV2 {
    #[serde(rename = "xades:Cert", alias = "Cert")]
    pub certs: Vec<Cert>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cert {
    #[serde(rename = "xades:CertDigest", alias = "CertDigest")]
    pub cert_digest: CertDigest,

    // base64-encoded DER IssuerSerial (RFC 5035)
    #[serde(rename = "xades:IssuerSerialV2", alias = "IssuerSerialV2")]
    pub issuer_serial_v2: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertDigest {
    #[serde(rename = "ds:DigestMethod", alias = "DigestMethod")]
    pub digest_method: AlgorithmIdentifier,
    #[serde(rename = "ds:DigestValue", alias = "DigestValue")]
    pub digest_value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedDataObjectProperties {
    #[serde(rename = "xades:DataObjectFormat", alias = "DataObjectFormat")]
    pub data_object_format: DataObjectFormat,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataObjectFormat {
    #[serde(rename = "@ObjectReference")]
    pub object_reference: String,
    #[serde(rename = "xades:MimeType", alias = "MimeType")]
    pub mime_type: String,
}
