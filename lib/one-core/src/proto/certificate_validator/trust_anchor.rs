//! Validation of a certificate chain against a set of configured trust anchors.

use std::collections::HashMap;

use x509_parser::pem::Pem;
use x509_parser::prelude::X509Certificate;

use super::{
    CertSelection, CertificateValidationOptions, CertificateValidator, Error, ParsedCertificate,
};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::authority_key_identifier;

/// Validates `pem_chain` (leaf first) up to one of `trusted_anchors`, each given as its PEM keyed by
/// its Subject Key Identifier, and returns the parsed leaf.
pub async fn validate_chain_against_trust_anchors(
    validator: &dyn CertificateValidator,
    pem_chain: &str,
    trusted_anchors: &HashMap<String, String>,
    validation: impl Fn() -> CertificateValidationOptions,
) -> Result<ParsedCertificate, Error> {
    let pems = Pem::iter_from_buffer(pem_chain.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let certs = pems
        .iter()
        .map(|pem| pem.parse_x509())
        .collect::<Result<Vec<_>, _>>()?;

    let leaf = certs.first().ok_or(Error::EmptyChain)?;
    if is_self_signed(leaf) {
        return Err(Error::InvalidCaCertificateChain(
            "Leaf certificate must not be self-signed".to_string(),
        ));
    }

    let declared_akids = certs
        .iter()
        .map(authority_key_identifier)
        .collect::<Result<Vec<_>, _>>()
        .error_while("parsing authority key identifier")?;

    let declared_anchors: Vec<&String> = declared_akids
        .iter()
        .flatten()
        .filter_map(|akid| trusted_anchors.get(akid))
        .collect();

    // An anchor named by the chain is tried alone, so its real failure (expired, revoked, bad
    // signature) is reported. Otherwise — e.g. a chain without AKIs — every anchor is tried.
    if !declared_anchors.is_empty() {
        let mut last_error = None;
        for anchor_pem in declared_anchors {
            match validate_against(validator, pem_chain, anchor_pem, validation()).await {
                Ok(leaf) => return Ok(leaf),
                Err(error) => last_error = Some(error),
            }
        }
        return Err(last_error.unwrap_or(Error::EmptyChain));
    }

    for (skid, anchor_pem) in trusted_anchors {
        match validate_against(validator, pem_chain, anchor_pem, validation()).await {
            Ok(leaf) => return Ok(leaf),
            Err(error) => tracing::debug!(%skid, %error, "chain does not validate against anchor"),
        }
    }

    Err(Error::InvalidCaCertificateChain(
        "Certificate chain does not validate against any trusted anchor".to_string(),
    ))
}

async fn validate_against(
    validator: &dyn CertificateValidator,
    pem_chain: &str,
    anchor_pem: &str,
    validation: CertificateValidationOptions,
) -> Result<ParsedCertificate, Error> {
    validator
        .validate_chain_against_ca_chain(pem_chain, anchor_pem, validation, CertSelection::Leaf)
        .await
}

fn is_self_signed(certificate: &X509Certificate) -> bool {
    certificate.subject() == certificate.issuer() && certificate.verify_signature(None).is_ok()
}
