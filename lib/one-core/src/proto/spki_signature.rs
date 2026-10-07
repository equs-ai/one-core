//! Verification-only RSA (PKCS#1 v1.5, PSS) and ECDSA P-384 signatures over X.509 public keys.
//!
//! Fork addition, used to authenticate trust lists signed by keys the key algorithm provider
//! does not support (most EU national TSLs are RSA-signed). These keys never sign: there is no
//! key algorithm, key storage or DID support for them.

use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_parser::oid_registry::{
    OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_PKCS1_RSAENCRYPTION, OID_PKCS1_RSASSAPSS,
};
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::{KeyHandleError, SignaturePublicKeyHandle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpkiSignatureAlgorithm {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    /// ECDSA P-384 with SHA-384, signature as fixed-size `r || s`.
    EcdsaP384Sha384,
}

impl SpkiSignatureAlgorithm {
    fn verification_algorithm(self) -> &'static dyn VerificationAlgorithm {
        match self {
            Self::RsaPkcs1Sha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            Self::RsaPkcs1Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            Self::RsaPkcs1Sha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            Self::RsaPssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
            Self::RsaPssSha384 => &signature::RSA_PSS_2048_8192_SHA384,
            Self::RsaPssSha512 => &signature::RSA_PSS_2048_8192_SHA512,
            Self::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_FIXED,
        }
    }

    /// JOSE `alg` values handled here (RFC 7518 §3.1).
    pub fn from_jose_alg(alg: &str) -> Option<Self> {
        Some(match alg {
            "RS256" => Self::RsaPkcs1Sha256,
            "RS384" => Self::RsaPkcs1Sha384,
            "RS512" => Self::RsaPkcs1Sha512,
            "PS256" => Self::RsaPssSha256,
            "PS384" => Self::RsaPssSha384,
            "PS512" => Self::RsaPssSha512,
            "ES384" => Self::EcdsaP384Sha384,
            _ => return None,
        })
    }

    /// XML-DSig `SignatureMethod` URIs handled here (RFC 6931).
    pub fn from_xmldsig_uri(uri: &str) -> Option<Self> {
        Some(match uri {
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Self::RsaPkcs1Sha256,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Self::RsaPkcs1Sha384,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Self::RsaPkcs1Sha512,
            "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" => Self::RsaPssSha256,
            "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1" => Self::RsaPssSha384,
            "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1" => Self::RsaPssSha512,
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => Self::EcdsaP384Sha384,
            _ => return None,
        })
    }

    fn is_rsa(self) -> bool {
        !matches!(self, Self::EcdsaP384Sha384)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpkiSignatureError {
    #[error("Unsupported public key: {0}")]
    UnsupportedKey(String),
    #[error("Public key does not match the signature algorithm")]
    KeyMismatch,
    #[error("Signature is invalid")]
    InvalidSignature,
}

/// The key family a SubjectPublicKeyInfo carries, when it is one handled here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpkiKeyFamily {
    Rsa,
    EcP384,
}

pub fn key_family(spki: &SubjectPublicKeyInfo<'_>) -> Option<SpkiKeyFamily> {
    let algorithm = &spki.algorithm.algorithm;
    if algorithm == &OID_PKCS1_RSAENCRYPTION || algorithm == &OID_PKCS1_RSASSAPSS {
        return Some(SpkiKeyFamily::Rsa);
    }
    if algorithm == &OID_KEY_TYPE_EC_PUBLIC_KEY
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .is_some_and(|curve| curve == OID_NIST_EC_P384)
    {
        return Some(SpkiKeyFamily::EcP384);
    }
    None
}

/// Verify `signature` over `message` with the key in the DER-encoded SubjectPublicKeyInfo.
pub fn verify(
    algorithm: SpkiSignatureAlgorithm,
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), SpkiSignatureError> {
    let (_, spki) = SubjectPublicKeyInfo::from_der(spki_der)
        .map_err(|e| SpkiSignatureError::UnsupportedKey(e.to_string()))?;
    let family = key_family(&spki).ok_or_else(|| {
        SpkiSignatureError::UnsupportedKey(spki.algorithm.algorithm.to_id_string())
    })?;
    if (family == SpkiKeyFamily::Rsa) != algorithm.is_rsa() {
        return Err(SpkiSignatureError::KeyMismatch);
    }
    UnparsedPublicKey::new(
        algorithm.verification_algorithm(),
        spki.subject_public_key.data.as_ref(),
    )
    .verify(message, signature)
    .map_err(|_| SpkiSignatureError::InvalidSignature)
}

/// Verify-only key handle for an RSA or P-384 certificate key. `verify` uses the key family's
/// default algorithm (RSA PKCS#1 v1.5 with SHA-256, ECDSA P-384 with SHA-384); callers that know
/// the actual algorithm (XML-DSig, JOSE) call [`verify`] directly.
pub struct SpkiPublicKeyHandle {
    spki_der: Vec<u8>,
    key_bytes: Vec<u8>,
    default_algorithm: SpkiSignatureAlgorithm,
}

impl SpkiPublicKeyHandle {
    pub fn from_spki_der(spki_der: &[u8]) -> Result<Self, KeyAlgorithmError> {
        let (_, spki) = SubjectPublicKeyInfo::from_der(spki_der)
            .map_err(|e| KeyAlgorithmError::InvalidEncoding(e.to_string()))?;
        let default_algorithm = match key_family(&spki) {
            Some(SpkiKeyFamily::Rsa) => SpkiSignatureAlgorithm::RsaPkcs1Sha256,
            Some(SpkiKeyFamily::EcP384) => SpkiSignatureAlgorithm::EcdsaP384Sha384,
            None => {
                return Err(KeyAlgorithmError::NotSupported(format!(
                    "unsupported public key algorithm {}",
                    spki.algorithm.algorithm.to_id_string()
                )));
            }
        };
        Ok(Self {
            spki_der: spki_der.to_vec(),
            key_bytes: spki.subject_public_key.data.to_vec(),
            default_algorithm,
        })
    }
}

impl SignaturePublicKeyHandle for SpkiPublicKeyHandle {
    fn as_jwk(&self) -> Result<standardized_types::jwk::PublicJwk, KeyHandleError> {
        Err(KeyHandleError::OperationNotSupported)
    }

    fn as_multibase(&self) -> Result<String, KeyHandleError> {
        Err(KeyHandleError::OperationNotSupported)
    }

    fn as_raw(&self) -> Vec<u8> {
        self.key_bytes.clone()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyHandleError> {
        verify(self.default_algorithm, &self.spki_der, message, signature).map_err(|e| {
            KeyHandleError::SignerError(one_crypto::SignerError::CouldNotVerify(e.to_string()))
        })
    }
}

#[cfg(test)]
mod test {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, RsaKeyPair};
    use similar_asserts::assert_eq;

    use super::*;

    fn spki_of(cert: &rcgen::Certificate) -> Vec<u8> {
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.der()).unwrap();
        parsed.tbs_certificate.subject_pki.raw.to_vec()
    }

    #[test]
    fn jose_and_xmldsig_identifiers() {
        assert_eq!(
            SpkiSignatureAlgorithm::from_jose_alg("PS384"),
            Some(SpkiSignatureAlgorithm::RsaPssSha384)
        );
        assert_eq!(SpkiSignatureAlgorithm::from_jose_alg("ES256"), None);
        assert_eq!(
            SpkiSignatureAlgorithm::from_xmldsig_uri(
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
            ),
            Some(SpkiSignatureAlgorithm::EcdsaP384Sha384)
        );
    }

    #[test]
    fn verifies_ecdsa_p384() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let signer = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            &key_pair.serialize_der(),
        )
        .unwrap();
        let cert = rcgen::CertificateParams::new(vec!["p384.test".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let spki = spki_of(&cert);
        let message = b"trust list";
        let signature = signer.sign(&SystemRandom::new(), message).unwrap();

        verify(
            SpkiSignatureAlgorithm::EcdsaP384Sha384,
            &spki,
            message,
            signature.as_ref(),
        )
        .unwrap();
        assert!(matches!(
            verify(
                SpkiSignatureAlgorithm::EcdsaP384Sha384,
                &spki,
                b"other",
                signature.as_ref()
            ),
            Err(SpkiSignatureError::InvalidSignature)
        ));
        assert!(matches!(
            verify(
                SpkiSignatureAlgorithm::RsaPkcs1Sha256,
                &spki,
                message,
                signature.as_ref()
            ),
            Err(SpkiSignatureError::KeyMismatch)
        ));
        assert_eq!(signer.public_key().as_ref().len(), 97);
    }

    #[test]
    fn verifies_rsa_pkcs1_and_pss_through_a_certificate_key() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["rsa.test".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let spki = spki_of(&cert);
        let signer = RsaKeyPair::from_pkcs8(&key_pair.serialize_der()).unwrap();
        let message = b"trust list";
        let rng = SystemRandom::new();

        let mut pkcs1 = vec![0; signer.public_modulus_len()];
        signer
            .sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut pkcs1)
            .unwrap();
        let mut pss = vec![0; signer.public_modulus_len()];
        signer
            .sign(&signature::RSA_PSS_SHA384, &rng, message, &mut pss)
            .unwrap();

        verify(
            SpkiSignatureAlgorithm::RsaPkcs1Sha256,
            &spki,
            message,
            &pkcs1,
        )
        .unwrap();
        verify(SpkiSignatureAlgorithm::RsaPssSha384, &spki, message, &pss).unwrap();
        assert!(
            verify(
                SpkiSignatureAlgorithm::RsaPkcs1Sha512,
                &spki,
                message,
                &pkcs1
            )
            .is_err()
        );

        // the default handle verifies PKCS#1 v1.5 / SHA-256
        let handle = SpkiPublicKeyHandle::from_spki_der(&spki).unwrap();
        handle.verify(message, &pkcs1).unwrap();
        assert!(handle.verify(message, &pss).is_err());
    }
}
