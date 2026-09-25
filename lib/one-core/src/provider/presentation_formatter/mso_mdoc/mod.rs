use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use coset::{RegisteredLabelWithPrivate, SignatureContext, iana};
use serde::Deserialize;
use shared_types::DidValue;
use standardized_types::jwk::PublicJwk;
use time::Duration;
use url::Url;
use uuid::Uuid;

use self::model::{
    DeviceAuth, DeviceAuthentication, DeviceNamespaces, DeviceResponse, DeviceResponseVersion,
    DeviceSigned, Document,
};
use self::session_transcript::iso_18013_7::OID4VPDraftHandover;
use self::session_transcript::{Handover, SessionTranscript};
use crate::config::core_config::{FormatType, KeyAlgorithmType, VerificationProtocolType};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::mapper::{decode_cbor_base64, encode_cbor_base64};
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, CertificateValidatorImpl, EnforceKeyUsage,
    validate_chain_against_trust_anchors,
};
use crate::proto::clock::DefaultClock;
use crate::proto::cose::{CoseSign1, CoseSign1Builder};
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::jwt::TokenError;
use crate::provider::caching_loader::android_attestation_crl::{
    AndroidAttestationCrlCache, AndroidAttestationCrlResolver,
};
use crate::provider::caching_loader::x509_crl::{X509CrlCache, X509CrlResolver};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::util::{
    EmbeddedCbor, IssuerSigned, extract_certificate_from_x5chain_header,
    try_build_algorithm_header, try_extract_holder_public_key, try_extract_mobile_security_object,
};
use crate::provider::credential_formatter::mdoc_formatter::verify_digests;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CertificateDetails, IdentifierDetails, PublicKeySource, SignatureProvider,
    TokenVerifier, VerificationFn,
};
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, ExtractPresentationCtx, ExtractedPresentation, FormatPresentationCtx,
    FormattedPresentation,
};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::openid4vp_final1_0::OID4VPFinal1_0Handover;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;

pub(crate) mod model;
pub(crate) mod session_transcript;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
}

pub struct MsoMdocPresentationFormatter {
    certificate_validator: Arc<dyn CertificateValidator>,
    base_url: Option<String>,
    params: Params,
}

impl MsoMdocPresentationFormatter {
    pub fn new(
        certificate_validator: Arc<dyn CertificateValidator>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            base_url,
            certificate_validator,
            params: Params { leeway: 60 },
        }
    }
}

impl Default for MsoMdocPresentationFormatter {
    fn default() -> Self {
        let key_algorithm_provider = Arc::new(KeyAlgorithmProviderImpl::new(
            HashMap::from_iter(vec![
                (
                    KeyAlgorithmType::Eddsa,
                    Arc::new(crate::provider::key_algorithm::eddsa::Eddsa) as Arc<dyn KeyAlgorithm>,
                ),
                (
                    KeyAlgorithmType::Ecdsa,
                    Arc::new(crate::provider::key_algorithm::ecdsa::Ecdsa) as Arc<dyn KeyAlgorithm>,
                ),
            ]),
            Default::default(),
        ));

        let crl_cache = Arc::new(X509CrlCache::new(
            Arc::new(X509CrlResolver::new(Some(Arc::new(
                ReqwestClient::default(),
            )))),
            Arc::new(InMemoryStorage::new(HashMap::new())),
            100,
            Duration::hours(1),
            Duration::hours(1),
        ));

        let android_key_attestation_crl_cache = Arc::new(AndroidAttestationCrlCache::new(
            Arc::new(AndroidAttestationCrlResolver::new(Arc::new(
                ReqwestClient::default(),
            ))),
            Arc::new(InMemoryStorage::new(HashMap::new())),
            1,
            Duration::hours(1),
            Duration::hours(1),
        ));

        let cert_val_provider = Arc::new(CertificateValidatorImpl::new(
            key_algorithm_provider,
            crl_cache,
            Arc::new(DefaultClock),
            Duration::minutes(1),
            android_key_attestation_crl_cache,
        ));

        MsoMdocPresentationFormatter::new(cert_val_provider, None)
    }
}

#[async_trait]
impl PresentationFormatter for MsoMdocPresentationFormatter {
    async fn format_presentation(
        &self,
        credentials_to_present: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        _holder_did: &Option<DidValue>,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        let FormatPresentationCtx {
            mdoc_session_transcript: Some(session_transcript),
            ..
        } = context
        else {
            return Err(FormatterError::CouldNotFormat(format!(
                "Cannot format mdoc presentation invalid context `{context:?}`"
            )));
        };

        let tokens: Vec<String> = credentials_to_present
            .iter()
            .map(|cred| {
                if cred.credential_format != FormatType::Mdoc {
                    return Err(FormatterError::CouldNotFormat(format!(
                        "Unsupported credential format: {}",
                        cred.credential_format
                    )));
                }
                Ok(cred.credential_token.clone())
            })
            .collect::<Result<Vec<String>, FormatterError>>()?;

        let mut documents = Vec::with_capacity(tokens.len());
        for token in tokens {
            let issuer_signed: IssuerSigned = decode_cbor_base64(&token)?;
            let mso = try_extract_mobile_security_object(&issuer_signed.issuer_auth)?;
            let doc_type = mso.doc_type;
            let algorithm = holder_binding_fn
                .get_key_algorithm()
                .map_err(|key_type| FormatterError::CouldNotFormat(format!("Failed mapping algorithm `{key_type}` to name compatible with allowed COSE Algorithms")))?;

            let device_signed = try_build_device_signed(
                &*holder_binding_fn,
                algorithm,
                &doc_type,
                &session_transcript,
            )
            .await?;

            let document = Document {
                doc_type,
                issuer_signed,
                device_signed,
                errors: None,
            };

            documents.push(document);
        }

        let device_response = DeviceResponse {
            version: DeviceResponseVersion::V1_0,
            documents: Some(documents),
            document_errors: None,
            // this will be != 0 if document errors is not None
            status: 0,
        };

        Ok(FormattedPresentation {
            vp_token: encode_cbor_base64(device_response)?,
            oidc_format: "mso_mdoc".to_string(),
        })
    }

    async fn extract_presentation(
        &self,
        presentation: &str,
        verification_fn: VerificationFn,
        context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        let device_response_signed: DeviceResponse = decode_cbor_base64(presentation)?;

        let documents =
            device_response_signed
                .documents
                .ok_or(FormatterError::CouldNotExtractPresentation(
                    "Missing docs".to_string(),
                ))?;

        let mut tokens: Vec<String> = Vec::with_capacity(documents.len());

        let (session_transcript, nonce) = self.extract_presentation_context(&context)?;

        let mut presentation_issuer_jwk = None;
        // can we have more than one document?
        for document in documents {
            let issuer_signed = document.issuer_signed;

            let cert_details =
                parse_issuer_certificate(&*self.certificate_validator, &issuer_signed.issuer_auth)
                    .await?;

            try_verify_issuer_auth(
                &*self.certificate_validator,
                &issuer_signed.issuer_auth,
                cert_details.chain.as_str(),
                context.trusted_certs.as_ref(),
                &verification_fn,
            )
            .await?;
            verify_issuer_signed_data(&issuer_signed, &document.doc_type)?;

            let holder_jwk = try_extract_holder_public_key(&issuer_signed.issuer_auth)?;

            //try verify device signed
            let device_signed = document.device_signed;
            let doc_type = document.doc_type;

            let signature: coset::CoseSign1 = device_signed
                .device_auth
                .device_signature
                .ok_or(FormatterError::CouldNotExtractPresentation(
                    "Missing device signature".to_owned(),
                ))?
                .0;

            try_verify_device_signed(
                session_transcript.to_owned(),
                &doc_type,
                &signature,
                &holder_jwk,
                &verification_fn,
            )
            .await?;

            presentation_issuer_jwk = Some(holder_jwk);
            tokens.push(encode_cbor_base64(issuer_signed)?)
        }

        // todo transfer issued and expires from the token
        Ok(ExtractedPresentation {
            id: Some(Uuid::new_v4().to_string()),
            issued_at: context.issuance_date,
            expires_at: context.expiration_date,
            issuer: presentation_issuer_jwk.map(IdentifierDetails::Key),
            nonce,
            credentials: tokens,
        })
    }

    async fn extract_presentation_unverified(
        &self,
        presentation: &str,
        context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        let device_response_signed: DeviceResponse = decode_cbor_base64(presentation)?;

        let documents =
            device_response_signed
                .documents
                .ok_or(FormatterError::CouldNotExtractPresentation(
                    "Missing docs".to_string(),
                ))?;

        let tokens = documents
            .into_iter()
            .map(|doc| encode_cbor_base64(doc.issuer_signed))
            .collect::<Result<Vec<String>, FormatterError>>()?;

        // todo transfer issued and expires from the token
        Ok(ExtractedPresentation {
            id: Some(Uuid::new_v4().to_string()),
            issued_at: context.issuance_date,
            expires_at: context.expiration_date,
            issuer: None,
            nonce: context.nonce,
            credentials: tokens,
        })
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }
}

impl MsoMdocPresentationFormatter {
    fn extract_presentation_context(
        &self,
        context: &ExtractPresentationCtx,
    ) -> Result<(SessionTranscript, Option<String>), FormatterError> {
        if context.verification_protocol_type == VerificationProtocolType::IsoMdl {
            let Some(session_transcript) = context.mdoc_session_transcript.as_ref() else {
                return Err(FormatterError::CouldNotExtractPresentation(
                    "missing ISO mDL session transcript".to_string(),
                ));
            };
            let session_transcript = ciborium::from_reader(session_transcript.as_slice())?;

            return Ok((session_transcript, None));
        }

        // OpenID4VP:
        let nonce = context
            .nonce
            .as_ref()
            .ok_or(FormatterError::CouldNotExtractPresentation(
                "Missing nonce".to_owned(),
            ))?
            .to_string();

        let client_id = context
            .client_id
            .clone()
            .or_else(|| {
                // fallback for backwards compatibility (also note "base_url" is not available on mobile verifier)
                let base_url = self.base_url.as_ref()?;
                Url::parse(&format!("{base_url}/ssi/openid4vp/draft-20/response"))
                    .map(|u| u.to_string())
                    .ok()
            })
            .ok_or({
                FormatterError::CouldNotExtractPresentation(
                    "Could not create client_id for validation".to_owned(),
                )
            })?;

        let handover = match &context.verification_protocol_type {
            VerificationProtocolType::OpenId4VpFinal1_0 => {
                if let Some(response_uri) = context.response_uri.as_deref() {
                    Handover::OID4VPFinal1_0(OID4VPFinal1_0Handover::compute(
                        &client_id,
                        response_uri,
                        &nonce,
                        context.verifier_key.as_ref(),
                    )?)
                } else {
                    Handover::OID4VPFinal1_0(
                        OID4VPFinal1_0Handover::compute_for_dc_api(
                            &client_id,
                            &nonce,
                            context.verifier_key.as_ref(),
                        )
                        .map_err(|e| FormatterError::CouldNotExtractPresentation(e.to_string()))?,
                    )
                }
            }
            // proximity V2 (using dcql)
            VerificationProtocolType::OpenId4VpProximityDraft00
                if context.format_nonce.is_none() =>
            {
                let response_uri = context
                    .response_uri
                    .as_deref()
                    .unwrap_or(client_id.as_str());
                Handover::OID4VPFinal1_0(OID4VPFinal1_0Handover::compute(
                    &client_id,
                    response_uri,
                    &nonce,
                    context.verifier_key.as_ref(),
                )?)
            }
            _ => {
                let response_uri = context
                    .response_uri
                    .as_deref()
                    .unwrap_or(client_id.as_str());
                let mdoc_generated_nonce = context.format_nonce.as_ref().ok_or(
                    FormatterError::CouldNotExtractPresentation(
                        "Missing mdoc_generated_nonce".to_owned(),
                    ),
                )?;

                Handover::Iso18013_7AnnexB(OID4VPDraftHandover::compute(
                    &client_id,
                    response_uri,
                    &nonce,
                    mdoc_generated_nonce,
                )?)
            }
        };

        let session_transcript = SessionTranscript {
            device_engagement_bytes: None,
            e_reader_key_bytes: None,
            handover: Some(handover),
        };

        Ok((session_transcript, Some(nonce)))
    }
}

/// Parses the Document Signer chain of `issuer_auth` without validating it.
async fn parse_issuer_certificate(
    certificate_validator: &dyn CertificateValidator,
    issuer_auth: &CoseSign1,
) -> Result<CertificateDetails, FormatterError> {
    extract_certificate_from_x5chain_header(certificate_validator, issuer_auth, false).await
}

/// Issuer data authentication (ISO/IEC 18013-5 §9.3.1) beyond the `issuerAuth` signature.
fn verify_issuer_signed_data(
    issuer_signed: &IssuerSigned,
    doc_type: &str,
) -> Result<(), FormatterError> {
    let mso = try_extract_mobile_security_object(&issuer_signed.issuer_auth)?;

    if mso.doc_type != doc_type {
        return Err(FormatterError::CouldNotVerify(format!(
            "MSO docType `{}` does not match the document docType `{doc_type}`",
            mso.doc_type
        )));
    }

    match &issuer_signed.name_spaces {
        Some(namespaces) => verify_digests(&mso, namespaces),
        None => Ok(()),
    }
}

async fn try_verify_issuer_auth(
    certificate_validator: &dyn CertificateValidator,
    CoseSign1(cose_sign1): &CoseSign1,
    pem_chain: &str,
    trusted_certs: Option<&HashMap<String, String>>,
    verifier: &dyn TokenVerifier,
) -> Result<(), FormatterError> {
    // the Document Signer chain must validate up to a trusted IACA anchor; no anchor skips the check
    let trusted_leaf = match trusted_certs.filter(|certs| !certs.is_empty()) {
        Some(trusted_certs) => Some(
            validate_chain_against_trust_anchors(
                certificate_validator,
                pem_chain,
                trusted_certs,
                || {
                    CertificateValidationOptions::signature_and_revocation(Some(vec![
                        EnforceKeyUsage::DigitalSignature,
                    ]))
                },
            )
            .await
            .map_err(|e| {
                FormatterError::CouldNotVerify(format!(
                    "Issuer certificate chain is not trusted: {e}"
                ))
            })?,
        ),
        None => None,
    };

    let x5c = pem_chain_into_x5c(pem_chain).map_err(|err| {
        FormatterError::CouldNotExtractPresentation(format!("Failed to create x5c: {err}"))
    })?;

    let token = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        cose_sign1.protected.clone(),
        None,
        &[],
        cose_sign1.payload.as_ref().unwrap_or(&vec![]),
    );

    let algorithm = extract_algorithm_from_header(cose_sign1).ok_or_else(|| {
        FormatterError::CouldNotVerify("IssuerAuth is missing algorithm information".to_owned())
    })?;

    let params = match trusted_leaf {
        Some(leaf) => PublicKeySource::Jwk {
            jwk: Cow::Owned(leaf.public_key.public_key_as_jwk().map_err(|e| {
                FormatterError::CouldNotVerify(format!("Failed to read the DS public key: {e}"))
            })?),
        },
        None => PublicKeySource::X5c { x5c: &x5c },
    };
    Ok(verifier
        .verify(params, algorithm, &token, &cose_sign1.signature)
        .await
        .error_while("verifying")?)
}

async fn try_verify_device_signed(
    session_transcript: SessionTranscript,
    doctype: &str,
    signature: &coset::CoseSign1,
    holder_key: &PublicJwk,
    verify_fn: &VerificationFn,
) -> Result<(), FormatterError> {
    let device_namespaces = EmbeddedCbor::new([].into())?;

    let device_auth = DeviceAuthentication {
        session_transcript,
        doctype: doctype.to_owned(),
        device_namespaces,
    };
    let device_auth_bytes = EmbeddedCbor::new(device_auth)?.into_bytes();

    Ok(try_verify_detached_signature_with_provider(
        signature,
        &device_auth_bytes,
        &[],
        holder_key,
        verify_fn,
    )
    .await
    .error_while("verifying DeviceSigned")?)
}

fn extract_algorithm_from_header(cose_sign1: &coset::CoseSign1) -> Option<KeyAlgorithmType> {
    let alg = &cose_sign1.protected.header.alg;

    if let Some(RegisteredLabelWithPrivate::Assigned(algorithm)) = alg {
        match algorithm {
            iana::Algorithm::ES256 => Some(KeyAlgorithmType::Ecdsa),
            iana::Algorithm::EdDSA => Some(KeyAlgorithmType::Eddsa),
            _ => None,
        }
    } else {
        None
    }
}

async fn try_verify_detached_signature_with_provider(
    device_signature: &coset::CoseSign1,
    payload: &[u8],
    external_aad: &[u8],
    issuer_key: &PublicJwk,
    verifier: &dyn TokenVerifier,
) -> Result<(), TokenError> {
    let sig_data = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        device_signature.protected.clone(),
        None,
        external_aad,
        payload,
    );

    let algorithm = extract_algorithm_from_header(device_signature).ok_or(
        TokenError::MissingJOSEAlgorithm("Missing or invalid signature algorithm".to_string()),
    )?;

    let signature = &device_signature.signature;

    let params = PublicKeySource::Jwk {
        jwk: Cow::Borrowed(issuer_key),
    };
    verifier
        .verify(params, algorithm, &sig_data, signature)
        .await
}

async fn try_build_device_signed(
    auth_fn: &dyn SignatureProvider,
    algorithm: KeyAlgorithmType,
    doctype: &str,
    session_transcript_bytes: &[u8],
) -> Result<DeviceSigned, FormatterError> {
    let session_transcript = ciborium::from_reader(session_transcript_bytes)?;
    let device_namespaces = EmbeddedCbor::<DeviceNamespaces>::new([].into())?;

    let device_auth = DeviceAuthentication {
        session_transcript,
        doctype: doctype.to_owned(),
        device_namespaces: device_namespaces.clone(),
    };
    let device_auth_bytes = EmbeddedCbor::new(device_auth)?.into_bytes();

    let algorithm_header = try_build_algorithm_header(algorithm)?;
    let cose_sign1 = CoseSign1Builder::new()
        .protected(algorithm_header)
        .try_create_detached_signature_with_provider(&device_auth_bytes, &[], auth_fn)
        .await
        .error_while("creating signature")?
        .build();

    let device_auth = DeviceAuth {
        device_signature: Some(cose_sign1.into()),
    };

    let device_signed = DeviceSigned {
        name_spaces: device_namespaces,
        device_auth,
    };

    Ok(device_signed)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use ciborium::Value;
    use coset::iana::EnumI64;
    use coset::{HeaderBuilder, iana};
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
        DistinguishedName, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, RevokedCertParams,
        SerialNumber,
    };
    use rstest::rstest;
    use similar_asserts::assert_eq;
    use time::Duration;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use indexmap::IndexMap;
    use sha2::{Digest, Sha256};

    use super::{parse_issuer_certificate, try_verify_issuer_auth, verify_issuer_signed_data};
    use crate::mapper::x509::subject_key_identifier;
    use crate::proto::certificate_validator::{
        CertificateValidationOptions, CertificateValidator, CertificateValidatorImpl,
        EnforceKeyUsage, Error, validate_chain_against_trust_anchors,
    };
    use crate::proto::cose::CoseSign1;
    use crate::provider::credential_formatter::mdoc_formatter::util::{
        Bstr, DateTime, DeviceKey, DeviceKeyInfo, DigestAlgorithm, EmbeddedCbor, IssuerSigned,
        IssuerSignedItem, MobileSecurityObject, MobileSecurityObjectVersion, ValidityInfo,
    };
    use crate::provider::credential_formatter::model::{MockTokenVerifier, PublicKeySource};

    const DS_SERIAL: u64 = 0x2a;

    struct TestPki {
        iaca_pem: String,
        iaca_skid: String,
        ds_pem: String,
        ds_der: Vec<u8>,
    }

    async fn test_pki(crl_server: &MockServer, revoke_ds: bool, crl_downloads: u64) -> TestPki {
        let iaca_key = KeyPair::generate().unwrap();
        let mut iaca_params = CertificateParams::default();
        iaca_params.distinguished_name = common_name("Test IACA");
        iaca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        iaca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key_identifier_method = iaca_params.key_identifier_method.clone();
        let iaca = iaca_params.self_signed(&iaca_key).unwrap();
        let iaca_issuer = Issuer::new(iaca_params, iaca_key);

        let ds_key = KeyPair::generate().unwrap();
        let mut ds_params = CertificateParams::default();
        ds_params.distinguished_name = common_name("Test Document Signer");
        ds_params.serial_number = Some(SerialNumber::from(DS_SERIAL));
        ds_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        ds_params.use_authority_key_identifier_extension = true;
        ds_params.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![format!("{}/crl", crl_server.uri())],
        }];
        let ds = ds_params.signed_by(&ds_key, &iaca_issuer).unwrap();

        let now = crate::clock::now_utc();
        let revoked_certs = revoke_ds
            .then(|| RevokedCertParams {
                serial_number: SerialNumber::from(DS_SERIAL),
                revocation_time: now - Duration::hours(1),
                reason_code: None,
                invalidity_date: None,
            })
            .into_iter()
            .collect();
        let crl = CertificateRevocationListParams {
            this_update: now - Duration::hours(1),
            next_update: now + Duration::hours(24),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method,
        }
        .signed_by(&iaca_issuer)
        .unwrap();

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(crl.der().to_vec()))
            .expect(crl_downloads)
            .mount(crl_server)
            .await;

        let (_, iaca_x509) = x509_parser::parse_x509_certificate(iaca.der()).unwrap();
        TestPki {
            iaca_pem: iaca.pem(),
            iaca_skid: subject_key_identifier(&iaca_x509).unwrap().unwrap(),
            ds_pem: ds.pem(),
            ds_der: ds.der().to_vec(),
        }
    }

    fn common_name(name: &str) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        dn
    }

    /// An ES256 `issuerAuth` whose `x5chain` carries only `ds_der`; its signature is left empty.
    fn issuer_auth(ds_der: Vec<u8>) -> CoseSign1 {
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();
        let x5chain = HeaderBuilder::new()
            .value(
                iana::HeaderParameter::X5Chain.to_i64(),
                Value::Bytes(ds_der),
            )
            .build();

        CoseSign1(
            coset::CoseSign1Builder::new()
                .protected(protected)
                .unprotected(x5chain)
                .payload(vec![])
                .build(),
        )
    }

    fn ds_signature_and_revocation() -> CertificateValidationOptions {
        CertificateValidationOptions::signature_and_revocation(Some(vec![
            EnforceKeyUsage::DigitalSignature,
        ]))
    }

    #[tokio::test]
    async fn standalone_ds_chain_cannot_check_its_crl() {
        let crl_server = MockServer::start().await;
        let pki = test_pki(&crl_server, false, 1).await;

        let error = CertificateValidatorImpl::default()
            .parse_pem_chain(&pki.ds_pem, ds_signature_and_revocation())
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("CRL signer certificate is not present in the chain"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn issuer_certificate_is_parsed_without_checking_revocation() {
        let crl_server = MockServer::start().await;
        let pki = test_pki(&crl_server, false, 0).await;

        let details = parse_issuer_certificate(
            &CertificateValidatorImpl::default(),
            &issuer_auth(pki.ds_der),
        )
        .await
        .unwrap();

        assert_eq!(
            details.subject_common_name.as_deref(),
            Some("Test Document Signer")
        );
    }

    #[rstest]
    #[case::trusted_iaca(true)]
    #[case::no_trust_anchors(false)]
    #[tokio::test]
    async fn issuer_signature_is_verified_with_the_ds_key_the_trusted_iaca_vouches_for(
        #[case] with_anchor: bool,
    ) {
        let crl_server = MockServer::start().await;
        let pki = test_pki(&crl_server, false, u64::from(with_anchor)).await;
        let trusted_certs = HashMap::from([(pki.iaca_skid.clone(), pki.iaca_pem.clone())]);
        let ds_jwk = CertificateValidatorImpl::default()
            .parse_pem_chain(&pki.ds_pem, CertificateValidationOptions::no_validation())
            .await
            .unwrap()
            .public_key
            .public_key_as_jwk()
            .unwrap();

        let mut verifier = MockTokenVerifier::new();
        verifier
            .expect_verify()
            .withf(move |source, _, _, _| match source {
                PublicKeySource::Jwk { jwk } => with_anchor && **jwk == ds_jwk,
                PublicKeySource::X5c { .. } => !with_anchor,
                PublicKeySource::Did { .. } => false,
            })
            .once()
            .return_once(|_, _, _, _| Ok(()));

        try_verify_issuer_auth(
            &CertificateValidatorImpl::default(),
            &issuer_auth(pki.ds_der),
            &pki.ds_pem,
            with_anchor.then_some(&trusted_certs),
            &verifier,
        )
        .await
        .unwrap();
    }

    #[rstest]
    #[case::valid_ds(false)]
    #[case::revoked_ds(true)]
    #[tokio::test]
    async fn ds_revocation_is_checked_against_the_trusted_iaca(#[case] revoked: bool) {
        let crl_server = MockServer::start().await;
        let pki = test_pki(&crl_server, revoked, 1).await;

        let result = validate_chain_against_trust_anchors(
            &CertificateValidatorImpl::default(),
            &pki.ds_pem,
            &HashMap::from([(pki.iaca_skid, pki.iaca_pem)]),
            ds_signature_and_revocation,
        )
        .await;

        if revoked {
            assert!(
                matches!(result, Err(Error::CertificateRevoked)),
                "{result:?}"
            );
        } else {
            result.unwrap();
        }
    }

    const DOC_TYPE: &str = "org.example.test.doc";
    const NAMESPACE: &str = "org.example.test";

    fn given_name_item(value: &str) -> EmbeddedCbor<IssuerSignedItem> {
        EmbeddedCbor::new(IssuerSignedItem {
            digest_id: 0,
            random: Bstr(vec![7; 16]),
            element_identifier: "given_name".to_owned(),
            element_value: Value::Text(value.to_owned()),
        })
        .unwrap()
    }

    /// `IssuerSigned` disclosing `presented` as `given_name`, under an MSO for `mso_doc_type` whose
    /// digest was computed over `signed`. `issuerAuth` is unsigned: only its MSO payload is read.
    fn issuer_signed(signed: &str, presented: &str, mso_doc_type: &str) -> IssuerSigned {
        let digest = Sha256::digest(given_name_item(signed).bytes()).to_vec();
        let now = crate::clock::now_utc();
        let mso = MobileSecurityObject {
            version: MobileSecurityObjectVersion::V1_0,
            digest_algorithm: DigestAlgorithm::Sha256,
            value_digests: IndexMap::from([(
                NAMESPACE.to_owned(),
                IndexMap::from([(0, Bstr(digest))]),
            )]),
            device_key_info: DeviceKeyInfo {
                device_key: DeviceKey(
                    coset::CoseKeyBuilder::new_ec2_pub_key(
                        iana::EllipticCurve::P_256,
                        vec![1; 32],
                        vec![2; 32],
                    )
                    .build(),
                ),
                key_authorizations: None,
                key_info: None,
            },
            doc_type: mso_doc_type.to_owned(),
            validity_info: ValidityInfo {
                signed: DateTime(now),
                valid_from: DateTime(now),
                valid_until: DateTime(now + Duration::days(1)),
                expected_update: None,
            },
        };
        let payload = EmbeddedCbor::new(mso).unwrap().into_bytes();

        IssuerSigned {
            name_spaces: Some(IndexMap::from([(
                NAMESPACE.to_owned(),
                vec![given_name_item(presented)],
            )])),
            issuer_auth: CoseSign1(coset::CoseSign1Builder::new().payload(payload).build()),
        }
    }

    #[rstest]
    #[case::genuine("Erika", "Erika", DOC_TYPE, None)]
    #[case::tampered_element("Erika", "Erikb", DOC_TYPE, Some("Invalid digest"))]
    #[case::other_doc_type(
        "Erika",
        "Erika",
        "org.example.other.doc",
        Some("does not match the document docType")
    )]
    fn disclosed_data_must_match_the_mso(
        #[case] signed: &str,
        #[case] presented: &str,
        #[case] mso_doc_type: &str,
        #[case] expected_error: Option<&str>,
    ) {
        let result =
            verify_issuer_signed_data(&issuer_signed(signed, presented, mso_doc_type), DOC_TYPE);

        match expected_error {
            None => result.unwrap(),
            Some(expected) => {
                let error = result.unwrap_err().to_string();
                assert!(error.contains(expected), "unexpected error: {error}");
            }
        }
    }

    #[test]
    fn element_of_a_namespace_without_digests_is_rejected() {
        let mut signed = issuer_signed("Erika", "Erika", DOC_TYPE);
        let name_spaces = signed.name_spaces.as_mut().unwrap();
        let items = name_spaces.shift_remove(NAMESPACE).unwrap();
        name_spaces.insert("org.example.unsigned".to_owned(), items);

        let error = verify_issuer_signed_data(&signed, DOC_TYPE)
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("Missing digests for namespace"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn nothing_disclosed_needs_no_digests() {
        let mut signed = issuer_signed("Erika", "Erika", DOC_TYPE);
        signed.name_spaces = None;

        verify_issuer_signed_data(&signed, DOC_TYPE).unwrap();
    }
}
