mod mapper;

use std::sync::Arc;

use proc_macros::Provider;
use rcgen::{
    CertificateParams, CustomExtension, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    OtherNameValue, SanType,
};
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{CertificateId, Permission, RevocationMethodId, SignerId};
use standardized_types::etsi_119_475::access_certificate::{
    CertificatePolicy, OID_MDL_READER_AUTH, OID_MDOC_READER_AUTH,
};
use standardized_types::x509::oid;
use time::Duration;
use yasna::Tag;
use yasna::models::ObjectIdentifier;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType, RevocationType};
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::Signer;
use crate::provider::signer::access_certificate::mapper::{
    certificate_policies_extension, to_ia5, validated_pubkey_from_csr,
};
use crate::provider::signer::dto::{CreateSignatureRequest, CreateSignatureResponseDTO, Issuer};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::SignerCapabilities;
use crate::provider::signer::validity::{SignatureValidity, calculate_signature_validity};
use crate::provider::signer::x509_utils::{
    CaSigningInfo, IdentifierInfo, RevocationInfo, issuer_from_cert,
    prepare_issuer_alternative_name_extension, prepare_params_and_ca_issuer,
};

#[serde_as]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    /// exposed publicly via `GET /api/config/v1`
    #[serde_as(as = "DurationSeconds<i64>")]
    pub max_validity_duration_seconds: Duration,
    pub revocation_method: Option<RevocationMethodId>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestData {
    csr: String,
    organization_identifier: String,
    country_name: String,
    rfc822_name: Option<String>,
    other_name_phone_nr: Option<String>,
    san_uri: String,
    organization_name: Option<String>,
    common_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    policy: CertificatePolicy,
    national_registry_url: String,
}

#[derive(Provider)]
pub struct AccessCertificateSigner {
    config_name: SignerId,
    core_base_url: String,
    params: Params,
    key_provider: Arc<dyn KeyProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
}

impl AccessCertificateSigner {
    pub fn new(
        config_name: SignerId,
        params: Params,
        key_provider: Arc<dyn KeyProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        core_base_url: String,
    ) -> Self {
        Self {
            config_name,
            core_base_url,
            params,
            key_provider,
            revocation_method_provider,
        }
    }
}

#[async_trait::async_trait]
impl Signer for AccessCertificateSigner {
    fn config_name(&self) -> &SignerId {
        &self.config_name
    }

    fn get_capabilities(&self) -> SignerCapabilities {
        SignerCapabilities {
            features: vec![],
            supported_identifiers: vec![IdentifierType::CertificateAuthority],
            sign_required_permissions: vec![Permission::AccessCertificateSign],
            revoke_required_permissions: vec![Permission::AccessCertificateRevoke],
            signing_key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            revocation_methods: vec![RevocationType::CRL],
        }
    }

    async fn sign(
        &self,
        issuer: Issuer,
        request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        let (identifier, certificate, key) = match issuer {
            Issuer::Identifier {
                identifier,
                certificate,
                key,
            } => (identifier, certificate, key),
            Issuer::Key(_) => {
                return Err(SignerError::KeyIssuerNotSupported);
            }
        };

        let SignatureValidity { start, end } =
            calculate_signature_validity(self.params.max_validity_duration_seconds, &request)?;
        let request_data: RequestData = serde_json::from_value(request.data)?;
        let pub_key = validated_pubkey_from_csr(&request_data.csr)?;

        let mut cert_params = CertificateParams::default();
        cert_params.use_authority_key_identifier_extension = true;
        cert_params.not_before = start;
        cert_params.not_after = end;
        cert_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyAgreement,
        ];
        cert_params.is_ca = IsCa::ExplicitNoCa;

        cert_params
            .custom_extensions
            .push(certificate_policies_extension(&request_data.policy));
        add_extended_key_usages(&mut cert_params);
        cert_params
            .subject_alt_names
            .push(SanType::URI(to_ia5(request_data.san_uri.clone())?));
        if let Some(phone_nr) = &request_data.other_name_phone_nr {
            cert_params.subject_alt_names.push(SanType::OtherName((
                oid::attribute::TELEPHONE_NUMBER.to_vec(),
                OtherNameValue::Utf8String(phone_nr.clone()),
            )));
        }
        if let Some(rfc822_name) = &request_data.rfc822_name {
            cert_params
                .subject_alt_names
                .push(SanType::Rfc822Name(to_ia5(rfc822_name.clone())?));
        }

        cert_params.distinguished_name = mapper::request_to_distinguished_name(request_data)?;

        let CaSigningInfo {
            signature_id: id,
            ca_certificate,
            signing_key,
        } = prepare_params_and_ca_issuer(
            &mut cert_params,
            IdentifierInfo {
                identifier: &identifier,
                certificate,
                key,
            },
            RevocationInfo {
                config_name: self.config_name.to_owned(),
                revocation_method: self.revocation_method()?,
            },
            self.key_provider.clone(),
        )
        .await?;

        let (cert_issuer, issuer_alternative_name) =
            issuer_from_cert(&ca_certificate, signing_key)?;
        if let Some(issuer_alternative_name) = &issuer_alternative_name {
            cert_params
                .custom_extensions
                .push(prepare_issuer_alternative_name_extension(
                    issuer_alternative_name,
                ));
        }

        cert_params
            .custom_extensions
            .push(authority_information_access_extension(
                self.core_base_url.as_str(),
                ca_certificate.id,
            ));

        let content = cert_params
            .signed_by(&pub_key, &cert_issuer)
            .map_err(SignerError::signing_error)?;
        let chain = format!("{}{}", content.pem(), ca_certificate.chain); // include CA chain

        Ok(CreateSignatureResponseDTO { id, result: chain })
    }

    fn revocation_method(&self) -> Result<Option<Arc<dyn RevocationMethod>>, SignerError> {
        Ok(
            if let Some(revocation_method) = &self.params.revocation_method {
                Some(
                    self.revocation_method_provider
                        .get_revocation_method(revocation_method)?,
                )
            } else {
                None
            },
        )
    }
}

fn authority_information_access_extension(
    core_base_url: &str,
    certificate_id: CertificateId,
) -> CustomExtension {
    let authority_info_access = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&ObjectIdentifier::from_slice(
                    oid::access_description::CA_ISSUERS,
                ));
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(6), |writer| {
                        writer.write_ia5_string(&format!(
                            "{}/ssi/ca/{}",
                            core_base_url, certificate_id
                        ))
                    });
            });
        });
    });
    // Non-critical
    CustomExtension::from_oid_content(
        oid::extension::AUTHORITY_INFORMATION_ACCESS,
        authority_info_access,
    )
}

fn add_extended_key_usages(params: &mut CertificateParams) {
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::Other(OID_MDL_READER_AUTH.to_vec()));
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::Other(
            OID_MDOC_READER_AUTH.to_vec(),
        ));
}
