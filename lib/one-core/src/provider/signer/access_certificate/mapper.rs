use rcgen::string::Ia5String;
use rcgen::{
    CertificateSigningRequestParams, CustomExtension, DistinguishedName, DnType, PublicKey,
};
use standardized_types::etsi_119_475::access_certificate::CertificatePolicy;
use standardized_types::x509::oid;
use yasna::models::ObjectIdentifier;

use crate::provider::signer::access_certificate::RequestData;
use crate::provider::signer::error::SignerError;

/// ETSI TS 119 475 clause 5.1: asserts the certificate policy the WRPAC is issued under.
pub(super) fn certificate_policies_extension(policy: &CertificatePolicy) -> CustomExtension {
    let certificate_policy_ext_content = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(policy.oid()));
            });
        });
    });
    // Not critical according to ETSI EN 319 412-2
    CustomExtension::from_oid_content(
        oid::extension::CERTIFICATE_POLICIES,
        certificate_policy_ext_content,
    )
}

pub(super) fn validated_pubkey_from_csr(csr: &str) -> Result<PublicKey, SignerError> {
    let csr = CertificateSigningRequestParams::from_pem(csr)
        .map_err(|e| SignerError::InvalidPayload(Box::new(e)))?;
    Ok(csr.public_key)
}

pub(super) fn request_to_distinguished_name(
    request: RequestData,
) -> Result<DistinguishedName, SignerError> {
    let mut dn = DistinguishedName::new();

    dn.push(DnType::CountryName, request.country_name);
    dn.push(
        DnType::CustomDnType(oid::attribute::CONTENT_URL.to_vec()),
        request.national_registry_url,
    );
    if let Some(cn) = request.common_name {
        dn.push(DnType::CommonName, cn)
    }

    match &request.policy {
        CertificatePolicy::NaturalPerson => {
            // ETSI 119 475 Table 3: identifier → serialNumber (clause 5.1.5)
            dn.push(
                DnType::CustomDnType(oid::attribute::SERIAL_NUMBER.to_vec()),
                request.organization_identifier,
            );
            if request.organization_name.is_some() {
                return Err(SignerError::InvalidPayload(
                    "organizationName is not allowed for natural person"
                        .to_string()
                        .into(),
                ));
            }
            let Some(given_name) = request.given_name else {
                return Err(SignerError::InvalidPayload(
                    "givenName is required for natural person"
                        .to_string()
                        .into(),
                ));
            };
            dn.push(
                DnType::CustomDnType(oid::attribute::GIVEN_NAME.to_vec()),
                given_name,
            );
            let Some(family_name) = request.family_name else {
                return Err(SignerError::InvalidPayload(
                    "familyName is required for natural person"
                        .to_string()
                        .into(),
                ));
            };
            dn.push(
                DnType::CustomDnType(oid::attribute::SURNAME.to_vec()),
                family_name,
            )
        }
        CertificatePolicy::LegalPerson => {
            // ETSI 119 475 Table 1: identifier → organizationIdentifier (clause 5.1.3)
            dn.push(
                DnType::CustomDnType(oid::attribute::ORGANIZATION_IDENTIFIER.to_vec()),
                request.organization_identifier,
            );
            if request.given_name.is_some() {
                return Err(SignerError::InvalidPayload(
                    "givenName is not allowed for legal person"
                        .to_string()
                        .into(),
                ));
            }
            if request.family_name.is_some() {
                return Err(SignerError::InvalidPayload(
                    "familyName is not allowed for legal person"
                        .to_string()
                        .into(),
                ));
            }
            let Some(organization_name) = request.organization_name else {
                return Err(SignerError::InvalidPayload(
                    "organizationName is required for legal person"
                        .to_string()
                        .into(),
                ));
            };
            dn.push(DnType::OrganizationName, organization_name)
        }
    }
    Ok(dn)
}

pub(super) fn to_ia5(string: String) -> Result<Ia5String, SignerError> {
    string
        .try_into()
        .map_err(|err| SignerError::InvalidPayload(Box::new(err)))
}
