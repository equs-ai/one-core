use standardized_types::etsi_119_475::registration_certificate::{Payload, Status, Subject};

use crate::provider::signer::registration_certificate::model::RequestData;

/// Builds the WRPRC payload of clause 5.2.4 from the signing request, flattening the subject into
/// the `sub_ln` / `sub_gn` / `sub_fn` claims.
pub(super) fn payload_from_request_data(req: RequestData, status: Status) -> Payload {
    let (sub_ln, sub_gn, sub_fn) = match req.subject {
        Subject::LegalPerson { legal_name, .. } => (Some(legal_name), None, None),
        Subject::NaturalPerson {
            given_name,
            family_name,
            ..
        } => (None, Some(given_name), Some(family_name)),
    };

    Payload {
        name: req.name,
        sub_ln,
        sub_gn,
        sub_fn,
        country: req.country,
        registry_uri: req.registry_uri,
        service_descriptions: vec![req.service_description],
        entitlements: req.entitlements,
        privacy_policy: req.privacy_policy,
        info_uri: req.info_uri,
        supervisory_authority: req.supervisory_authority,
        policy_id: req.policy_id,
        certificate_policy: req.certificate_policy,
        provides_attestations: req.provided_attestations,
        credentials: req.credentials,
        purpose: req.purpose,
        intended_use_id: req.intended_use_id,
        public_body: req.public_body,
        support_uri: req.support_uri,
        intermediary: req.intermediary,
        status,
    }
}
