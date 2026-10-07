use std::sync::Arc;

use standardized_types::etsi_119_612::xml::{OtherTslPointer, TrustServiceStatusList};
use standardized_types::etsi_119_612::{MIME_TSL_XML, TslType};
use standardized_types::xades::{EXC_C14N, SIGNED_PROPERTIES_TYPE, Transform};
use time::OffsetDateTime;

use super::model::DelegatedMember;
use super::preprocessing::preprocess_services;
use crate::error::ContextWithErrorCode;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::clock::Clock;
use crate::proto::http_client::HttpClient;
use crate::proto::xades::{XAdESProto, XAdESSignedXML, XAdESVerified};
use crate::provider::caching_loader::{ResolveResult, Resolver, ResolverError};
use crate::provider::trust_list_subscriber::fetch::{
    self, Deadline, FetchError, FetchLimits, SignerPin, SkipReason, SkippedMember,
};

/// XML media types a TS 119 612 TSL may be served as.
const TSL_XML_MEDIA_TYPES: &[&str] = &[MIME_TSL_XML, "application/xml", "text/xml"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PointerKind {
    /// A member-state TSL aggregated here.
    Member,
    /// A 612 list we recognize but don't follow.
    Skip,
    /// Not a 612 list, handed to the delegate subscribers.
    Delegate,
}

/// The TSL signature must be over the whole document (`URI=""` or `#<root Id>`, with the
/// enveloped-signature transform) and over its SignedProperties, so that the parsed content is
/// the signed content.
fn assert_tsl_signature_policy(
    verified: &XAdESVerified,
    root_id: Option<&str>,
    leeway: time::Duration,
    now: OffsetDateTime,
) -> Result<(), FetchError> {
    if verified.signing_time > now + leeway {
        return Err(FetchError::InvalidSignature(
            "TSL signing time is in the future".to_string(),
        ));
    }
    let doc_signed = verified.references.iter().any(|r| {
        fetch::is_whole_document_reference(&r.uri, root_id)
            && r.transforms
                .iter()
                .any(|t| matches!(t, Transform::EnvelopedSignature))
    });
    if !doc_signed {
        return Err(FetchError::InvalidSignature(
            "TSL signature does not cover the whole document".to_string(),
        ));
    }
    if !verified
        .references
        .iter()
        .any(|r| r.r#type.as_deref() == Some(SIGNED_PROPERTIES_TYPE))
    {
        return Err(FetchError::InvalidSignature(
            "TSL signature does not cover the SignedProperties".to_string(),
        ));
    }
    // TS 119 612 Annex B.1.0 mandates exclusive C14N for the trusted-list
    // signature, but the deployed EUDI lists are signed with inclusive C14N. We
    // accept the deviation (so the real lists resolve) but surface it.
    if verified.canonicalization_method != EXC_C14N {
        tracing::warn!(
            canonicalization = %verified.canonicalization_method,
            "TSL uses non-exclusive XML canonicalization; TS 119 612 Annex B.1.0 mandates \
             exclusive C14N ({EXC_C14N}). Accepting to interoperate with the deployed EUDI lists."
        );
    }
    Ok(())
}

/// Resolution options of an [`EtsiLotlResolver`].
#[derive(Clone, Debug)]
pub struct EtsiLotlResolverOptions {
    /// Root LoTL signer anchors (PEM), e.g. the OJEU-published LoTL signing certificates.
    pub trust_anchors: Vec<String>,
    /// Accept the root LoTL on its embedded signer when `trust_anchors` is empty.
    pub allow_unpinned_root: bool,
    pub leeway: time::Duration,
    pub limits: FetchLimits,
}

/// One authenticated member TSL.
pub struct CollectedTsl {
    pub url: String,
    pub next_update: OffsetDateTime,
    pub tsl: TrustServiceStatusList,
}

/// A LoTL, its authenticated member TSLs, the non-TSL pointers left to delegates, and the members
/// that could not be used.
pub struct LotlCollection {
    pub sequence_number: u64,
    pub issued_at: OffsetDateTime,
    pub next_update: OffsetDateTime,
    pub members: Vec<CollectedTsl>,
    pub delegated: Vec<DelegatedMember>,
    pub skipped: Vec<SkippedMember>,
    pub unpinned: bool,
    /// Pointers counted against `max_pointers`, delegated members included.
    pub followed: usize,
}

pub struct EtsiLotlResolver {
    clock: Arc<dyn Clock>,
    client: Arc<dyn HttpClient>,
    certificate_validator: Arc<dyn CertificateValidator>,
    xades_proto: Arc<dyn XAdESProto>,
    options: EtsiLotlResolverOptions,
}

impl EtsiLotlResolver {
    pub fn new(
        clock: Arc<dyn Clock>,
        client: Arc<dyn HttpClient>,
        certificate_validator: Arc<dyn CertificateValidator>,
        xades_proto: Arc<dyn XAdESProto>,
        options: EtsiLotlResolverOptions,
    ) -> Self {
        Self {
            clock,
            client,
            certificate_validator,
            xades_proto,
            options,
        }
    }

    /// Cache scope of this resolver, so lists resolved under other limits never share an entry.
    pub fn cache_scope(&self) -> String {
        format!("lotl;{}", self.options.limits.scope())
    }

    /// The pin the root LoTL is authenticated under.
    pub fn root_pin(&self) -> Result<SignerPin, FetchError> {
        SignerPin::for_root(
            &self.options.trust_anchors,
            self.options.allow_unpinned_root,
        )
    }

    /// Fetch the TSL at `url`, verify its signature under `pin`, check freshness.
    async fn fetch_and_verify(
        &self,
        url: &str,
        pin: &SignerPin,
    ) -> Result<(TrustServiceStatusList, OffsetDateTime), FetchError> {
        let document = fetch::fetch_document(
            self.client.as_ref(),
            url,
            &TSL_XML_MEDIA_TYPES.join(", "),
            &self.options.limits,
        )
        .await?;
        match document.content_type.as_deref() {
            Some(received) if TSL_XML_MEDIA_TYPES.contains(&received) => {}
            Some(received) => {
                return Err(FetchError::InvalidDocument(format!(
                    "unexpected content type `{received}`"
                )));
            }
            None => {
                return Err(FetchError::InvalidDocument(
                    "header Content-Type not present".to_string(),
                ));
            }
        }
        let body = str::from_utf8(&document.body)
            .map_err(|e| FetchError::InvalidDocument(e.to_string()))?;
        let parsed = roxmltree::Document::parse(body)
            .map_err(|e| FetchError::InvalidDocument(e.to_string()))?;
        if !fetch::xml_has_next_update(&parsed) {
            return Err(FetchError::Closed);
        }

        let signed = XAdESSignedXML::<TrustServiceStatusList>::decompose_document(body)
            .map_err(fetch::classify_xades)?;
        let verified = self
            .xades_proto
            .verify_enveloped_signature(signed.envelope())
            .await
            .map_err(fetch::classify_xades)?;
        assert_tsl_signature_policy(
            &verified,
            fetch::root_id(&parsed),
            self.options.leeway,
            self.clock.now_utc(),
        )?;
        fetch::verify_signer(
            self.certificate_validator.as_ref(),
            &verified.signer_chain_pem,
            pin,
        )
        .await?;

        let tsl = signed.content;
        let next_update = tsl
            .scheme_information
            .next_update
            .date_time
            .ok_or(FetchError::Closed)?;
        if next_update + self.options.leeway < self.clock.now_utc() {
            return Err(FetchError::Expired);
        }
        Ok((tsl, next_update))
    }

    /// Fetch the LoTL under `pin` and each member TSL pinned to its pointer's certificates.
    /// Single level: members' own pointers are not followed. Only the root failing fails.
    /// Each document is bounded by [FetchLimits::document_timeout] and the whole collection by
    /// [FetchLimits::deadline]: the root over either fails, a member is skipped.
    pub async fn collect(&self, url: &str, pin: &SignerPin) -> Result<LotlCollection, FetchError> {
        let limits = &self.options.limits;
        let deadline = Deadline::after(limits);
        let (lotl, next_update) = deadline
            .bound(limits, self.fetch_and_verify(url, pin))
            .await?;
        if lotl.scheme_information.tsl_type != TslType::ListOfLists {
            return Err(FetchError::InvalidDocument(format!(
                "expected {}, got {}",
                TslType::ListOfLists,
                lotl.scheme_information.tsl_type
            )));
        }

        let mut collection = LotlCollection {
            sequence_number: lotl.scheme_information.tsl_sequence_number,
            issued_at: lotl.scheme_information.list_issue_date_time,
            next_update,
            members: vec![],
            delegated: vec![],
            skipped: vec![],
            unpinned: pin.is_unpinned(),
            followed: 0,
        };
        let pointers = lotl
            .scheme_information
            .pointers_to_other_tsl
            .map(|p| p.pointers)
            .unwrap_or_default();

        for pointer in pointers {
            let kind = classify_pointer(&pointer);
            if kind == PointerKind::Skip {
                tracing::debug!(url = %pointer.tsl_location, "skipping non-followed pointer");
                continue;
            }
            let location = pointer.tsl_location.clone();
            if collection.followed >= self.options.limits.max_pointers {
                collection.skipped.push(SkippedMember {
                    url: location,
                    reason: SkipReason::PointerLimit,
                });
                continue;
            }
            collection.followed += 1;
            if let Err(error) = fetch::check_pointer_url(&location, &self.options.limits) {
                tracing::warn!(url = %location, %error, "skipping LoTL pointer");
                collection.skipped.push(error.skipped(&location));
                continue;
            }
            // no pointer certificate → the member cannot be authenticated
            let signer_pems = pointer_signer_cert_pems(&pointer);
            if signer_pems.is_empty() {
                tracing::warn!(url = %location, "skipping pointer with no signing identity");
                collection.skipped.push(SkippedMember {
                    url: location,
                    reason: SkipReason::SignerMismatch,
                });
                continue;
            }

            if kind == PointerKind::Delegate {
                // resolved by a delegate subscriber, pinned to these certificates and type
                collection.delegated.push(DelegatedMember {
                    url: location,
                    signer_pems,
                    declared_type: pointer_tsl_type(&pointer),
                    mime_type: pointer_mime_type(&pointer),
                });
                continue;
            }

            let member_pin = SignerPin::Pointer {
                pems: signer_pems,
                expected_type: None,
            };
            match deadline
                .bound(limits, self.fetch_and_verify(&location, &member_pin))
                .await
            {
                Ok((member, _))
                    if !matches!(
                        member.scheme_information.tsl_type,
                        TslType::Generic | TslType::CcList
                    ) =>
                {
                    tracing::warn!(
                        url = %location,
                        tsl_type = %member.scheme_information.tsl_type,
                        "skipping member list with unexpected TSLType",
                    );
                    collection.skipped.push(SkippedMember {
                        url: location,
                        reason: SkipReason::InvalidDocument,
                    });
                }
                Ok((tsl, next_update)) => collection.members.push(CollectedTsl {
                    url: location,
                    next_update,
                    tsl,
                }),
                Err(error) => {
                    tracing::warn!(url = %location, %error, "skipping member list that failed to fetch/verify");
                    collection.skipped.push(error.skipped(&location));
                }
            }
        }
        Ok(collection)
    }

    /// Collect under `pin` and build the cached lookup index.
    pub(crate) async fn resolve_pinned(
        &self,
        url: &str,
        pin: &SignerPin,
    ) -> Result<ResolveResult, ResolverError> {
        let collection = self.collect(url, pin).await?;
        let earliest_next_update = collection
            .members
            .iter()
            .map(|member| member.next_update)
            .fold(collection.next_update, OffsetDateTime::min);

        let services = collection
            .members
            .into_iter()
            .flat_map(|member| member.tsl.trust_service_provider_list)
            .flat_map(|list| list.providers)
            .flat_map(|provider| provider.tsp_services.services)
            .collect();
        let mut index = preprocess_services(services, self.certificate_validator.as_ref())
            .await
            .error_while("preprocessing TSL services")?;
        index.delegated_members = collection.delegated;
        index.unpinned = collection.unpinned;

        Ok(ResolveResult::NewValue {
            content: serde_json::to_vec(&index)?,
            media_type: Some("application/json".to_string()),
            expiry_date: Some(earliest_next_update),
        })
    }
}

/// A resolution of one LoTL location under one pin; the cache key carries the pin.
pub(crate) struct PinnedLotlResolver {
    pub resolver: Arc<EtsiLotlResolver>,
    pub url: String,
    pub pin: SignerPin,
}

#[async_trait::async_trait]
impl Resolver for PinnedLotlResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        _key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        self.resolver.resolve_pinned(&self.url, &self.pin).await
    }
}

/// Whether the MIME is an XML TSL we can parse (absent counts as parseable).
fn is_parseable_tsl_xml(mime: Option<&str>) -> bool {
    match mime {
        None => true,
        Some(mime) => TSL_XML_MEDIA_TYPES.contains(&mime),
    }
}

/// Classify a LOTL pointer by its `TSLType`; non-612 types are delegated.
pub(crate) fn classify_pointer(pointer: &OtherTslPointer) -> PointerKind {
    let mime = pointer.additional_information.as_ref().and_then(|info| {
        info.other_information
            .iter()
            .find_map(|oi| oi.mime_type.as_deref())
    });
    let tsl_type = pointer.additional_information.as_ref().and_then(|info| {
        info.other_information
            .iter()
            .find_map(|oi| oi.tsl_type.as_ref())
    });

    match tsl_type {
        // member TSL: follow only a parseable XML representation (a PDF copy shares the TSLType)
        Some(TslType::Generic | TslType::CcList) if is_parseable_tsl_xml(mime) => {
            PointerKind::Member
        }
        Some(TslType::Generic | TslType::CcList) => PointerKind::Skip,
        // nested list-of-lists: not followed (the EU LOTL self-references)
        Some(TslType::ListOfLists | TslType::CcListOfLists) => PointerKind::Skip,
        Some(TslType::Other(_)) => PointerKind::Delegate,
        // no TSLType: a member only if the MIME is TSL XML, else delegate
        None => match mime {
            Some(mime) if TSL_XML_MEDIA_TYPES.contains(&mime) => PointerKind::Member,
            _ => PointerKind::Delegate,
        },
    }
}

/// The media type a pointer declares.
fn pointer_mime_type(pointer: &OtherTslPointer) -> Option<String> {
    pointer.additional_information.as_ref().and_then(|info| {
        info.other_information
            .iter()
            .find_map(|oi| oi.mime_type.clone())
    })
}

/// The `TSLType` a pointer declares, as its URI.
fn pointer_tsl_type(pointer: &OtherTslPointer) -> Option<String> {
    pointer.additional_information.as_ref().and_then(|info| {
        info.other_information
            .iter()
            .find_map(|oi| oi.tsl_type.as_ref().map(ToString::to_string))
    })
}

/// PEMs of every X.509 certificate in the pointer's `ServiceDigitalIdentities`; all are
/// eligible signers, so a member signed during key rollover still authenticates.
pub(crate) fn pointer_signer_cert_pems(pointer: &OtherTslPointer) -> Vec<String> {
    pointer
        .service_digital_identities
        .identities
        .iter()
        .flat_map(|identity| &identity.digital_ids)
        .filter_map(|id| id.x509_certificate.as_ref())
        .filter_map(|cert_b64| {
            crate::mapper::x509::x5c_into_pem_chain(std::slice::from_ref(cert_b64)).ok()
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod test;
