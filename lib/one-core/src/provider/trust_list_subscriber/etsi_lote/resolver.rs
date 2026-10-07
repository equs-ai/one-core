use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use standardized_types::etsi_119_602::json::OtherLoTEPointer;
use standardized_types::etsi_119_602::{json, xml};
use standardized_types::xades::SIGNED_PROPERTIES_TYPE;
use time::OffsetDateTime;

use super::LoteContentType;
use super::preprocessing::{merge_lote, preprocess_lote};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::did::KeyRole;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::clock::Clock;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::key_verification::KeyVerification;
use crate::proto::xades::{XAdESProto, XAdESSignedXML, XAdESVerified};
use crate::provider::caching_loader::{ResolveResult, Resolver, ResolverError};
use crate::provider::credential_formatter::model::PublicKeySource;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::trust_list_subscriber::fetch::{
    self, FetchError, FetchLimits, SignerPin, SkipReason, SkippedMember,
};

/// PEMs of every X.509 certificate a pointer names; all are eligible signers (key rollover).
pub(crate) fn pointer_signer_cert_pems(pointer: &OtherLoTEPointer) -> Vec<String> {
    pointer
        .service_digital_identities
        .iter()
        .filter_map(|identity| identity.x509_certificates.as_ref())
        .flatten()
        .filter_map(|pki| x5c_into_pem_chain(std::slice::from_ref(&pki.val)).ok())
        .collect()
}

fn assert_lote_signature_policy(
    verified: &XAdESVerified,
    leeway: time::Duration,
    now: OffsetDateTime,
) -> Result<(), FetchError> {
    if verified.signing_time > now + leeway {
        return Err(FetchError::InvalidSignature(
            "LoTE signing time is in the future".to_string(),
        ));
    }
    if !verified.references.iter().any(|r| r.uri.is_empty()) {
        return Err(FetchError::InvalidSignature(
            "LoTE signature does not cover the document".to_string(),
        ));
    }
    if !verified
        .references
        .iter()
        .any(|r| r.r#type.as_deref() == Some(SIGNED_PROPERTIES_TYPE))
    {
        return Err(FetchError::InvalidSignature(
            "LoTE signature does not cover the SignedProperties".to_string(),
        ));
    }
    Ok(())
}

/// Resolution options of an [`EtsiLoteResolver`].
#[derive(Clone, Debug)]
pub struct EtsiLoteResolverOptions {
    pub content_type: LoteContentType,
    pub leeway: time::Duration,
    /// Maximum `PointersToOtherLoTE` depth to follow; `None` = no limit.
    pub max_pointer_depth: Option<usize>,
    /// Root LoTE signer anchors (PEM).
    pub trust_anchors: Vec<String>,
    /// Accept a root LoTE on its embedded signer when `trust_anchors` is empty.
    pub allow_unpinned_root: bool,
    pub limits: FetchLimits,
}

/// One authenticated LoTE of a collection.
pub struct CollectedLote {
    pub url: String,
    pub payload: json::LoTEPayload,
}

/// A root LoTE and the pointed-to LoTEs that authenticated, plus the ones that did not.
pub struct LoteCollection {
    pub lists: Vec<CollectedLote>,
    pub skipped: Vec<SkippedMember>,
    pub unpinned: bool,
}

pub struct EtsiLoteResolver {
    clock: Arc<dyn Clock>,
    client: Arc<dyn HttpClient>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    xades_proto: Arc<dyn XAdESProto>,
    options: EtsiLoteResolverOptions,
}

impl EtsiLoteResolver {
    pub fn new(
        clock: Arc<dyn Clock>,
        client: Arc<dyn HttpClient>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        xades_proto: Arc<dyn XAdESProto>,
        options: EtsiLoteResolverOptions,
    ) -> Self {
        Self {
            clock,
            client,
            did_method_provider,
            key_algorithm_provider,
            certificate_validator,
            xades_proto,
            options,
        }
    }

    /// The pin a root LoTE fetched directly is authenticated under.
    pub fn root_pin(&self) -> Result<SignerPin, FetchError> {
        SignerPin::for_root(
            &self.options.trust_anchors,
            self.options.allow_unpinned_root,
        )
    }

    /// Fetch a LoTE from `url`, verify its signature under `pin`, and check freshness.
    async fn fetch_and_verify(
        &self,
        url: &str,
        pin: &SignerPin,
    ) -> Result<json::LoTEPayload, FetchError> {
        let content_type = self.options.content_type.to_string();
        let document = fetch::fetch_document(
            self.client.as_ref(),
            url,
            &content_type,
            &self.options.limits,
        )
        .await?;
        match document.content_type.as_deref() {
            Some(received) if received == content_type => {}
            Some(received) => {
                return Err(FetchError::InvalidDocument(format!(
                    "unexpected content type `{received}`, expected `{content_type}`"
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

        let (lote, signer_pem) = match self.options.content_type {
            LoteContentType::Jwt => self.verify_jwt(body).await?,
            LoteContentType::Xml => self.verify_xml(body).await?,
        };

        fetch::verify_signer(self.certificate_validator.as_ref(), &signer_pem, pin).await?;

        if lote.list_and_scheme_information.next_update + self.options.leeway < self.clock.now_utc()
        {
            return Err(FetchError::Expired);
        }
        Ok(lote)
    }

    async fn verify_jwt(&self, body: &str) -> Result<(json::LoTEPayload, String), FetchError> {
        if !fetch::jws_payload(body)
            .is_some_and(|payload| fetch::json_lote_has_next_update(&payload))
        {
            return Err(FetchError::Closed);
        }
        let decomposed_token = Jwt::<json::LoTEPayload>::decompose_token(body)
            .map_err(|e| FetchError::InvalidDocument(e.to_string()))?;
        let x5c =
            decomposed_token.header.x5c.as_ref().ok_or_else(|| {
                FetchError::InvalidDocument("missing x5c header claim".to_string())
            })?;
        let signer_pem =
            x5c_into_pem_chain(x5c).map_err(|e| FetchError::InvalidDocument(e.to_string()))?;

        let verification = KeyVerification {
            did_method_provider: self.did_method_provider.clone(),
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            certificate_validator: self.certificate_validator.clone(),
            key_role: KeyRole::AssertionMethod,
        };
        decomposed_token
            .verify_signature(PublicKeySource::X5c { x5c }, &verification)
            .await
            .map_err(|e| FetchError::InvalidSignature(e.to_string()))?;
        Ok((decomposed_token.payload.custom, signer_pem))
    }

    async fn verify_xml(&self, body: &str) -> Result<(json::LoTEPayload, String), FetchError> {
        let document = roxmltree::Document::parse(body)
            .map_err(|e| FetchError::InvalidDocument(e.to_string()))?;
        if !fetch::xml_has_next_update(&document) {
            return Err(FetchError::Closed);
        }
        let signed_xml = XAdESSignedXML::<xml::LoTEPayload>::decompose_document(body)
            .map_err(fetch::classify_xades)?;
        let verified = self
            .xades_proto
            .verify_enveloped_signature(signed_xml.envelope())
            .await
            .map_err(fetch::classify_xades)?;
        assert_lote_signature_policy(&verified, self.options.leeway, self.clock.now_utc())?;
        Ok((signed_xml.content.into(), verified.signer_chain_pem))
    }

    /// Fetch the root LoTE under `pin` and follow its `PointersToOtherLoTE` breadth-first, each
    /// pinned to its pointer's certificates. Only the root failing fails the collection.
    pub async fn collect(&self, url: &str, pin: &SignerPin) -> Result<LoteCollection, FetchError> {
        tokio::time::timeout(self.options.limits.deadline, self.collect_inner(url, pin))
            .await
            .map_err(|_| FetchError::Deadline)?
    }

    async fn collect_inner(
        &self,
        url: &str,
        pin: &SignerPin,
    ) -> Result<LoteCollection, FetchError> {
        let mut root = self.fetch_and_verify(url, pin).await?;
        let mut queue: VecDeque<(OtherLoTEPointer, usize)> = root
            .list_and_scheme_information
            .pointers_to_other_lote
            .take()
            .unwrap_or_default()
            .into_iter()
            .map(|pointer| (pointer, 1))
            .collect();

        let mut collection = LoteCollection {
            lists: vec![CollectedLote {
                url: url.to_string(),
                payload: root,
            }],
            skipped: vec![],
            unpinned: pin.is_unpinned(),
        };
        let mut visited = HashSet::from([url.to_string()]);
        let mut followed = 0usize;

        while let Some((pointer, depth)) = queue.pop_front() {
            let location = pointer.lote_location.clone();
            if !visited.insert(location.clone()) {
                continue;
            }
            if self
                .options
                .max_pointer_depth
                .is_some_and(|max| depth > max)
                || followed >= self.options.limits.max_pointers
            {
                tracing::warn!(url = %location, "skipping LoTE pointer beyond the pointer limit");
                collection.skipped.push(SkippedMember {
                    url: location,
                    reason: SkipReason::PointerLimit,
                });
                continue;
            }
            followed += 1;
            if let Err(error) = fetch::check_pointer_url(&location, &self.options.limits) {
                tracing::warn!(url = %location, %error, "skipping LoTE pointer");
                collection.skipped.push(error.skipped(&location));
                continue;
            }
            let pointer_pems = pointer_signer_cert_pems(&pointer);
            if pointer_pems.is_empty() {
                tracing::warn!(url = %location, "skipping LoTE pointer with no signing identity");
                collection.skipped.push(SkippedMember {
                    url: location,
                    reason: SkipReason::SignerMismatch,
                });
                continue;
            }

            let mut child = match self
                .fetch_and_verify(&location, &SignerPin::Pointer { pems: pointer_pems })
                .await
            {
                Ok(child) => child,
                Err(error) => {
                    tracing::warn!(url = %location, %error, "skipping LoTE pointer that failed to fetch/verify");
                    collection.skipped.push(error.skipped(&location));
                    continue;
                }
            };
            for child_pointer in child
                .list_and_scheme_information
                .pointers_to_other_lote
                .take()
                .unwrap_or_default()
            {
                queue.push_back((child_pointer, depth + 1));
            }
            collection.lists.push(CollectedLote {
                url: location,
                payload: child,
            });
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
        let earliest_expiry = collection
            .lists
            .iter()
            .map(|list| list.payload.list_and_scheme_information.next_update)
            .min();

        let mut lists = collection.lists.into_iter();
        let root = lists.next().ok_or(ResolverError::UnexpectedResolveResult)?;
        let mut aggregate = preprocess_lote(
            root.payload,
            self.certificate_validator.as_ref(),
            self.key_algorithm_provider.as_ref(),
        )
        .await
        .error_while("preprocessing ETSI LoTE")?;
        aggregate.unpinned = collection.unpinned;

        for child in lists {
            match preprocess_lote(
                child.payload,
                self.certificate_validator.as_ref(),
                self.key_algorithm_provider.as_ref(),
            )
            .await
            {
                Ok(index) => merge_lote(&mut aggregate, index),
                Err(error) => {
                    tracing::warn!(url = %child.url, %error, "skipping LoTE pointer that failed to preprocess");
                }
            }
        }

        Ok(ResolveResult::NewValue {
            content: serde_json::to_vec(&aggregate)?,
            media_type: Some(self.options.content_type.to_string()),
            expiry_date: earliest_expiry,
        })
    }
}

/// A resolution request for one LoTE location under one pin; the cache key carries the pin.
pub(crate) struct PinnedLoteResolver {
    pub resolver: Arc<EtsiLoteResolver>,
    pub url: String,
    pub pin: SignerPin,
}

#[async_trait::async_trait]
impl Resolver for PinnedLoteResolver {
    type Error = ResolverError;

    async fn do_resolve(
        &self,
        _key: &str,
        _last_modified: Option<&OffsetDateTime>,
    ) -> Result<ResolveResult, Self::Error> {
        self.resolver.resolve_pinned(&self.url, &self.pin).await
    }
}
