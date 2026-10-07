//! Fetching, signer pinning and limits shared by the ETSI trust-list resolvers.
//!
//! Fork addition (not upstream): every list is authenticated under an explicit [`SignerPin`], and
//! cached content is keyed by the list location *and* that pin, so a list accepted under a weaker
//! policy is never served to a stricter one.

use std::time::Duration as StdDuration;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::mapper::x509::{get_akis_for_pem_chain, pem_to_subject_key_identifier};
use crate::proto::certificate_validator::{
    CertSelection, CertificateValidationOptions, CertificateValidator, EnforceKeyUsage,
};
use crate::proto::http_client::HttpClient;
use crate::proto::xades;
use crate::provider::caching_loader::ResolverError;

pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_POINTERS: usize = 256;
pub const DEFAULT_DEADLINE: StdDuration = StdDuration::from_secs(300);
pub const DEFAULT_DOCUMENT_TIMEOUT: StdDuration = StdDuration::from_secs(30);

/// How the signer of a fetched list is authenticated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignerPin {
    /// Root list: the signer must equal, or chain to, one of these PEM anchors.
    Anchors { pems: Vec<String> },
    /// Member list: the signer must equal one of the certificates its pointer names, and the
    /// list must be of the type the pointer declares (when it declares one).
    Pointer {
        pems: Vec<String>,
        #[serde(default)]
        expected_type: Option<String>,
    },
    /// Root list accepted on its own embedded signer. Only when explicitly allowed.
    Unpinned,
}

impl SignerPin {
    /// Root pin from configuration: anchors when given, otherwise `Unpinned` only if allowed.
    pub fn for_root(anchors: &[String], allow_unpinned_root: bool) -> Result<Self, FetchError> {
        match (anchors.is_empty(), allow_unpinned_root) {
            (false, _) => Ok(Self::Anchors {
                pems: anchors.to_vec(),
            }),
            (true, true) => Ok(Self::Unpinned),
            (true, false) => Err(FetchError::UnpinnedNotAllowed),
        }
    }

    pub fn is_unpinned(&self) -> bool {
        matches!(self, Self::Unpinned)
    }

    /// Cache key binding `url` to this pin and to the resolving subscriber's `scope` (its kind,
    /// content type and limits), so no two policies share an entry.
    pub(crate) fn cache_key(&self, url: &str, scope: &str) -> Result<String, FetchError> {
        let policy = serde_json::to_vec(&(scope, self))
            .map_err(|e| FetchError::InvalidDocument(e.to_string()))?;
        let digest = SHA256
            .hash(&policy)
            .map_err(|e| FetchError::InvalidDocument(e.to_string()))?;
        Ok(format!("{url}#pin={}", hex::encode(digest)))
    }
}

/// Bounds on a single export or resolution.
#[derive(Clone, Debug)]
pub struct FetchLimits {
    /// Maximum size of any fetched document.
    pub max_document_bytes: usize,
    /// Maximum number of pointers followed in total.
    pub max_pointers: usize,
    /// Accept `http` pointers (tests only); otherwise pointers must be `https`.
    pub allow_http: bool,
    /// Deadline for the whole export or resolution. The root not authenticated within it fails;
    /// members not reached or not done within it are skipped with [SkipReason::Deadline].
    pub deadline: StdDuration,
    /// Time to fetch and authenticate one member list, so one slow host cannot spend the whole
    /// deadline; a member over it is skipped as [SkipReason::Unreachable]. The root is bounded by
    /// the deadline only.
    pub document_timeout: StdDuration,
}

impl FetchLimits {
    /// The limits as part of a cache scope.
    pub(crate) fn scope(&self) -> String {
        format!(
            "bytes={};pointers={};http={};deadline={};document_timeout={}",
            self.max_document_bytes,
            self.max_pointers,
            self.allow_http,
            self.deadline.as_secs(),
            self.document_timeout.as_secs()
        )
    }
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
            max_pointers: DEFAULT_MAX_POINTERS,
            allow_http: false,
            deadline: DEFAULT_DEADLINE,
            document_timeout: DEFAULT_DOCUMENT_TIMEOUT,
        }
    }
}

/// When an export or resolution has to end, from [FetchLimits::deadline].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline(tokio::time::Instant);

impl Deadline {
    pub(crate) fn after(limits: &FetchLimits) -> Self {
        Self(tokio::time::Instant::now() + limits.deadline)
    }

    /// Run `work` on one document for at most [FetchLimits::document_timeout], and never past
    /// the deadline: [FetchError::Unreachable] when the document took too long,
    /// [FetchError::Deadline] when the deadline did.
    pub(crate) async fn bound<T>(
        &self,
        limits: &FetchLimits,
        work: impl Future<Output = Result<T, FetchError>>,
    ) -> Result<T, FetchError> {
        let remaining = self
            .0
            .saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(FetchError::Deadline);
        }
        if limits.document_timeout < remaining {
            return tokio::time::timeout(limits.document_timeout, work)
                .await
                .map_err(|_| {
                    FetchError::Unreachable(format!(
                        "not fetched and authenticated within {} s",
                        limits.document_timeout.as_secs()
                    ))
                })?;
        }
        tokio::time::timeout(remaining, work)
            .await
            .map_err(|_| FetchError::Deadline)?
    }

    /// Run `work` on the root list until the deadline. The per-document timeout isolates
    /// members from each other; a root has nothing to be isolated from, and a large one (the EU
    /// LoTL, with its signer's CRL) may need longer.
    pub(crate) async fn bound_root<T>(
        &self,
        work: impl Future<Output = Result<T, FetchError>>,
    ) -> Result<T, FetchError> {
        let remaining = self
            .0
            .saturating_duration_since(tokio::time::Instant::now());
        tokio::time::timeout(remaining, work)
            .await
            .map_err(|_| FetchError::Deadline)?
    }
}

/// Why a member list was not used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SkipReason {
    SignerMismatch,
    InvalidSignature,
    UnsupportedAlgorithm,
    Expired,
    Closed,
    Unreachable,
    InvalidDocument,
    SizeLimit,
    PointerLimit,
    /// Not reached, or not done, within the export's deadline.
    Deadline,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedMember {
    pub url: String,
    pub reason: SkipReason,
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("Trust list unreachable: {0}")]
    Unreachable(String),
    #[error("Trust list exceeds the maximum size of {0} bytes")]
    SizeLimit(usize),
    #[error("Trust list pointer refused: {0}")]
    PointerLimit(String),
    #[error("Invalid trust list document: {0}")]
    InvalidDocument(String),
    #[error("Invalid trust list signature: {0}")]
    InvalidSignature(String),
    #[error("Unsupported trust list signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Trust list signer not trusted")]
    SignerNotTrusted,
    #[error("Trust list expired")]
    Expired,
    #[error("Trust list closed (no NextUpdate)")]
    Closed,
    #[error("Unpinned root trust list not allowed")]
    UnpinnedNotAllowed,
    #[error("Trust list export deadline exceeded")]
    Deadline,
}

impl FetchError {
    pub fn skip_reason(&self) -> SkipReason {
        match self {
            Self::Unreachable(_) => SkipReason::Unreachable,
            Self::Deadline => SkipReason::Deadline,
            Self::SizeLimit(_) => SkipReason::SizeLimit,
            Self::PointerLimit(_) => SkipReason::PointerLimit,
            Self::InvalidDocument(_) => SkipReason::InvalidDocument,
            Self::InvalidSignature(_) => SkipReason::InvalidSignature,
            Self::UnsupportedAlgorithm(_) => SkipReason::UnsupportedAlgorithm,
            Self::SignerNotTrusted | Self::UnpinnedNotAllowed => SkipReason::SignerMismatch,
            Self::Expired => SkipReason::Expired,
            Self::Closed => SkipReason::Closed,
        }
    }

    pub(crate) fn skipped(&self, url: &str) -> SkippedMember {
        SkippedMember {
            url: url.to_string(),
            reason: self.skip_reason(),
        }
    }
}

impl ErrorCodeMixin for FetchError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::SignerNotTrusted | Self::InvalidSignature(_) | Self::UnpinnedNotAllowed => {
                ErrorCode::BR_0410
            }
            _ => ErrorCode::BR_0354,
        }
    }
}

impl From<FetchError> for ResolverError {
    fn from(error: FetchError) -> Self {
        ResolverError::InvalidResponse(error.to_string())
    }
}

/// Classify an XAdES verification failure.
pub(crate) fn classify_xades(error: xades::error::Error) -> FetchError {
    use xades::error::Error;
    match error {
        Error::UnsupportedSuite(_) | Error::KeyAlgorithm(_) => {
            FetchError::UnsupportedAlgorithm(error.to_string())
        }
        Error::InvalidDocument(_)
        | Error::MissingEnvelopedSignature
        | Error::RoXMLParsing(_)
        | Error::SerdeDe(_)
        | Error::Base64Encoding(_)
        | Error::C14n(_) => FetchError::InvalidDocument(error.to_string()),
        _ => FetchError::InvalidSignature(error.to_string()),
    }
}

/// The media type of a `Content-Type` value, without parameters, lower-cased.
pub(crate) fn media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Refuse a pointer location that is not `https` (or `http` when allowed).
pub(crate) fn check_pointer_url(url: &str, limits: &FetchLimits) -> Result<(), FetchError> {
    let parsed = Url::parse(url).map_err(|e| FetchError::PointerLimit(e.to_string()))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if limits.allow_http => Ok(()),
        scheme => Err(FetchError::PointerLimit(format!(
            "scheme `{scheme}` not allowed"
        ))),
    }
}

pub(crate) struct FetchedDocument {
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

/// Download a list, enforcing the size limit.
pub(crate) async fn fetch_document(
    client: &dyn HttpClient,
    url: &str,
    accept: &str,
    limits: &FetchLimits,
) -> Result<FetchedDocument, FetchError> {
    let response = client
        .get(url)
        .header("Accept", accept)
        // members are cut off sooner by `Deadline::bound`
        .timeout(time::Duration::try_from(limits.deadline).unwrap_or(time::Duration::MAX))
        .send()
        .await
        .and_then(|response| response.error_for_status())
        .map_err(|e| FetchError::Unreachable(e.to_string()))?;

    if let Some(length) = response
        .header_get("Content-Length")
        .and_then(|value| value.trim().parse::<usize>().ok())
        && length > limits.max_document_bytes
    {
        return Err(FetchError::SizeLimit(limits.max_document_bytes));
    }
    if response.body.len() > limits.max_document_bytes {
        return Err(FetchError::SizeLimit(limits.max_document_bytes));
    }
    let content_type = response.header_get("Content-Type").map(|v| media_type(v));
    Ok(FetchedDocument {
        body: response.body,
        content_type,
    })
}

/// Authenticate the signer of a list (`signer_chain_pem`, leaf first) under `pin`.
pub(crate) async fn verify_signer(
    certificate_validator: &dyn CertificateValidator,
    signer_chain_pem: &str,
    pin: &SignerPin,
) -> Result<(), FetchError> {
    let pems = match pin {
        SignerPin::Unpinned => return Ok(()),
        SignerPin::Anchors { pems } | SignerPin::Pointer { pems, .. } => pems,
    };
    let signer_fingerprint = fingerprint_of(certificate_validator, signer_chain_pem)
        .await
        .ok_or(FetchError::SignerNotTrusted)?;
    for pem in pems {
        if fingerprint_of(certificate_validator, pem).await.as_deref()
            == Some(signer_fingerprint.as_str())
        {
            return Ok(());
        }
    }
    // a root may also be signed by a signing certificate issued under a configured anchor
    if let SignerPin::Anchors { pems } = pin {
        let chain_akis = get_akis_for_pem_chain(signer_chain_pem.as_bytes()).unwrap_or_default();
        for anchor in pems {
            // only anchors the chain names as an issuer are candidates
            if let Ok(Some(anchor_ski)) = pem_to_subject_key_identifier(anchor)
                && !chain_akis.contains(&anchor_ski)
            {
                continue;
            }
            if certificate_validator
                .validate_chain_against_ca_chain(
                    signer_chain_pem,
                    anchor,
                    CertificateValidationOptions::signature_and_revocation_below_anchor(Some(
                        vec![EnforceKeyUsage::DigitalSignature],
                    )),
                    CertSelection::Leaf,
                )
                .await
                .is_ok()
            {
                return Ok(());
            }
        }
    }
    Err(FetchError::SignerNotTrusted)
}

async fn fingerprint_of(
    certificate_validator: &dyn CertificateValidator,
    pem: &str,
) -> Option<String> {
    certificate_validator
        .parse_pem_chain(pem, CertificateValidationOptions::no_validation())
        .await
        .ok()
        .map(|parsed| parsed.attributes.fingerprint)
}

/// The LoTE of a JSON LoTE payload: the published EU lists wrap it in a `LoTE` member, upstream
/// and earlier drafts put it at the root. A `LoTE` member wins over root fields.
pub(crate) fn json_lote_object(
    payload: &serde_json::Value,
) -> Result<&serde_json::Value, FetchError> {
    match payload.get("LoTE") {
        None => Ok(payload),
        Some(lote) if lote.is_object() => Ok(lote),
        Some(_) => Err(FetchError::InvalidDocument(
            "`LoTE` is not an object".to_string(),
        )),
    }
}

/// Whether a LoTE (JSON, see [json_lote_object]) carries a `NextUpdate`; a list without one is
/// closed.
pub(crate) fn json_lote_has_next_update(lote: &serde_json::Value) -> bool {
    lote.pointer("/ListAndSchemeInformation/NextUpdate")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

/// The JSON payload of a compact JWS, without verifying it.
pub(crate) fn jws_payload(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = Base64UrlSafeNoPadding::decode_to_vec(payload, None).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Whether an XML list (TSL or LoTE) carries a non-empty `NextUpdate/dateTime`.
pub(crate) fn xml_has_next_update(document: &roxmltree::Document<'_>) -> bool {
    document
        .descendants()
        .filter(|node| node.tag_name().name() == "NextUpdate")
        .any(|node| {
            node.children().any(|child| {
                child.tag_name().name() == "dateTime"
                    && child.text().is_some_and(|text| !text.trim().is_empty())
            })
        })
}

/// The `Id` of the document element, used to accept a `#<Id>` whole-document reference.
pub(crate) fn root_id<'a>(document: &'a roxmltree::Document<'a>) -> Option<&'a str> {
    document.root_element().attribute("Id")
}

/// Whether a reference URI designates the whole document.
pub(crate) fn is_whole_document_reference(uri: &str, root_id: Option<&str>) -> bool {
    uri.is_empty()
        || root_id.is_some_and(|id| uri.strip_prefix('#').is_some_and(|fragment| fragment == id))
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn media_type_ignores_parameters() {
        assert_eq!(
            media_type("application/xml; charset=utf-8"),
            "application/xml"
        );
        assert_eq!(media_type(" Application/JWT "), "application/jwt");
    }

    #[test]
    fn root_pin_requires_anchors_unless_allowed() {
        assert!(matches!(
            SignerPin::for_root(&[], false),
            Err(FetchError::UnpinnedNotAllowed)
        ));
        assert_eq!(SignerPin::for_root(&[], true).unwrap(), SignerPin::Unpinned);
        assert!(matches!(
            SignerPin::for_root(&["pem".to_string()], false).unwrap(),
            SignerPin::Anchors { .. }
        ));
    }

    #[test]
    fn cache_key_differs_per_pin() {
        let pinned = SignerPin::Anchors {
            pems: vec!["a".to_string()],
        };
        let other = SignerPin::Anchors {
            pems: vec!["b".to_string()],
        };
        let url = "https://example.com/lote";
        let key = |pin: &SignerPin, scope: &str| pin.cache_key(url, scope).unwrap();
        assert_ne!(key(&pinned, "lote"), key(&SignerPin::Unpinned, "lote"));
        assert_ne!(key(&pinned, "lote"), key(&other, "lote"));
        assert_eq!(key(&pinned, "lote"), key(&pinned, "lote"));
        // another subscriber kind or limit set never shares the entry
        assert_ne!(key(&pinned, "lote"), key(&pinned, "lotl"));
    }

    #[test]
    fn pointer_scheme_is_restricted() {
        let limits = FetchLimits::default();
        assert!(check_pointer_url("https://example.com/tl.xml", &limits).is_ok());
        assert!(matches!(
            check_pointer_url("http://example.com/tl.xml", &limits),
            Err(FetchError::PointerLimit(_))
        ));
        let allow_http = FetchLimits {
            allow_http: true,
            ..Default::default()
        };
        assert!(check_pointer_url("http://example.com/tl.xml", &allow_http).is_ok());
    }

    #[test]
    fn whole_document_reference() {
        assert!(is_whole_document_reference("", None));
        assert!(is_whole_document_reference("#TSL", Some("TSL")));
        assert!(!is_whole_document_reference("#Other", Some("TSL")));
        assert!(!is_whole_document_reference("#TSL", None));
    }

    #[test]
    fn closed_xml_list_is_detected() {
        let open = roxmltree::Document::parse(
            "<L><NextUpdate><dateTime>2026-01-01T00:00:00Z</dateTime></NextUpdate></L>",
        )
        .unwrap();
        let closed = roxmltree::Document::parse("<L><NextUpdate/></L>").unwrap();
        assert!(xml_has_next_update(&open));
        assert!(!xml_has_next_update(&closed));
    }

    #[test]
    fn closed_json_lote_is_detected() {
        let open =
            serde_json::json!({"ListAndSchemeInformation": {"NextUpdate": "2026-01-01T00:00:00Z"}});
        let closed = serde_json::json!({"ListAndSchemeInformation": {}});
        assert!(json_lote_has_next_update(&open));
        assert!(!json_lote_has_next_update(&closed));
    }

    #[test]
    fn the_lote_member_wins_over_root_fields() {
        let open =
            serde_json::json!({"ListAndSchemeInformation": {"NextUpdate": "2026-01-01T00:00:00Z"}});
        let wrapped_open = serde_json::json!({ "LoTE": open });
        let wrapped_closed = serde_json::json!({ "LoTE": {"ListAndSchemeInformation": {}}, "ListAndSchemeInformation": open["ListAndSchemeInformation"] });

        assert!(json_lote_has_next_update(
            json_lote_object(&wrapped_open).unwrap()
        ));
        assert!(!json_lote_has_next_update(
            json_lote_object(&wrapped_closed).unwrap()
        ));
        assert!(matches!(
            json_lote_object(&serde_json::json!({"LoTE": "list"})),
            Err(FetchError::InvalidDocument(_))
        ));
    }

    fn limits(deadline: u64, document_timeout: u64) -> FetchLimits {
        FetchLimits {
            deadline: StdDuration::from_secs(deadline),
            document_timeout: StdDuration::from_secs(document_timeout),
            ..Default::default()
        }
    }

    async fn never() -> Result<(), FetchError> {
        std::future::pending().await
    }

    #[tokio::test(start_paused = true)]
    async fn document_over_its_timeout_is_unreachable() {
        let limits = limits(300, 30);

        let result = Deadline::after(&limits).bound(&limits, never()).await;

        assert!(
            matches!(result, Err(FetchError::Unreachable(_))),
            "{result:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn document_running_into_the_deadline_is_cut_off_by_it() {
        let limits = limits(10, 30);

        let started = tokio::time::Instant::now();
        let result = Deadline::after(&limits).bound(&limits, never()).await;

        assert!(matches!(result, Err(FetchError::Deadline)), "{result:?}");
        assert_eq!(started.elapsed(), StdDuration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn document_after_the_deadline_is_not_started() {
        let limits = limits(10, 30);
        let deadline = Deadline::after(&limits);
        tokio::time::advance(StdDuration::from_secs(10)).await;

        let result = deadline
            .bound(&limits, async { panic!("started after the deadline") })
            .await;

        assert!(matches!(result, Err::<(), _>(FetchError::Deadline)));
    }

    #[test]
    fn deadline_and_unreachable_are_distinct_skip_reasons() {
        assert_eq!(FetchError::Deadline.skip_reason(), SkipReason::Deadline);
        assert_eq!(
            FetchError::Unreachable(String::new()).skip_reason(),
            SkipReason::Unreachable
        );
    }

    /// The capped client against a real server: the ETSI media types go out as asked, the body
    /// is cut one byte past the limit, and the size check refuses it.
    #[tokio::test]
    async fn capped_client_reads_one_byte_past_the_limit_and_the_document_is_refused() {
        use wiremock::matchers::{headers, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::proto::http_client::StatusCode;
        use crate::proto::http_client::reqwest_client::ReqwestClient;

        const ACCEPT: &str = "application/vnd.etsi.tsl+xml, application/xml, text/xml";
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/tl.xml"))
            .and(headers(
                "Accept",
                vec![
                    "application/vnd.etsi.tsl+xml",
                    "application/xml",
                    "text/xml",
                ],
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Content-Type", "application/vnd.etsi.tsl+xml")
                    .set_body_bytes(vec![b'x'; 10_000]),
            )
            .mount(&server)
            .await;
        let url = format!("{}/tl.xml", server.uri());
        let client = ReqwestClient::new(reqwest::Client::new()).with_max_body_bytes(100);

        let response = client
            .get(&url)
            .header("Accept", ACCEPT)
            .send()
            .await
            .unwrap();
        let fetched = fetch_document(
            &client,
            &url,
            ACCEPT,
            &FetchLimits {
                max_document_bytes: 100,
                ..Default::default()
            },
        )
        .await;

        assert_eq!(response.status, StatusCode(200));
        assert_eq!(response.body.len(), 101);
        assert!(
            matches!(fetched, Err(FetchError::SizeLimit(100))),
            "{:?}",
            fetched.err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn root_may_take_longer_than_a_member_but_not_the_deadline() {
        let limits = limits(300, 30);
        let deadline = Deadline::after(&limits);

        let slow = deadline
            .bound_root(async {
                tokio::time::sleep(StdDuration::from_secs(60)).await;
                Ok(())
            })
            .await;
        let never = deadline.bound_root(never()).await;

        assert!(slow.is_ok());
        assert!(matches!(never, Err(FetchError::Deadline)), "{never:?}");
    }
}
