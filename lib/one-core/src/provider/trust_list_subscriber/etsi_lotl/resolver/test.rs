//! Signer pinning, signature-scope, freshness and limit tests for the LoTL resolver.
//! XAdES verification is mocked; fingerprints are SHA-256 of the PEM text.

use std::sync::Arc;

use maplit::hashmap;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use similar_asserts::assert_eq;
use standardized_types::etsi_119_612::xml::TrustServiceStatusList;
use standardized_types::xades::{SIGNED_PROPERTIES_TYPE, Transform};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use super::{EtsiLotlResolver, EtsiLotlResolverOptions, pointer_signer_cert_pems};
use crate::proto::certificate_validator::{
    Error as CertValidatorError, MockCertificateValidator, ParsedCertificate,
};
use crate::proto::clock::{TaskLocalClock, run_with_mocked_time_async};
use crate::proto::http_client::{Method, MockHttpClient, Request, Response, StatusCode};
use crate::proto::xades::{MockXAdESProto, VerifiedReference, XAdESVerified};
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::trust_list_subscriber::fetch::{
    FetchError, FetchLimits, SignerPin, SkipReason,
};
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::util::test_utilities::mock_http_get_request;

pub(crate) const LOTL: &str =
    include_str!("../../../../../../standardized-types/tests/fixtures/eudiw_lotl.xml");
pub(crate) const MEMBER: &str =
    include_str!("../../../../../../standardized-types/tests/fixtures/eudiw_member_tsl.xml");
pub(crate) const LOTL_URL: &str = "https://trustedlist.eudiw.dev/tools/lotl/eu-lotl.xml";
pub(crate) const FR_URL: &str = "https://trustedlist.serviceproviders.eudiw.dev/TL/FR/01.xml";
pub(crate) const DE_URL: &str = "https://trustedlist.serviceproviders.eudiw.dev/TL/DE/01.xml";
pub(crate) const ROOT_SIGNER: &str = "ROOT SIGNER PEM";
const FOREIGN_SIGNER: &str = "FOREIGN SIGNER PEM";
pub(crate) const NOW: OffsetDateTime = datetime!(2026-10-01 00:00 UTC);

pub(crate) fn fingerprint(pem: &str) -> String {
    hex::encode(SHA256.hash(pem.as_bytes()).unwrap())
}

pub(crate) fn parsed(fingerprint: String) -> ParsedCertificate {
    ParsedCertificate {
        attributes: CertificateX509AttributesDTO {
            serial_number: "00".to_string(),
            not_before: datetime!(2025-01-01 00:00 UTC),
            not_after: datetime!(2030-01-01 00:00 UTC),
            issuer: "CN=Test".to_string(),
            subject: "CN=Test".to_string(),
            fingerprint,
            extensions: vec![],
        },
        subject_common_name: None,
        subject_key_identifier: None,
        public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
            MockSignaturePublicKeyHandle::new(),
        ))),
    }
}

/// Validator identifying a certificate by the hash of its PEM; no CA chaining.
pub(crate) fn validator() -> Arc<MockCertificateValidator> {
    let mut validator = MockCertificateValidator::new();
    validator
        .expect_parse_pem_chain()
        .returning(|pem, _| Ok(parsed(fingerprint(pem))));
    validator
        .expect_validate_chain_against_ca_chain()
        .returning(|_, _, _, _| Err(CertValidatorError::CertificateSignatureInvalid));
    Arc::new(validator)
}

pub(crate) fn whole_document_references() -> Vec<VerifiedReference> {
    vec![
        VerifiedReference {
            uri: "#TrustServiceStatusList".to_string(),
            r#type: None,
            transforms: vec![Transform::EnvelopedSignature],
        },
        VerifiedReference {
            uri: "#signed-properties".to_string(),
            r#type: Some(SIGNED_PROPERTIES_TYPE.to_string()),
            transforms: vec![],
        },
    ]
}

pub(crate) fn verified(signer: &str, references: Vec<VerifiedReference>) -> XAdESVerified {
    XAdESVerified {
        signer_chain_pem: signer.to_string(),
        signing_time: datetime!(2026-09-01 00:00 UTC),
        canonicalization_method: standardized_types::xades::EXC_C14N.to_string(),
        references,
    }
}

/// XAdES mock: the root LoTL is signed by `root_signer`, members by `member_signer`.
fn xades(
    root_signer: &'static str,
    root_references: Vec<VerifiedReference>,
    member_signer: Option<String>,
) -> MockXAdESProto {
    let mut xades = MockXAdESProto::new();
    xades
        .expect_verify_enveloped_signature()
        .returning(move |signed| {
            // the mock is generated over the `async_trait`-desugared signature
            let result = if signed.unverified_document.contains(FR_URL) {
                verified(root_signer, root_references.clone())
            } else {
                let signer = member_signer.clone().unwrap_or_else(fr_pointer_pem);
                verified(&signer, whole_document_references())
            };
            Box::pin(async move { Ok(result) })
        });
    xades
}

pub(crate) fn fr_pointer_pem() -> String {
    let lotl: TrustServiceStatusList = quick_xml::de::from_str(LOTL).unwrap();
    let pointer = lotl
        .scheme_information
        .pointers_to_other_tsl
        .unwrap()
        .pointers
        .into_iter()
        .find(|pointer| pointer.tsl_location == FR_URL)
        .unwrap();
    pointer_signer_cert_pems(&pointer).remove(0)
}

pub(crate) fn response(url: &str, body: &str, content_type: &str) -> Response {
    Response {
        body: body.as_bytes().to_vec(),
        headers: hashmap! { "Content-Type".to_string() => content_type.to_string() },
        status: StatusCode(200),
        request: Request {
            body: None,
            headers: Default::default(),
            method: Method::Get,
            url: url.to_string(),
            timeout: None,
        },
    }
}

/// Client serving the LoTL and the FR member; DE and every other member answer 404.
fn client(lotl_body: &str) -> Arc<MockHttpClient> {
    let mut client = MockHttpClient::new();
    mock_http_get_request(
        &mut client,
        LOTL_URL.to_string(),
        response(LOTL_URL, lotl_body, "application/vnd.etsi.tsl+xml"),
    );
    let lotl: TrustServiceStatusList = quick_xml::de::from_str(LOTL).unwrap();
    for pointer in lotl
        .scheme_information
        .pointers_to_other_tsl
        .unwrap()
        .pointers
    {
        let url = pointer.tsl_location;
        if url == LOTL_URL || url.contains("/tools/TOE/") {
            continue;
        }
        let mut answer = response(&url, MEMBER, "application/xml; charset=utf-8");
        if url != FR_URL {
            answer.status = StatusCode(404);
        }
        mock_http_get_request(&mut client, url, answer);
    }
    Arc::new(client)
}

fn resolver(
    client: Arc<MockHttpClient>,
    xades: MockXAdESProto,
    trust_anchors: Vec<String>,
    limits: FetchLimits,
) -> EtsiLotlResolver {
    EtsiLotlResolver::new(
        Arc::new(TaskLocalClock),
        client,
        validator(),
        Arc::new(xades),
        EtsiLotlResolverOptions {
            trust_anchors,
            allow_unpinned_root: false,
            leeway: Duration::seconds(0),
            limits,
        },
    )
}

#[tokio::test]
async fn root_pinned_to_anchor_and_member_pinned_to_pointer() {
    let resolver = resolver(
        client(LOTL),
        xades(ROOT_SIGNER, whole_document_references(), None),
        vec![ROOT_SIGNER.to_string()],
        FetchLimits::default(),
    );
    let pin = resolver.root_pin().unwrap();

    let collection = run_with_mocked_time_async(NOW, resolver.collect(LOTL_URL, &pin))
        .await
        .unwrap();

    assert!(!collection.unpinned);
    assert_eq!(collection.members.len(), 1);
    assert_eq!(collection.members[0].url, FR_URL);
    // members answering 404 are reported, not fatal
    assert!(
        collection
            .skipped
            .iter()
            .any(|skipped| skipped.url == DE_URL && skipped.reason == SkipReason::Unreachable)
    );
}

#[tokio::test]
async fn root_signed_by_unknown_key_is_rejected() {
    let resolver = resolver(
        client(LOTL),
        xades(FOREIGN_SIGNER, whole_document_references(), None),
        vec![ROOT_SIGNER.to_string()],
        FetchLimits::default(),
    );
    let pin = resolver.root_pin().unwrap();

    let result = run_with_mocked_time_async(NOW, resolver.collect(LOTL_URL, &pin)).await;

    assert!(matches!(result, Err(FetchError::SignerNotTrusted)));
}

#[test]
fn empty_anchors_are_refused_unless_unpinned_root_allowed() {
    let resolver = resolver(
        Arc::new(MockHttpClient::new()),
        MockXAdESProto::new(),
        vec![],
        FetchLimits::default(),
    );
    assert!(matches!(
        resolver.root_pin(),
        Err(FetchError::UnpinnedNotAllowed)
    ));
}

#[tokio::test]
async fn unpinned_root_is_marked() {
    let resolver = resolver(
        client(LOTL),
        xades(FOREIGN_SIGNER, whole_document_references(), None),
        vec![],
        FetchLimits::default(),
    );

    let collection =
        run_with_mocked_time_async(NOW, resolver.collect(LOTL_URL, &SignerPin::Unpinned))
            .await
            .unwrap();

    assert!(collection.unpinned);
}

#[tokio::test]
async fn member_signed_by_foreign_key_is_skipped() {
    let resolver = resolver(
        client(LOTL),
        xades(
            ROOT_SIGNER,
            whole_document_references(),
            Some(FOREIGN_SIGNER.to_string()),
        ),
        vec![ROOT_SIGNER.to_string()],
        FetchLimits::default(),
    );
    let pin = resolver.root_pin().unwrap();

    let collection = run_with_mocked_time_async(NOW, resolver.collect(LOTL_URL, &pin))
        .await
        .unwrap();

    assert!(collection.members.is_empty());
    assert!(
        collection
            .skipped
            .iter()
            .any(|skipped| skipped.url == FR_URL && skipped.reason == SkipReason::SignerMismatch)
    );
}

#[tokio::test]
async fn signature_over_a_fragment_is_rejected() {
    let fragment_only = vec![
        VerifiedReference {
            uri: "#SomeOtherElement".to_string(),
            r#type: None,
            transforms: vec![Transform::EnvelopedSignature],
        },
        whole_document_references().remove(1),
    ];
    let resolver = resolver(
        client(LOTL),
        xades(ROOT_SIGNER, fragment_only, None),
        vec![ROOT_SIGNER.to_string()],
        FetchLimits::default(),
    );
    let pin = resolver.root_pin().unwrap();

    let result = run_with_mocked_time_async(NOW, resolver.collect(LOTL_URL, &pin)).await;

    assert!(matches!(result, Err(FetchError::InvalidSignature(_))));
}

#[tokio::test]
async fn signature_without_signed_properties_is_rejected() {
    let resolver = resolver(
        client(LOTL),
        xades(
            ROOT_SIGNER,
            vec![whole_document_references().remove(0)],
            None,
        ),
        vec![ROOT_SIGNER.to_string()],
        FetchLimits::default(),
    );
    let pin = resolver.root_pin().unwrap();

    let result = run_with_mocked_time_async(NOW, resolver.collect(LOTL_URL, &pin)).await;

    assert!(matches!(result, Err(FetchError::InvalidSignature(_))));
}

#[tokio::test]
async fn closed_lotl_is_rejected() {
    let closed = LOTL.replacen(
        "<NextUpdate>\n            <dateTime>2026-10-27T14:28:34</dateTime>\n        </NextUpdate>",
        "<NextUpdate/>",
        1,
    );
    assert_ne!(closed, LOTL);
    let mut client = MockHttpClient::new();
    mock_http_get_request(
        &mut client,
        LOTL_URL.to_string(),
        response(LOTL_URL, &closed, "application/vnd.etsi.tsl+xml"),
    );
    let resolver = resolver(
        Arc::new(client),
        MockXAdESProto::new(),
        vec![ROOT_SIGNER.to_string()],
        FetchLimits::default(),
    );
    let pin = resolver.root_pin().unwrap();

    let result = run_with_mocked_time_async(NOW, resolver.collect(LOTL_URL, &pin)).await;

    assert!(matches!(result, Err(FetchError::Closed)));
}

#[tokio::test]
async fn expired_lotl_is_rejected() {
    let resolver = resolver(
        client(LOTL),
        xades(ROOT_SIGNER, whole_document_references(), None),
        vec![ROOT_SIGNER.to_string()],
        FetchLimits::default(),
    );
    let pin = resolver.root_pin().unwrap();

    let result = run_with_mocked_time_async(
        datetime!(2026-11-01 00:00 UTC),
        resolver.collect(LOTL_URL, &pin),
    )
    .await;

    assert!(matches!(result, Err(FetchError::Expired)));
}

#[tokio::test]
async fn oversized_root_is_rejected() {
    let resolver = resolver(
        client(LOTL),
        MockXAdESProto::new(),
        vec![ROOT_SIGNER.to_string()],
        FetchLimits {
            max_document_bytes: 1024,
            ..Default::default()
        },
    );
    let pin = resolver.root_pin().unwrap();

    let result = run_with_mocked_time_async(NOW, resolver.collect(LOTL_URL, &pin)).await;

    assert!(matches!(result, Err(FetchError::SizeLimit(1024))));
}

#[tokio::test]
async fn pointers_beyond_the_limit_are_skipped() {
    let mut client = MockHttpClient::new();
    mock_http_get_request(
        &mut client,
        LOTL_URL.to_string(),
        response(LOTL_URL, LOTL, "application/vnd.etsi.tsl+xml"),
    );
    // only the first followed pointer (FR) is fetched
    mock_http_get_request(
        &mut client,
        FR_URL.to_string(),
        response(FR_URL, MEMBER, "application/xml"),
    );
    let resolver = resolver(
        Arc::new(client),
        xades(ROOT_SIGNER, whole_document_references(), None),
        vec![ROOT_SIGNER.to_string()],
        FetchLimits {
            max_pointers: 1,
            ..Default::default()
        },
    );
    let pin = resolver.root_pin().unwrap();

    let collection = run_with_mocked_time_async(NOW, resolver.collect(LOTL_URL, &pin))
        .await
        .unwrap();

    assert_eq!(collection.members.len(), 1);
    let limited: Vec<_> = collection
        .skipped
        .iter()
        .filter(|skipped| skipped.reason == SkipReason::PointerLimit)
        .collect();
    assert_eq!(limited.len(), 15);
}

/// Live export of the EU LoTL; needs network access and the LoTL signer certificates, so it is
/// ignored by default:
///
/// `EU_LOTL_ANCHORS=/path/to/ojeu-lotl-signers.pem [EU_LOTL_URL=…] cargo test -p equs-one-core \
///   --features mock --lib -- --ignored live_eu_lotl --nocapture`
#[tokio::test]
#[ignore = "network: fetches the live EU LoTL and member lists"]
async fn live_eu_lotl() {
    use crate::proto::certificate_validator::CertificateValidatorImpl;
    use crate::proto::clock::DefaultClock;
    use crate::proto::http_client::reqwest_client::ReqwestClient;
    use crate::proto::xades::XAdES;

    let url = std::env::var("EU_LOTL_URL")
        .unwrap_or_else(|_| "https://ec.europa.eu/tools/lotl/eu-lotl.xml".to_string());
    let anchors_path = std::env::var("EU_LOTL_ANCHORS").expect("EU_LOTL_ANCHORS (PEM file)");
    let anchors = std::fs::read_to_string(anchors_path).expect("readable PEM file");
    let anchors: Vec<String> = x509_parser::pem::Pem::iter_from_buffer(anchors.as_bytes())
        .map(|pem| crate::mapper::x509::der_chain_into_pem_chain(vec![pem.unwrap().contents]))
        .collect();

    let validator: Arc<dyn crate::proto::certificate_validator::CertificateValidator> =
        Arc::new(CertificateValidatorImpl::default());
    let resolver = EtsiLotlResolver::new(
        Arc::new(DefaultClock),
        Arc::new(ReqwestClient::default()),
        validator.clone(),
        Arc::new(XAdES::new(validator)),
        EtsiLotlResolverOptions {
            trust_anchors: anchors,
            allow_unpinned_root: false,
            leeway: Duration::minutes(5),
            limits: FetchLimits::default(),
        },
    );
    let pin = resolver.root_pin().unwrap();

    let collection = resolver
        .collect(&url, &pin)
        .await
        .expect("LoTL authenticates");

    println!(
        "sequence {}, {} members, {} skipped",
        collection.sequence_number,
        collection.members.len(),
        collection.skipped.len()
    );
    for skipped in &collection.skipped {
        println!("  skipped {} ({:?})", skipped.url, skipped.reason);
    }
    assert!(!collection.members.is_empty());
}
