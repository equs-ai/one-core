//! Anchor export over the EUDI pilot fixtures; XAdES verification is mocked.

use std::sync::Arc;

use similar_asserts::assert_eq;
use standardized_types::etsi_119_612::xml::TrustServiceStatusList;
use time::macros::datetime;
use url::Url;

use standardized_types::etsi_119_602::json::LoTEType;

use super::{AnchorRole, ExportPolicy, TrustListExporter, TrustListKind};
use crate::proto::clock::{TaskLocalClock, run_with_mocked_time_async};
use crate::proto::http_client::{MockHttpClient, StatusCode};
use crate::proto::xades::MockXAdESProto;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::trust_list_subscriber::etsi_lote::test::{LOTE_XML, TRUSTED_CERT};
use crate::provider::trust_list_subscriber::etsi_lotl::resolver::pointer_signer_cert_pems;
use crate::provider::trust_list_subscriber::etsi_lotl::resolver::test::{
    DE_URL, FR_URL, LOTL, LOTL_URL, MEMBER, NOW, ROOT_SIGNER, fr_pointer_pem, response, validator,
    verified, whole_document_references,
};
use crate::provider::trust_list_subscriber::fetch::{FetchLimits, SkipReason};
use crate::util::test_utilities::mock_http_get_request;

const REGISTRARS_LOTE_TYPE: &str =
    "http://uri.etsi.org/19602/LoTEType/EURegistrarsAndRegistersList";
const PID_LOTE_TYPE: &str = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList";

/// The LoTL with its DE pointer turned into a pointer to an XML LoTE of `declared_type`.
fn lotl_with_delegated_lote(declared_type: &str) -> String {
    let start = LOTL[..LOTL.find(DE_URL).unwrap()]
        .rfind("<OtherTSLPointer>")
        .unwrap();
    let end = start + LOTL[start..].find("</OtherTSLPointer>").unwrap();
    let pointer = LOTL[start..end]
        .replace(
            "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric",
            declared_type,
        )
        .replace("application/vnd.etsi.tsl+xml", "application/xml");
    format!("{}{}{}", &LOTL[..start], pointer, &LOTL[end..])
}

fn de_pointer_pem() -> String {
    let lotl: TrustServiceStatusList = quick_xml::de::from_str(LOTL).unwrap();
    let pointer = lotl
        .scheme_information
        .pointers_to_other_tsl
        .unwrap()
        .pointers
        .into_iter()
        .find(|pointer| pointer.tsl_location == DE_URL)
        .unwrap();
    pointer_signer_cert_pems(&pointer).remove(0)
}

/// Serves the LoTL, the FR member TSL, and (when `delegated`) an XML LoTE at the DE location.
fn client(lotl_body: &str, delegated: bool) -> Arc<MockHttpClient> {
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
        if url.contains("/tools/TOE/") {
            continue;
        }
        let answer = match url.as_str() {
            FR_URL => response(&url, MEMBER, "application/xml"),
            DE_URL if delegated => response(&url, LOTE_XML, "application/xml"),
            _ => {
                let mut answer = response(&url, "", "application/xml");
                answer.status = StatusCode(404);
                answer
            }
        };
        mock_http_get_request(&mut client, url, answer);
    }
    Arc::new(client)
}

/// Root signed by `ROOT_SIGNER`, the LoTE at DE by the DE pointer certificate, members by FR's.
fn xades() -> MockXAdESProto {
    let mut xades = MockXAdESProto::new();
    xades
        .expect_verify_enveloped_signature()
        .returning(move |signed| {
            let document = &signed.unverified_document;
            let signer = if document.contains(FR_URL) {
                ROOT_SIGNER.to_string()
            } else if document.contains("ListOfTrustedEntities") {
                de_pointer_pem()
            } else {
                fr_pointer_pem()
            };
            let mut result = verified(&signer, whole_document_references());
            if document.contains("ListOfTrustedEntities") {
                result.references[0].uri = String::new();
            }
            Box::pin(async move { Ok(result) })
        });
    xades
}

fn exporter(client: Arc<MockHttpClient>) -> TrustListExporter {
    TrustListExporter::with_xades(
        Arc::new(TaskLocalClock),
        client,
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        validator(),
        Arc::new(xades()),
    )
}

fn policy() -> ExportPolicy {
    ExportPolicy {
        trust_anchors: vec![ROOT_SIGNER.to_string()],
        limits: FetchLimits::default(),
        ..Default::default()
    }
}

#[tokio::test]
async fn lotl_export_returns_member_anchors_with_roles_and_freshness() {
    let exporter = exporter(client(LOTL, false));
    let url = Url::parse(LOTL_URL).unwrap();

    let export = run_with_mocked_time_async(
        NOW,
        exporter.export(&url, TrustListKind::Lotl119612, &policy()),
    )
    .await
    .unwrap();

    assert!(!export.unpinned);
    assert!(!export.anchors.is_empty());
    assert!(
        export
            .anchors
            .iter()
            .all(|anchor| anchor.source_url == FR_URL)
    );
    assert!(
        export
            .anchors
            .iter()
            .all(|anchor| anchor.source_next_update == datetime!(2026-10-27 14:28:34 UTC))
    );
    assert!(export.anchors.iter().all(|anchor| {
        anchor.service_status.as_deref().is_some_and(|status| {
            status.ends_with("/granted") || status.ends_with("/recognisedatnationallevel")
        })
    }));
    let roles: Vec<_> = export.anchors.iter().map(|anchor| anchor.role).collect();
    assert!(roles.contains(&Some(AnchorRole::EaaProvider)));
    assert!(roles.contains(&Some(AnchorRole::PubEaaProvider)));
    // EUDI pilot `Svc/Svctype/Provider/PID`
    assert!(roles.contains(&Some(AnchorRole::PidProvider)));
    // pilot wallet / RP-access services carry no role
    assert!(roles.contains(&None));
    assert!(export.anchors.iter().all(|anchor| anchor.ski.is_some()));
    assert!(
        export
            .skipped_members
            .iter()
            .any(|skipped| skipped.url == DE_URL && skipped.reason == SkipReason::Unreachable)
    );
}

#[tokio::test]
async fn delegated_lote_is_exported_pinned_to_its_pointer() {
    let exporter = exporter(client(
        &lotl_with_delegated_lote(REGISTRARS_LOTE_TYPE),
        true,
    ));
    let url = Url::parse(LOTL_URL).unwrap();

    let export = run_with_mocked_time_async(
        datetime!(2026-04-01 00:00 UTC),
        exporter.export(
            &url,
            TrustListKind::Lotl119612,
            &ExportPolicy {
                leeway: time::Duration::days(365),
                ..policy()
            },
        ),
    )
    .await
    .unwrap();

    let lote_anchors: Vec<_> = export
        .anchors
        .iter()
        .filter(|anchor| anchor.source_url == DE_URL)
        .collect();
    assert_eq!(lote_anchors.len(), 1);
    assert_eq!(lote_anchors[0].pem, TRUSTED_CERT);
    assert_eq!(lote_anchors[0].role, Some(AnchorRole::Registrar));
    assert_eq!(lote_anchors[0].entity_name.as_deref(), Some("Test Entity"));
}

#[tokio::test]
async fn delegated_lote_of_another_type_is_skipped() {
    let exporter = exporter(client(&lotl_with_delegated_lote(PID_LOTE_TYPE), true));
    let url = Url::parse(LOTL_URL).unwrap();

    let export = run_with_mocked_time_async(
        datetime!(2026-04-01 00:00 UTC),
        exporter.export(
            &url,
            TrustListKind::Lotl119612,
            &ExportPolicy {
                leeway: time::Duration::days(365),
                ..policy()
            },
        ),
    )
    .await
    .unwrap();

    assert!(
        export
            .anchors
            .iter()
            .all(|anchor| anchor.source_url != DE_URL)
    );
    assert!(
        export
            .skipped_members
            .iter()
            .any(|skipped| skipped.url == DE_URL && skipped.reason == SkipReason::InvalidDocument)
    );
}

#[tokio::test]
async fn export_without_anchors_is_refused() {
    let exporter = exporter(Arc::new(MockHttpClient::new()));
    let url = Url::parse(LOTL_URL).unwrap();

    let result = exporter
        .export(&url, TrustListKind::Lotl119612, &ExportPolicy::default())
        .await;

    assert!(matches!(
        result,
        Err(crate::provider::trust_list_subscriber::fetch::FetchError::UnpinnedNotAllowed)
    ));
}

#[test]
fn every_mapped_role_is_exported() {
    use standardized_types::etsi_119_612::ServiceType;

    use crate::mapper::etsi_lotl::role_for_service_type;
    use crate::model::trust_list_role::TrustListRoleEnum;

    let tsl = |uri: &str| {
        role_for_service_type(&ServiceType::from(uri.to_string()))
            .and_then(AnchorRole::from_trust_list_role)
    };
    assert_eq!(
        tsl("http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"),
        Some(AnchorRole::QeaaProvider)
    );
    assert_eq!(
        tsl("http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA"),
        Some(AnchorRole::PubEaaProvider)
    );
    assert_eq!(
        tsl("http://uri.etsi.org/TrstSvc/Svctype/EAA"),
        Some(AnchorRole::EaaProvider)
    );
    assert_eq!(
        tsl("http://uri.etsi.org/Svc/Svctype/Provider/PID"),
        Some(AnchorRole::PidProvider)
    );
    assert_eq!(tsl("http://uri.etsi.org/TrstSvc/Svctype/CA/QC"), None);

    let lote = |lote_type: LoTEType| {
        TrustListRoleEnum::try_from(lote_type)
            .ok()
            .and_then(AnchorRole::from_trust_list_role)
    };
    assert_eq!(
        lote(LoTEType::EuPidProvidersList),
        Some(AnchorRole::PidProvider)
    );
    assert_eq!(
        lote(LoTEType::EuPubEaaProvidersList),
        Some(AnchorRole::PubEaaProvider)
    );
    assert_eq!(
        lote(LoTEType::EuWalletProvidersList),
        Some(AnchorRole::WalletProvider)
    );
    assert_eq!(
        lote(LoTEType::EuWrpAcProvidersList),
        Some(AnchorRole::WrpAcProvider)
    );
    assert_eq!(
        lote(LoTEType::EuWrpRcProvidersList),
        Some(AnchorRole::WrpRcProvider)
    );
    assert_eq!(
        lote(LoTEType::EuRegistrarsAndRegistersList),
        Some(AnchorRole::Registrar)
    );
    assert_eq!(
        AnchorRole::from_trust_list_role(TrustListRoleEnum::QesrcProvider),
        None
    );
}
