use std::collections::HashMap;
use std::sync::Arc;

use ct_codecs::Decoder as _;
use maplit::hashmap;
use mockall::predicate::{always, eq, ne};
use similar_asserts::assert_eq;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::proto::clock::{TaskLocalClock, run_with_mocked_time_async};
use crate::proto::http_client::{Method, MockHttpClient, Request, Response, StatusCode};
use crate::proto::xades::{MockXAdESProto, XAdES};
use crate::provider::caching_loader::etsi_lote::EtsiLoteCache;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::trust_list_subscriber::TrustListSubscriber;
use crate::provider::trust_list_subscriber::error::TrustListSubscriberError;
use crate::provider::trust_list_subscriber::etsi_lote::resolver::{
    EtsiLoteResolver, EtsiLoteResolverOptions,
};
use crate::provider::trust_list_subscriber::etsi_lote::{EtsiLoteSubscriber, LoteContentType};
use crate::provider::trust_list_subscriber::fetch::{FetchError, FetchLimits, SignerPin};
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::test_utilities::{dummy_identifier, dummy_key};
use crate::util::test_utilities::mock_http_get_request;

pub(super) const SPRIND_LOTE_JWS: &str = "eyJhbGciOiJFUzI1NiIsImlhdCI6MTc3MjQ5MzA2NywieDVjIjpbIk1JSUNGekNDQWIyZ0F3SUJBZ0lVUUF4ZXY4eDJCbzRZNWhWbkdoT285VlNkQWNJd0NnWUlLb1pJemowRUF3SXdZVEVMTUFrR0ExVUVCaE1DUkVVeER6QU5CZ05WQkFnTUJrSmxjbXhwYmpFUE1BMEdBMVVFQnd3R1FtVnliR2x1TVJRd0VnWURWUVFLREF0VWNuVnpkQ0JNYVhOMGN6RWFNQmdHQTFVRUF3d1JWSEoxYzNRZ1RHbHpkQ0JUYVdkdVpYSXdIaGNOTWpZd01qQTJNVFF5TWpFNVdoY05Nell3TWpBME1UUXlNakU1V2pCaE1Rc3dDUVlEVlFRR0V3SkVSVEVQTUEwR0ExVUVDQXdHUW1WeWJHbHVNUTh3RFFZRFZRUUhEQVpDWlhKc2FXNHhGREFTQmdOVkJBb01DMVJ5ZFhOMElFeHBjM1J6TVJvd0dBWURWUVFEREJGVWNuVnpkQ0JNYVhOMElGTnBaMjVsY2pCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQk5GRHc5a0VaeHp3ZWxsVzRiNmlUYXhxYThlSEJaTUVzTzg0Q1Y1T0piZEI5ZG1OaUdiNTM5dnh3V2JpbTZ3WHorYzNuNUNVbnN1Z2VvbStubjBHQWxTalV6QlJNQjBHQTFVZERnUVdCQlMxdVhqODF4VHovUHhYWWpsaEtrWkhzNmREVVRBZkJnTlZIU01FR0RBV2dCUzF1WGo4MXhUei9QeFhZamxoS2taSHM2ZERVVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUUNFSnAvWlJ3eFBlZTJFUUpIZFZXQ3RiUjdiWFBwYzJIcjFsdEorL1U0SnNRSWdRWnFJWkFCMzhtNzl6VHhWR2lYUmF1ZzJTaml1NlAxRGJWYldSZVMwazBjPSJdfQ.eyJMaXN0QW5kU2NoZW1lSW5mb3JtYXRpb24iOnsiTG9URVZlcnNpb25JZGVudGlmaWVyIjoxLCJMb1RFU2VxdWVuY2VOdW1iZXIiOjEsIkxvVEVUeXBlIjoiaHR0cDovL3VyaS5ldHNpLm9yZy8xOTYwMi9Mb1RFVHlwZS9SZWdpc3RyYXJzQW5kUmVnaXN0ZXJzTGlzdFByb3ZpZGVyc0xpc3QiLCJTY2hlbWVJbmZvcm1hdGlvblVSSSI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwczovL2V4YW1wbGUuY29tL3ByZXZpb3VzLWxpc3RzIn1dLCJTdGF0dXNEZXRlcm1pbmF0aW9uQXBwcm9hY2giOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1JlZ2lzdHJhcnNBbmRSZWdpc3RlcnNMaXN0UHJvdmlkZXJzTGlzdC9TdGF0dXNEZXRuL0VVLiIsIlNjaGVtZVR5cGVDb21tdW5pdHlSdWxlcyI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1JlZ2lzdHJhcnNBbmRSZWdpc3RlcnNMaXN0UHJvdmlkZXJzTGlzdC9zY2hlbWVydWxlcy9FVSJ9XSwiU2NoZW1lVGVycml0b3J5IjoiRVUiLCJOZXh0VXBkYXRlIjoiMjAyNi0wMy0wM1QyMzoxMTowNy4xMzNaIiwiU2NoZW1lT3BlcmF0b3JOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IlNQUklORCBHbWJIIn1dLCJMaXN0SXNzdWVEYXRlVGltZSI6IjIwMjYtMDMtMDJUMjM6MTE6MDcuMTMzWiJ9LCJUcnVzdGVkRW50aXRpZXNMaXN0IjpbeyJUcnVzdGVkRW50aXR5SW5mb3JtYXRpb24iOnsiVEVJbmZvcm1hdGlvblVSSSI6W3sibGFuZyI6ImRlLURFIiwidXJpVmFsdWUiOiJodHRwczovL3d3dy5zcHJpbmQub3JnIn1dLCJURU5hbWUiOlt7ImxhbmciOiJkZS1ERSIsInZhbHVlIjoiU1BSSU5EIEdtYkgifV0sIlRFQWRkcmVzcyI6eyJURUVsZWN0cm9uaWNBZGRyZXNzIjpbeyJsYW5nIjoiZGUtREUiLCJ1cmlWYWx1ZSI6Imh0dHBzOi8vc3ByaW5kLm9yZy9jb250YWN0In1dLCJURVBvc3RhbEFkZHJlc3MiOlt7IkNvdW50cnkiOiJERSIsImxhbmciOiJkZSIsIkxvY2FsaXR5IjoiTGVpcHppZyIsIlBvc3RhbENvZGUiOiIwNDEwMyIsIlN0cmVldEFkZHJlc3MiOiJMYWdlcmhvZnN0cmHDn2UgNCJ9XX19LCJUcnVzdGVkRW50aXR5U2VydmljZXMiOlt7IlNlcnZpY2VJbmZvcm1hdGlvbiI6eyJTZXJ2aWNlVHlwZUlkZW50aWZpZXIiOiJodHRwOi8vdXJpLmV0c2kub3JnLzE5NjAyL1N2Y1R5cGUvUmVnaXN0cmFyc0FuZFJlZ2lzdGVyc0xpc3RTb2x1dGlvbi9Jc3N1YW5jZSIsIlNlcnZpY2VOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IkFjY2VzcyBDZXJ0aWZpY2F0ZSBBdXNzdGVsbHVuZ3NkaWVuc3QgZGVyIFNQUklORCBHbWJIIn1dLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUNMekNDQWRTZ0F3SUJBZ0lVSHlSakU0NjZZQTd0Yzg4OGswM091MlFvZEY0d0NnWUlLb1pJemowRUF3SXdLREVMTUFrR0ExVUVCaE1DUkVVeEdUQVhCZ05WQkFNTUVFZGxjbTFoYmlCU1pXZHBjM1J5WVhJd0hoY05Nall3TVRFMk1URXhOVFUwV2hjTk1qZ3dNVEUyTVRFeE5UVTBXakFvTVFzd0NRWURWUVFHRXdKRVJURVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJNZWZZMlg0aXhmUmtXRXZwOWdyRjJpMjF6NlBLWnNyOHp6QmFKLytHbm90Q2VIMmNKNkd0TGh4WGhIZkpqckVUc01OSUdoVmFKb0hvSGNaVEJISnJmeWpnZHN3Z2Rnd0hRWURWUjBPQkJZRUZLbkNvOW92YmF4VTdzNjVUdWdzeVN3QWc0QXpNQjhHQTFVZEl3UVlNQmFBRktuQ285b3ZiYXhVN3M2NVR1Z3N5U3dBZzRBek1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Db0dBMVVkRWdRak1DR0dIMmgwZEhCek9pOHZjMkZ1WkdKdmVDNWxkV1JwTFhkaGJHeGxkQzV2Y21jd1JnWURWUjBmQkQ4d1BUQTdvRG1nTjRZMWFIUjBjSE02THk5ellXNWtZbTk0TG1WMVpHa3RkMkZzYkdWMExtOXlaeTl6ZEdGMGRYTXRiV0Z1WVdkbGJXVnVkQzlqY213d0NnWUlLb1pJemowRUF3SURTUUF3UmdJaEFJWTdFUnBSckRSbDBscjVINXV4ako4M0pSNHF1YTJzZlBLeFgrcGw0UXcrQWlFQTJxTDZMWFZPUkEycjJWWmpTRWtuZmNpd0lHN2xhQTEya2pueUdBRDNWL0E9In1dfX19LHsiU2VydmljZUluZm9ybWF0aW9uIjp7IlNlcnZpY2VOYW1lIjpbeyJsYW5nIjoiZGUtREUiLCJ2YWx1ZSI6IkFjY2VzcyBDZXJ0aWZpY2F0ZS1SZXZva2F0aW9uc2RpZW5zdCBkZXIgU1BSSU5EIEdtYkgifV0sIlNlcnZpY2VUeXBlSWRlbnRpZmllciI6Imh0dHA6Ly91cmkuZXRzaS5vcmcvMTk2MDIvU3ZjVHlwZS9SZWdpc3RyYXJzQW5kUmVnaXN0ZXJzTGlzdFNvbHV0aW9uL1Jldm9jYXRpb24iLCJTZXJ2aWNlRGlnaXRhbElkZW50aXR5Ijp7Ilg1MDlDZXJ0aWZpY2F0ZXMiOlt7InZhbCI6Ik1JSUNMekNDQWRTZ0F3SUJBZ0lVSHlSakU0NjZZQTd0Yzg4OGswM091MlFvZEY0d0NnWUlLb1pJemowRUF3SXdLREVMTUFrR0ExVUVCaE1DUkVVeEdUQVhCZ05WQkFNTUVFZGxjbTFoYmlCU1pXZHBjM1J5WVhJd0hoY05Nall3TVRFMk1URXhOVFUwV2hjTk1qZ3dNVEUyTVRFeE5UVTBXakFvTVFzd0NRWURWUVFHRXdKRVJURVpNQmNHQTFVRUF3d1FSMlZ5YldGdUlGSmxaMmx6ZEhKaGNqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJNZWZZMlg0aXhmUmtXRXZwOWdyRjJpMjF6NlBLWnNyOHp6QmFKLytHbm90Q2VIMmNKNkd0TGh4WGhIZkpqckVUc01OSUdoVmFKb0hvSGNaVEJISnJmeWpnZHN3Z2Rnd0hRWURWUjBPQkJZRUZLbkNvOW92YmF4VTdzNjVUdWdzeVN3QWc0QXpNQjhHQTFVZEl3UVlNQmFBRktuQ285b3ZiYXhVN3M2NVR1Z3N5U3dBZzRBek1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01Db0dBMVVkRWdRak1DR0dIMmgwZEhCek9pOHZjMkZ1WkdKdmVDNWxkV1JwTFhkaGJHeGxkQzV2Y21jd1JnWURWUjBmQkQ4d1BUQTdvRG1nTjRZMWFIUjBjSE02THk5ellXNWtZbTk0TG1WMVpHa3RkMkZzYkdWMExtOXlaeTl6ZEdGMGRYTXRiV0Z1WVdkbGJXVnVkQzlqY213d0NnWUlLb1pJemowRUF3SURTUUF3UmdJaEFJWTdFUnBSckRSbDBscjVINXV4ako4M0pSNHF1YTJzZlBLeFgrcGw0UXcrQWlFQTJxTDZMWFZPUkEycjJWWmpTRWtuZmNpd0lHN2xhQTEya2pueUdBRDNWL0E9In1dfX19XX1dfQ.IzpFGp0TchXMvizip3HffMnmP40WkNsvLRBRUGsu1pKAd5PeMs2klbuEWb22FpQ1UyTUvRobi2xyHewySS6mpA";

const UNTRUSTED_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICADCCAYagAwIBAgIRANMI7LNjmBkq6LyFy5KhIoUwCgYIKoZIzj0EAwIwPzES
MBAGA1UEDAwJU3Ryb25nQm94MSkwJwYDVQQFEyAxNjY4ZjI4M2M2ZGQ3OTgyNTM1
YjViNWJiYWU1ODYxZTAeFw0yNDA5MTIyMTQ3MjZaFw0zNDA5MTAyMTQ3MjZaMD8x
EjAQBgNVBAwMCVN0cm9uZ0JveDEpMCcGA1UEBRMgYTVjMTM2YzdkOTM1NjI3ZDVm
ZWUzMjRjY2QzZmViMGQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQFPGMUj07/
qx5I9nPl0iivOq5gFTJ+QnflKyMYv7rrzaCe04ydj54NXXWgtaBOdUfiuZPUtqv7
luDQT6l7GAENo2MwYTAdBgNVHQ4EFgQU1KgfEPcAZG7u233No9Jc3katBEowHwYD
VR0jBBgwFoAURtwIzTltMRWBmDiz54wXB2lgqogwDwYDVR0TAQH/BAUwAwEB/zAO
BgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDaAAwZQIxANFoE7Ezv6jFOjiyoFT3
/sO7yFaPcwEBF+v6ff6eF0y3ySZArOiROOiji0rUbc5mSwIwC4O/UTP7WvksjGe1
IZvI/gYu+lOExQYHZebjfhtcl545ckTRmtGMKmBpoJr+8Vdr
-----END CERTIFICATE-----
"#;
const TRUSTED_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICLzCCAdSgAwIBAgIUHyRjE466YA7tc888k03Ou2QodF4wCgYIKoZIzj0EAwIw
KDELMAkGA1UEBhMCREUxGTAXBgNVBAMMEEdlcm1hbiBSZWdpc3RyYXIwHhcNMjYw
MTE2MTExNTU0WhcNMjgwMTE2MTExNTU0WjAoMQswCQYDVQQGEwJERTEZMBcGA1UE
AwwQR2VybWFuIFJlZ2lzdHJhcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMef
Y2X4ixfRkWEvp9grF2i21z6PKZsr8zzBaJ/+GnotCeH2cJ6GtLhxXhHfJjrETsMN
IGhVaJoHoHcZTBHJrfyjgdswgdgwHQYDVR0OBBYEFKnCo9ovbaxU7s65TugsySwA
g4AzMB8GA1UdIwQYMBaAFKnCo9ovbaxU7s65TugsySwAg4AzMBIGA1UdEwEB/wQI
MAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMCoGA1UdEgQjMCGGH2h0dHBzOi8vc2Fu
ZGJveC5ldWRpLXdhbGxldC5vcmcwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cHM6Ly9z
YW5kYm94LmV1ZGktd2FsbGV0Lm9yZy9zdGF0dXMtbWFuYWdlbWVudC9jcmwwCgYI
KoZIzj0EAwIDSQAwRgIhAIY7ERpRrDRl0lr5H5uxjJ83JR4qua2sfPKxX+pl4Qw+
AiEA2qL6LXVORA2r2VZjSEknfciwIG7laA12kjnyGAD3V/A=
-----END CERTIFICATE-----
"#;

const TRUSTED_FINGERPRINT: &str =
    "7421221cb1da97b3edb4ad2ccb4d00cbdced1e1316bf6768e677218cdb246d3e";

#[tokio::test]
async fn validate_subscription_success() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .validate_subscription(
                &reference,
                Some(TrustListRoleEnum::NationalRegistryRegistrar),
            )
            .await
    })
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn validate_subscription_roleless_when_no_role_derivable() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

    // A LoTE with no derivable role is a roleless subscription; the role is then
    // re-derived per entity at resolve time.
    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .validate_subscription(&reference, None)
            .await
            .unwrap()
    })
    .await;

    assert_eq!(result.role, None);
}

#[tokio::test]
async fn resolve_unsupported_identifier_type() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[dummy_identifier()])
            .await
    })
    .await;

    assert!(matches!(
        result,
        Err(TrustListSubscriberError::UnsupportedIdentifierType(_))
    ));
}

#[tokio::test]
async fn validate_subscription_expired() {
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

    let result = subscriber
        .validate_subscription(&reference, None)
        .await
        .err()
        .unwrap();

    assert_eq!(result.error_code(), ErrorCode::BR_0354);
}

#[tokio::test]
async fn resolve_untrusted_identifier() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

    let identifier_id = Uuid::new_v4().into();
    let identifier = certificate_identifier(identifier_id, UNTRUSTED_CERT, "unknown fingerprint");

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[identifier])
            .await
            .unwrap()
    })
    .await;

    assert_eq!(result, HashMap::new());
}

#[tokio::test]
async fn resolve_trusted_identifier() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

    let identifier_id = Uuid::new_v4().into();
    let identifier = certificate_identifier(identifier_id, TRUSTED_CERT, TRUSTED_FINGERPRINT);

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[identifier])
            .await
            .unwrap()
    })
    .await;

    assert_eq!(result.len(), 1);
    assert!(result.contains_key(&identifier_id));
}

#[tokio::test]
async fn resolve_trusted_certificate_authority_identifier() {
    let time = datetime!(2026-03-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote").unwrap();

    let subscriber = setup_subscriber(&reference);

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = certificate_identifier(identifier_id, TRUSTED_CERT, TRUSTED_FINGERPRINT);
    identifier.r#type = IdentifierType::CertificateAuthority;

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[identifier])
            .await
            .unwrap()
    })
    .await;

    assert_eq!(result.len(), 1);
    assert!(result.contains_key(&identifier_id));
}

fn setup_subscriber(reference: &Url) -> EtsiLoteSubscriber {
    let mut client = MockHttpClient::new();
    mock_http_get_request(
        &mut client,
        reference.to_string(),
        Response {
            body: SPRIND_LOTE_JWS.as_bytes().to_vec(),
            headers: hashmap! { "Content-Type".to_string() => "application/jwt".to_string() },
            status: StatusCode(200),
            request: Request {
                body: None,
                headers: Default::default(),
                method: Method::Get,
                url: reference.to_string(),
                timeout: None,
            },
        },
    );
    let client = Arc::new(client);
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Ecdsa))
        .returning(|_| Some(Arc::new(Ecdsa)));
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .returning(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));
    // trust-list certificate keys are indexed via the provider's raw form
    key_algorithm_provider.expect_parse_raw().returning(|der| {
        Ecdsa
            .parse_raw(der)
            .map(|key| ParsedKey {
                algorithm_type: KeyAlgorithmType::Ecdsa,
                key,
            })
            .map_err(|err| {
                KeyAlgorithmProviderError::MissingAlgorithmImplementation(err.to_string())
            })
    });
    let key_algorithm_provider = Arc::new(key_algorithm_provider);
    let cache_storage = Arc::new(InMemoryStorage::new(HashMap::new()));

    let mut certificate_validator = MockCertificateValidator::new();
    let certificate = {
        let mut handle = MockSignaturePublicKeyHandle::new();
        handle.expect_verify().returning(|_, _| Ok(()));
        ParsedCertificate {
            attributes: CertificateX509AttributesDTO {
                serial_number: "1F:24:63:13:8E:BA:60:0E:ED:73:CF:3C:93:4D:CE:BB:64:28:74:5E"
                    .to_string(),
                not_before: datetime!(2025-03-01 00:00 UTC),
                not_after: datetime!(2028-03-01 00:00 UTC),
                issuer: "CN=German Registrar, C=DE".to_string(),
                subject: "CN=German Registrar, C=DE".to_string(),
                fingerprint: TRUSTED_FINGERPRINT.to_string(),
                extensions: vec![],
            },
            subject_common_name: None,
            subject_key_identifier: None,
            public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                handle,
            ))),
        }
    };
    certificate_validator
        .expect_parse_pem_chain()
        .with(eq(TRUSTED_CERT), always())
        .returning({
            let certificate = certificate.clone();
            move |_, _| Ok(certificate.clone())
        });
    certificate_validator
        .expect_parse_pem_chain()
        .with(ne(TRUSTED_CERT), always())
        .returning({
            let mut certificate = certificate.clone();
            certificate.attributes.fingerprint = "unknown fingerprint".to_string();
            move |_, _| Ok(certificate.clone())
        });
    certificate_validator
        .expect_validate_chain_against_ca_chain()
        .returning(move |_, _, _, _| Ok(certificate.clone()));

    let certificate_validator = Arc::new(certificate_validator);
    let resolver = Arc::new(EtsiLoteResolver::new(
        Arc::new(TaskLocalClock),
        client,
        Arc::new(MockDidMethodProvider::new()),
        key_algorithm_provider.clone(),
        certificate_validator.clone(),
        Arc::new(MockXAdESProto::new()),
        EtsiLoteResolverOptions {
            content_type: LoteContentType::Jwt,
            leeway: Duration::seconds(0),
            max_pointer_depth: None,
            trust_anchors: vec![],
            allow_unpinned_root: true,
            limits: FetchLimits::default(),
        },
    ));
    let cache = EtsiLoteCache::new(
        cache_storage,
        100,
        Duration::seconds(60),
        Duration::seconds(60),
        Arc::new(TaskLocalClock),
    );

    EtsiLoteSubscriber::new(
        cache,
        resolver,
        certificate_validator,
        key_algorithm_provider,
    )
}

// XAdES-signed XML LoTE containing the same TRUSTED_CERT entity.
// Generated with the P-256 test key pair from proto::xades::test using
// generate_xml_lote_test_vector (run with --ignored --nocapture).
const LOTE_XML: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<ListOfTrustedEntities xmlns="http://uri.etsi.org/019602/v1#" LOTETag="http://uri.etsi.org/019602/tag#"><ListAndSchemeInformation><LoTEVersionIdentifier>1</LoTEVersionIdentifier><LoTESequenceNumber>1</LoTESequenceNumber><LoTEType>http://uri.etsi.org/19602/LoTEType/EURegistrarsAndRegistersList</LoTEType><SchemeOperatorName><Name xml:lang="en">Test Operator</Name></SchemeOperatorName><StatusDeterminationApproach/><SchemeTerritory>EU</SchemeTerritory><ListIssueDateTime>2026-03-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2026-06-01T00:00:00Z</dateTime></NextUpdate></ListAndSchemeInformation><TrustedEntitiesList><TrustedEntity><TrustedEntityInformation><TEName><Name xml:lang="de-DE">Test Entity</Name></TEName></TrustedEntityInformation><TrustedEntityServices><TrustedEntityService><ServiceInformation><ServiceName><Name xml:lang="de-DE">Test Service</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>MIICLzCCAdSgAwIBAgIUHyRjE466YA7tc888k03Ou2QodF4wCgYIKoZIzj0EAwIwKDELMAkGA1UEBhMCREUxGTAXBgNVBAMMEEdlcm1hbiBSZWdpc3RyYXIwHhcNMjYwMTE2MTExNTU0WhcNMjgwMTE2MTExNTU0WjAoMQswCQYDVQQGEwJERTEZMBcGA1UEAwwQR2VybWFuIFJlZ2lzdHJhcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMefY2X4ixfRkWEvp9grF2i21z6PKZsr8zzBaJ/+GnotCeH2cJ6GtLhxXhHfJjrETsMNIGhVaJoHoHcZTBHJrfyjgdswgdgwHQYDVR0OBBYEFKnCo9ovbaxU7s65TugsySwAg4AzMB8GA1UdIwQYMBaAFKnCo9ovbaxU7s65TugsySwAg4AzMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMCoGA1UdEgQjMCGGH2h0dHBzOi8vc2FuZGJveC5ldWRpLXdhbGxldC5vcmcwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cHM6Ly9zYW5kYm94LmV1ZGktd2FsbGV0Lm9yZy9zdGF0dXMtbWFuYWdlbWVudC9jcmwwCgYIKoZIzj0EAwIDSQAwRgIhAIY7ERpRrDRl0lr5H5uxjJ83JR4qua2sfPKxX+pl4Qw+AiEA2qL6LXVORA2r2VZjSEknfciwIG7laA12kjnyGAD3V/A=</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/19602/SvcStatus/active</ServiceStatus><StatusStartingTime>2026-03-01T00:00:00Z</StatusStartingTime></ServiceInformation></TrustedEntityService></TrustedEntityServices></TrustedEntity></TrustedEntitiesList><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="id-7f5552b2-bd88-425b-a42d-64e074b23d31"><ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference Id="r-id-7f5552b2-bd88-425b-a42d-64e074b23d31" URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>ibHwcbENffk1nsVFRhNhhBX9XOKIluQTGocvLekeOBY=</ds:DigestValue></ds:Reference><ds:Reference URI="#xades-id-7f5552b2-bd88-425b-a42d-64e074b23d31" Type="http://uri.etsi.org/01903#SignedProperties"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>Y0OazMA/aZaHQmPILNDLNRnNAaOWjb6NVKO63gg8xLg=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue Id="value-id-7f5552b2-bd88-425b-a42d-64e074b23d31">dFO8cosEG/KAgMqgB3BXGpuDuzZAGcgh5mv93DkqahQu054UOXL38EeIoWmfyYeMlwEPZpfWSzujtTpWgDZk+g==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBMTCB2KADAgECAhQSJe8xsm3dMnAInnpRGvwiotSp6jAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1YQWRFUyBUZXN0IENBMCAXDTc1MDEwMTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAYMRYwFAYDVQQDDA1YQWRFUyBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcd/LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yeJpCY9SCKvzQjZcIWqfb8o+p1YfQ/EzMII/xbe4/GVQDAKBggqhkjOPQQDAgNIADBFAiEA34ISXnPYu5LRBb0itF0Nlmm4imiZ5YUKZahKnnmmAMQCIBWBr/GnmGAj5aqM+V6HGzhpwlz6d5ocJqb5GY+WhnHb</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object><xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Target="#id-7f5552b2-bd88-425b-a42d-64e074b23d31"><xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="xades-id-7f5552b2-bd88-425b-a42d-64e074b23d31"><xades:SignedSignatureProperties><xades:SigningTime>2026-03-29T20:35:02.640504Z</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>Vko5kJdJk0XOYw1G3uHVzAgQ+uPXlHRtH32Qp1K2FSs=</ds:DigestValue></xades:CertDigest><xades:IssuerSerialV2/></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties><xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference="#r-id-7f5552b2-bd88-425b-a42d-64e074b23d31"><xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties></xades:QualifyingProperties></ds:Object></ds:Signature></ListOfTrustedEntities>"##;

const XADES_TEST_CA_B64: &str = "MIIBMTCB2KADAgECAhQSJe8xsm3dMnAInnpRGvwiotSp6jAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1YQWRFUyBUZXN0IENBMCAXDTc1MDEwMTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAYMRYwFAYDVQQDDA1YQWRFUyBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcd/LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yeJpCY9SCKvzQjZcIWqfb8o+p1YfQ/EzMII/xbe4/GVQDAKBggqhkjOPQQDAgNIADBFAiEA34ISXnPYu5LRBb0itF0Nlmm4imiZ5YUKZahKnnmmAMQCIBWBr/GnmGAj5aqM+V6HGzhpwlz6d5ocJqb5GY+WhnHb";

/// PEM of the certificate the XML LoTE fixture is signed with.
fn xades_test_ca_pem() -> String {
    crate::mapper::x509::x5c_into_pem_chain(&[XADES_TEST_CA_B64.to_string()]).unwrap()
}

struct XmlSetup {
    body: String,
    content_type: &'static str,
    trust_anchors: Vec<String>,
    allow_unpinned_root: bool,
    storage: Arc<InMemoryStorage>,
}

impl Default for XmlSetup {
    fn default() -> Self {
        Self {
            body: LOTE_XML.to_string(),
            content_type: "application/xml",
            trust_anchors: vec![],
            allow_unpinned_root: true,
            storage: Arc::new(InMemoryStorage::new(HashMap::new())),
        }
    }
}

fn setup_subscriber_xml(reference: &Url) -> EtsiLoteSubscriber {
    setup_xml(reference, XmlSetup::default()).1
}

/// XML LoTE subscriber over real XAdES; certificates other than `TRUSTED_CERT` are identified
/// by the hash of their PEM, and only `TRUSTED_CERT` acts as a CA.
fn setup_xml(reference: &Url, setup: XmlSetup) -> (Arc<EtsiLoteResolver>, EtsiLoteSubscriber) {
    let mut client = MockHttpClient::new();
    mock_http_get_request(
        &mut client,
        reference.to_string(),
        Response {
            body: setup.body.as_bytes().to_vec(),
            headers: hashmap! { "Content-Type".to_string() => setup.content_type.to_string() },
            status: StatusCode(200),
            request: Request {
                body: None,
                headers: Default::default(),
                method: Method::Get,
                url: reference.to_string(),
                timeout: None,
            },
        },
    );
    let client = Arc::new(client);
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Ecdsa))
        .returning(|_| Some(Arc::new(Ecdsa)));
    // trust-list certificate keys are indexed via the provider's raw form
    key_algorithm_provider.expect_parse_raw().returning(|der| {
        Ecdsa
            .parse_raw(der)
            .map(|key| ParsedKey {
                algorithm_type: KeyAlgorithmType::Ecdsa,
                key,
            })
            .map_err(|err| {
                KeyAlgorithmProviderError::MissingAlgorithmImplementation(err.to_string())
            })
    });
    let key_algorithm_provider = Arc::new(key_algorithm_provider);
    let cache_storage = setup.storage;

    // XAdES verification needs a certificate validator that returns
    // the test signing key's public key.
    let ecdsa = Ecdsa;
    let signing_cert_der =
        ct_codecs::Base64::decode_to_vec("MIIBMTCB2KADAgECAhQSJe8xsm3dMnAInnpRGvwiotSp6jAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1YQWRFUyBUZXN0IENBMCAXDTc1MDEwMTAwMDAwMFoYDzQwOTYwMTAxMDAwMDAwWjAYMRYwFAYDVQQDDA1YQWRFUyBUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcd/LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yeJpCY9SCKvzQjZcIWqfb8o+p1YfQ/EzMII/xbe4/GVQDAKBggqhkjOPQQDAgNIADBFAiEA34ISXnPYu5LRBb0itF0Nlmm4imiZ5YUKZahKnnmmAMQCIBWBr/GnmGAj5aqM+V6HGzhpwlz6d5ocJqb5GY+WhnHb", None).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(&signing_cert_der).unwrap();
    let key_handle = ecdsa
        .parse_raw(parsed.tbs_certificate.subject_pki.raw)
        .unwrap();

    let mut cert_validator = MockCertificateValidator::new();
    let certificate = {
        let now = OffsetDateTime::now_utc();
        ParsedCertificate {
            attributes: CertificateX509AttributesDTO {
                serial_number: "test".to_string(),
                not_before: now,
                not_after: now,
                issuer: "XAdES Test CA".to_string(),
                subject: "XAdES Test CA".to_string(),
                fingerprint: TRUSTED_FINGERPRINT.to_string(),
                extensions: vec![],
            },
            subject_common_name: Some("XAdES Test CA".to_string()),
            subject_key_identifier: None,
            public_key: key_handle,
        }
    };
    cert_validator
        .expect_parse_pem_chain()
        .with(eq(TRUSTED_CERT), always())
        .returning({
            let certificate = certificate.clone();
            move |_, _| Ok(certificate.clone())
        });
    cert_validator
        .expect_parse_pem_chain()
        .with(ne(TRUSTED_CERT), always())
        .returning({
            let certificate = certificate.clone();
            move |pem, _| {
                let mut certificate = certificate.clone();
                certificate.attributes.fingerprint = pem_hash(pem);
                Ok(certificate)
            }
        });
    cert_validator
        .expect_validate_chain_against_ca_chain()
        .returning(move |_, ca, _, _| {
            if ca == TRUSTED_CERT {
                Ok(certificate.clone())
            } else {
                Err(crate::proto::certificate_validator::Error::CertificateSignatureInvalid)
            }
        });

    let cert_validator = Arc::new(cert_validator);
    let xades = XAdES::new(cert_validator.clone());

    let resolver = Arc::new(EtsiLoteResolver::new(
        Arc::new(TaskLocalClock),
        client,
        Arc::new(MockDidMethodProvider::new()),
        key_algorithm_provider.clone(),
        cert_validator.clone(),
        Arc::new(xades),
        EtsiLoteResolverOptions {
            content_type: LoteContentType::Xml,
            leeway: Duration::seconds(0),
            max_pointer_depth: None,
            trust_anchors: setup.trust_anchors,
            allow_unpinned_root: setup.allow_unpinned_root,
            limits: FetchLimits::default(),
        },
    ));
    let cache = EtsiLoteCache::new(
        cache_storage,
        100,
        Duration::seconds(60),
        Duration::seconds(60),
        Arc::new(TaskLocalClock),
    );

    let subscriber = EtsiLoteSubscriber::new(
        cache,
        resolver.clone(),
        cert_validator,
        key_algorithm_provider,
    );
    (resolver, subscriber)
}

fn pem_hash(pem: &str) -> String {
    use one_crypto::Hasher;
    hex::encode(
        one_crypto::hasher::sha256::SHA256
            .hash(pem.as_bytes())
            .unwrap(),
    )
}

#[tokio::test]
async fn validate_subscription_xml_success() {
    let time = datetime!(2026-04-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote-xml").unwrap();

    let subscriber = setup_subscriber_xml(&reference);

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .validate_subscription(
                &reference,
                Some(TrustListRoleEnum::NationalRegistryRegistrar),
            )
            .await
    })
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn validate_subscription_xml_expired() {
    // After NextUpdate (2026-06-01) but still valid for XAdES signing time check
    let time = datetime!(2026-07-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote-xml").unwrap();

    let subscriber = setup_subscriber_xml(&reference);

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .validate_subscription(&reference, None)
            .await
            .err()
            .unwrap()
    })
    .await;

    assert_eq!(result.error_code(), ErrorCode::BR_0354);
}

#[tokio::test]
async fn resolve_trusted_identifier_xml() {
    let time = datetime!(2026-04-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote-xml").unwrap();

    let subscriber = setup_subscriber_xml(&reference);

    let identifier_id = Uuid::new_v4().into();
    let identifier = certificate_identifier(identifier_id, TRUSTED_CERT, TRUSTED_FINGERPRINT);

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[identifier])
            .await
            .unwrap()
    })
    .await;

    assert_eq!(result.len(), 1);
    assert!(result.contains_key(&identifier_id));
}

#[tokio::test]
async fn resolve_untrusted_identifier_xml() {
    let time = datetime!(2026-04-01 00:00 UTC);
    let reference = Url::parse("https://example.com/lote-xml").unwrap();

    let subscriber = setup_subscriber_xml(&reference);

    let identifier_id = Uuid::new_v4().into();
    let identifier = certificate_identifier(identifier_id, UNTRUSTED_CERT, "unknown fingerprint");

    let result = run_with_mocked_time_async(time, async move {
        subscriber
            .resolve_entries(&reference, &[identifier])
            .await
            .unwrap()
    })
    .await;

    assert!(result.is_empty());
}

fn certificate_identifier(
    identifier_id: shared_types::IdentifierId,
    chain: &str,
    fingerprint: &str,
) -> Identifier {
    let now = crate::clock::now_utc();
    Identifier {
        id: identifier_id,
        created_date: now,
        last_modified: now,
        name: "".to_string(),
        r#type: IdentifierType::Certificate,
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: None,
        did: None,
        key: None,
        certificates: Some(vec![Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation_id: None,
            created_date: now,
            last_modified: now,
            expiry_date: now,
            name: "".to_string(),
            chain: chain.to_string(),
            fingerprint: fingerprint.to_string(),
            state: CertificateState::Active,
            key: Some(dummy_key()),
        }]),
    }
}

#[tokio::test]
async fn xml_root_pinned_to_anchor_is_accepted() {
    let reference = Url::parse("https://example.com/lote-xml").unwrap();
    let (resolver, _) = setup_xml(
        &reference,
        XmlSetup {
            trust_anchors: vec![xades_test_ca_pem()],
            allow_unpinned_root: false,
            ..Default::default()
        },
    );
    let pin = resolver.root_pin().unwrap();

    let collection = run_with_mocked_time_async(
        datetime!(2026-04-01 00:00 UTC),
        resolver.collect(reference.as_str(), &pin),
    )
    .await
    .unwrap();

    assert!(!collection.unpinned);
    assert_eq!(collection.lists.len(), 1);
}

#[tokio::test]
async fn xml_root_signed_by_unknown_key_is_rejected() {
    let reference = Url::parse("https://example.com/lote-xml").unwrap();
    let (resolver, _) = setup_xml(
        &reference,
        XmlSetup {
            trust_anchors: vec![UNTRUSTED_CERT.to_string()],
            allow_unpinned_root: false,
            ..Default::default()
        },
    );
    let pin = resolver.root_pin().unwrap();

    let result = run_with_mocked_time_async(
        datetime!(2026-04-01 00:00 UTC),
        resolver.collect(reference.as_str(), &pin),
    )
    .await;

    assert!(matches!(result, Err(FetchError::SignerNotTrusted)));
}

#[tokio::test]
async fn root_without_anchors_is_refused_unless_allowed() {
    let reference = Url::parse("https://example.com/lote-xml").unwrap();
    let (_, subscriber) = setup_xml(
        &reference,
        XmlSetup {
            allow_unpinned_root: false,
            ..Default::default()
        },
    );

    let result = subscriber.validate_subscription(&reference, None).await;

    assert!(matches!(
        result,
        Err(TrustListSubscriberError::Fetch(
            FetchError::UnpinnedNotAllowed
        ))
    ));
}

#[tokio::test]
async fn xml_media_type_parameters_are_ignored() {
    let reference = Url::parse("https://example.com/lote-xml").unwrap();
    let (_, subscriber) = setup_xml(
        &reference,
        XmlSetup {
            content_type: "application/xml; charset=utf-8",
            ..Default::default()
        },
    );

    let result = run_with_mocked_time_async(
        datetime!(2026-04-01 00:00 UTC),
        subscriber.validate_subscription(&reference, None),
    )
    .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn closed_xml_lote_is_rejected() {
    let reference = Url::parse("https://example.com/lote-xml").unwrap();
    let closed = LOTE_XML.replacen(
        "<NextUpdate><dateTime>2026-06-01T00:00:00Z</dateTime></NextUpdate>",
        "",
        1,
    );
    assert_ne!(closed, LOTE_XML);
    let (resolver, _) = setup_xml(
        &reference,
        XmlSetup {
            body: closed,
            ..Default::default()
        },
    );

    let result = run_with_mocked_time_async(
        datetime!(2026-04-01 00:00 UTC),
        resolver.collect(reference.as_str(), &SignerPin::Unpinned),
    )
    .await;

    assert!(matches!(result, Err(FetchError::Closed)));
}

#[tokio::test]
async fn pointer_pin_rejects_a_foreign_signer() {
    let reference = Url::parse("https://example.com/lote-xml").unwrap();
    let (_, subscriber) = setup_xml(&reference, XmlSetup::default());

    // the LoTL pointer names a certificate other than the LoTE's actual signer
    let pin = SignerPin::Pointer {
        pems: vec![UNTRUSTED_CERT.to_string()],
    };
    let result = run_with_mocked_time_async(
        datetime!(2026-04-01 00:00 UTC),
        subscriber.resolve_certificate_pinned(&reference, TRUSTED_CERT, &pin),
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn pointer_pin_accepts_the_named_signer() {
    let reference = Url::parse("https://example.com/lote-xml").unwrap();
    let (_, subscriber) = setup_xml(&reference, XmlSetup::default());

    // rollover: the actual signer is the second certificate the pointer names
    let pin = SignerPin::Pointer {
        pems: vec![UNTRUSTED_CERT.to_string(), xades_test_ca_pem()],
    };
    let result = run_with_mocked_time_async(
        datetime!(2026-04-01 00:00 UTC),
        subscriber.resolve_certificate_pinned(&reference, TRUSTED_CERT, &pin),
    )
    .await
    .unwrap();

    assert_eq!(result.len(), 1);
}

#[tokio::test]
async fn unpinned_cache_entry_does_not_satisfy_a_pinned_lookup() {
    let reference = Url::parse("https://example.com/lote-xml").unwrap();
    // an entry cached under the unpinned policy that would match TRUSTED_CERT
    let (_, unpinned) = setup_xml(&reference, XmlSetup::default());
    let storage = Arc::new(InMemoryStorage::new(HashMap::new()));
    let (_, seeded) = setup_xml(
        &reference,
        XmlSetup {
            storage: storage.clone(),
            ..Default::default()
        },
    );
    run_with_mocked_time_async(
        datetime!(2026-04-01 00:00 UTC),
        seeded.resolve_certificate(&reference, TRUSTED_CERT),
    )
    .await
    .unwrap();
    drop(unpinned);

    // same storage, but the root must be signed by an anchor the fixture's signer is not
    let (_, pinned) = setup_xml(
        &reference,
        XmlSetup {
            storage,
            trust_anchors: vec![UNTRUSTED_CERT.to_string()],
            allow_unpinned_root: false,
            ..Default::default()
        },
    );
    let result = run_with_mocked_time_async(
        datetime!(2026-04-01 00:00 UTC),
        pinned.resolve_certificate(&reference, TRUSTED_CERT),
    )
    .await;

    // re-fetched and authenticated under the anchors, which fails
    assert!(result.is_err());
}

#[tokio::test]
async fn closed_jwt_lote_is_rejected() {
    use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

    let reference = Url::parse("https://example.com/lote").unwrap();
    let header = Base64UrlSafeNoPadding::encode_to_string(br#"{"alg":"ES256"}"#).unwrap();
    let payload = Base64UrlSafeNoPadding::encode_to_string(
        serde_json::json!({ "ListAndSchemeInformation": {} }).to_string(),
    )
    .unwrap();
    let token = format!("{header}.{payload}.c2ln");
    let mut client = MockHttpClient::new();
    mock_http_get_request(
        &mut client,
        reference.to_string(),
        Response {
            body: token.into_bytes(),
            headers: hashmap! { "Content-Type".to_string() => "application/jwt".to_string() },
            status: StatusCode(200),
            request: Request {
                body: None,
                headers: Default::default(),
                method: Method::Get,
                url: reference.to_string(),
                timeout: None,
            },
        },
    );
    let resolver = EtsiLoteResolver::new(
        Arc::new(TaskLocalClock),
        Arc::new(client),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockCertificateValidator::new()),
        Arc::new(MockXAdESProto::new()),
        EtsiLoteResolverOptions {
            content_type: LoteContentType::Jwt,
            leeway: Duration::seconds(0),
            max_pointer_depth: None,
            trust_anchors: vec![],
            allow_unpinned_root: true,
            limits: FetchLimits::default(),
        },
    );

    let result = resolver
        .collect(reference.as_str(), &SignerPin::Unpinned)
        .await;

    assert!(matches!(result, Err(FetchError::Closed)));
}
