use one_core::model::managed_instance::{
    InstanceStatus, ManagedInstanceListQuery, ManagedInstanceRole,
};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use similar_asserts::assert_eq;

use crate::fixtures::wallet_provider::{
    create_key_possession_proof, create_verifier_provider_issuer_identifier,
    create_wallet_unit_attestation_issuer_identifier,
};
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_register_instance_wallet_role_successfully() {
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
            params:
              public:
                walletInstanceAttestation:
                    integrityCheck:
                        enabled: false
    "}
    .to_string();
    // given
    let (context, org) = TestContext::new_with_organisation(Some(config)).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();

    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .register_instance(
            "PROCIVIS_ONE",
            "WALLET",
            "ANDROID",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    assert!(resp_json["id"].as_str().is_some());

    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert_eq!(wallet_units.values.len(), 1);
    let wallet_unit = &wallet_units.values[0];
    assert_eq!(wallet_unit.status, InstanceStatus::Active);
}

#[tokio::test]
async fn test_register_instance_verifier_role_successfully() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_verifier_provider_issuer_identifier(&context, &org).await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let holder_public_jwk = holder_key_pair.key.public_key_as_jwk().unwrap();

    let proof =
        create_key_possession_proof(&holder_key_pair, context.config.app.core_base_url.clone())
            .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .register_instance(
            "PROCIVIS_ONE",
            "VERIFIER",
            "ANDROID",
            Some(&holder_public_jwk),
            Some(&proof),
        )
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    assert!(resp_json["id"].as_str().is_some());

    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert_eq!(wallet_units.values.len(), 1);
    let wallet_unit = &wallet_units.values[0];
    assert_eq!(wallet_unit.status, InstanceStatus::Active);
    assert_eq!(wallet_unit.role, ManagedInstanceRole::Verifier);
}

#[tokio::test]
async fn test_register_instance_verifier_role_provider_not_configured() {
    // given: organisation has no verifierProvider link configured
    let (context, org) = TestContext::new_with_organisation(None).await;
    create_wallet_unit_attestation_issuer_identifier(&context, &org).await;

    // when
    let resp = context
        .api
        .wallet_provider
        .register_instance("PROCIVIS_ONE", "VERIFIER", "ANDROID", None, None)
        .await;

    // then
    assert_eq!(resp.status(), 400);
    let resp_json = resp.json_value().await;
    assert_eq!(resp_json["code"], "BR_0471");

    let wallet_units = context
        .db
        .managed_instances
        .list(ManagedInstanceListQuery::default())
        .await;
    assert_eq!(wallet_units.values.len(), 0);
}
