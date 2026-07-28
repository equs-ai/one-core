use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_organisation_trust_collections_without_wallet_instance_returns_empty() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .get_trust_collections(&organisation.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp.as_array().unwrap().len(), 0);
}
