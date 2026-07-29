use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use autometrics::autometrics;
use one_core::model::claim::Claim;
use one_core::model::relation::{BatchModelLoader, Related};
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::error::DataLayerError;
use sea_orm::{
    ColumnTrait, EntityTrait, FromQueryResult, JoinType, QueryFilter, QueryOrder, QuerySelect,
    RelationTrait,
};
use shared_types::{ClaimId, CredentialId};
use uuid::Uuid;

use super::ClaimProvider;
use crate::claim::mapper::claim_from_model;
use crate::entity::{claim, claim_schema};
use crate::mapper::to_data_layer_error;

#[autometrics]
#[async_trait::async_trait]
impl ClaimRepository for ClaimProvider {
    async fn create_claim_list(&self, claims: Vec<Claim>) -> Result<(), DataLayerError> {
        let models: Vec<claim::ActiveModel> = claims.into_iter().map(Into::into).collect();

        claim::Entity::insert_many(models)
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }

    async fn delete_claims_for_credential(
        &self,
        request: CredentialId,
    ) -> Result<(), DataLayerError> {
        claim::Entity::delete_many()
            .filter(claim::Column::CredentialId.eq(request))
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }

    async fn delete_claims_for_credentials(
        &self,
        request: HashSet<CredentialId>,
    ) -> Result<(), DataLayerError> {
        claim::Entity::delete_many()
            .filter(claim::Column::CredentialId.is_in(request))
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }

    async fn get_claim_list(&self, ids: Vec<ClaimId>) -> Result<Vec<Claim>, DataLayerError> {
        let claims_cnt = ids.len();
        let claim_id_to_index: HashMap<shared_types::ClaimId, usize> = ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id, index))
            .collect();

        let mut models = claim::Entity::find()
            .filter(claim::Column::Id.is_in(claim_id_to_index.keys()))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        if claims_cnt != models.len() {
            return Err(DataLayerError::IncompleteClaimsList {
                expected: claims_cnt,
                got: models.len(),
            });
        }

        #[allow(clippy::indexing_slicing)]
        models.sort_by_key(|model| claim_id_to_index[&model.id]);

        // A single loader shared by all returned claims: the claim schemas are fetched lazily, but
        // when they are, it happens with one query for the whole batch.
        let schema_loader = BatchModelLoader::new(
            models.iter().map(|model| model.claim_schema_id),
            self.claim_schema_repository.clone(),
        );

        Ok(models
            .into_iter()
            .map(|model| {
                let schema = Related::new(model.claim_schema_id, schema_loader.clone());
                claim_from_model(model, schema)
            })
            .collect())
    }

    async fn get_claims_for_credential(
        &self,
        credential_id: CredentialId,
    ) -> Result<Vec<Claim>, DataLayerError> {
        #[derive(FromQueryResult)]
        struct ClaimIdModel {
            pub id: String,
        }

        let ids: Vec<ClaimId> = claim::Entity::find()
            .select_only()
            .columns([claim::Column::Id])
            .filter(claim::Column::CredentialId.eq(credential_id))
            .join(JoinType::InnerJoin, claim::Relation::ClaimSchema.def())
            .join(
                JoinType::InnerJoin,
                claim_schema::Relation::CredentialSchema.def(),
            )
            // sorting claims according to the order from credential_schema
            .order_by_asc(claim_schema::Column::Order)
            .into_model::<ClaimIdModel>()
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?
            .into_iter()
            .map(|claim| Uuid::from_str(&claim.id).map(ClaimId::from))
            .collect::<Result<Vec<_>, _>>()?;

        self.get_claim_list(ids).await
    }
}
