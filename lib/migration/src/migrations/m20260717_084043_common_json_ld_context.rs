use sea_orm_migration::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::migrations::m20260417_150300_initial::RemoteEntityCache;

#[derive(DeriveMigrationName)]
pub struct Migration;

// Pre-populates a cache entry for the W3C Verifiable Credentials v2 context
// This is useful to avoid hitting rate limits when fetching from w3.org.

const CREDENTIAL_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
const CREDENTIAL_V2_CONTEXT_JSON: &str =
    include_str!("../../../one-core/src/util/context_vc2_0.jsonld");

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(RemoteEntityCache::Table)
                    .cond_where(Expr::col(RemoteEntityCache::Key).eq(CREDENTIAL_V2_CONTEXT))
                    .and_where(Expr::col(RemoteEntityCache::Type).eq("JSON_LD_CONTEXT"))
                    .to_owned(),
            )
            .await?;

        let now = OffsetDateTime::now_utc();
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(RemoteEntityCache::Table)
                    .columns([
                        RemoteEntityCache::Id,
                        RemoteEntityCache::CreatedDate,
                        RemoteEntityCache::LastModified,
                        RemoteEntityCache::LastUsed,
                        RemoteEntityCache::Type,
                        RemoteEntityCache::Key,
                        RemoteEntityCache::Value,
                        RemoteEntityCache::MediaType,
                    ])
                    .values([
                        Uuid::new_v4().to_string().into(),
                        now.into(),
                        now.into(),
                        now.into(),
                        "JSON_LD_CONTEXT".into(),
                        CREDENTIAL_V2_CONTEXT.into(),
                        CREDENTIAL_V2_CONTEXT_JSON.as_bytes().into(),
                        "application/ld+json".into(),
                    ])
                    .map_err(|e| DbErr::Migration(e.to_string()))?
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
