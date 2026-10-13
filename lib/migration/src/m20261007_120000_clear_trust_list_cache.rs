use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Drops trust-list cache entries from before they were keyed by signer pin; they are
/// re-resolved on next use.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(RemoteEntityCache::Table)
                    .and_where(Expr::col(RemoteEntityCache::Type).eq("TRUST_LIST"))
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum RemoteEntityCache {
    Table,
    Type,
}
