use sea_orm_migration::prelude::*;

use crate::migrations::m20260417_150300_initial::History;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // the verifier_instance entity was removed together with its history entity type
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(History::Table)
                    .and_where(Expr::col(History::EntityType).eq("VERIFIER_INSTANCE"))
                    .to_owned(),
            )
            .await
    }
}
