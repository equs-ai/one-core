use sea_orm_migration::prelude::*;

use crate::datatype::large_blob_null;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Interaction::Table)
                    .add_column(large_blob_null(Interaction::EcosystemData, manager))
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Interaction {
    Table,
    EcosystemData,
}
