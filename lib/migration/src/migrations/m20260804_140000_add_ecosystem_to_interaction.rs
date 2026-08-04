use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string_null;

use crate::migrations::m20260417_150300_initial::Interaction;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Interaction::Table)
                    .add_column(string_null(Col::Ecosystem))
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Col {
    Ecosystem,
}
