use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use serde::{Deserialize, Serialize};

use crate::migrations::m20260417_150300_initial::Organisation;

const EUDI_ECOSYSTEM: &str = "EUDI";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Default, Deserialize)]
#[serde(default)]
struct PreviousConfiguration {
    trusted_rp_required: bool,
    trusted_issuer_required: bool,
    trusted_wallet_provider_required: bool,
}

#[derive(Serialize)]
struct OrganisationConfiguration {
    selected_ecosystems: Vec<String>,
    enforce_ecosystem_as_issuer: bool,
    enforce_ecosystem_as_holder: bool,
    enforce_ecosystem_as_verifier: bool,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        #[derive(FromQueryResult)]
        struct OrganisationEntry {
            id: String,
            configuration: Option<serde_json::Value>,
        }

        let organisations = OrganisationEntry::find_by_statement(
            backend.build(
                Query::select()
                    .column(Organisation::Id)
                    .column(Col::Configuration)
                    .from(Organisation::Table),
            ),
        )
        .all(db)
        .await?;

        for organisation in organisations {
            let previous: PreviousConfiguration = organisation
                .configuration
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .unwrap_or_default();

            let configuration = OrganisationConfiguration {
                selected_ecosystems: vec![EUDI_ECOSYSTEM.to_string()],
                enforce_ecosystem_as_issuer: previous.trusted_wallet_provider_required,
                enforce_ecosystem_as_holder: previous.trusted_rp_required,
                enforce_ecosystem_as_verifier: previous.trusted_issuer_required,
            };

            manager
                .exec_stmt(
                    Query::update()
                        .table(Organisation::Table)
                        .value(
                            Col::Configuration,
                            serde_json::to_value(&configuration)
                                .map_err(|e| DbErr::Migration(e.to_string()))?,
                        )
                        .cond_where(Expr::col(Organisation::Id).eq(organisation.id))
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Col {
    Configuration,
}
