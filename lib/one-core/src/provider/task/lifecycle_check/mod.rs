use std::sync::Arc;

use serde_json::Value;
use time::OffsetDateTime;

use self::dto::LifecycleCheckResultDTO;
use super::Task;
use crate::config::core_config::{CoreConfig, FormatType};
use crate::error::ContextWithErrorCode;
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialListQuery, CredentialRole, CredentialStateEnum,
    CredentialType, UpdateCredentialRequest,
};
use crate::model::list_filter::{ComparisonType, ListFilterValue, ValueComparison};
use crate::proto::credential_validity_manager::{
    CredentialValidityManager, is_batch_parent_expired,
};
use crate::provider::revocation::model::RevocationState;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::error::ServiceError;

pub mod dto;

pub(crate) struct LifecycleCheckProvider {
    credential_repository: Arc<dyn CredentialRepository>,
    credential_validity_manager: Arc<dyn CredentialValidityManager>,
    config: Arc<CoreConfig>,
}

impl LifecycleCheckProvider {
    pub fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        credential_validity_manager: Arc<dyn CredentialValidityManager>,
        config: Arc<CoreConfig>,
    ) -> Self {
        LifecycleCheckProvider {
            credential_repository,
            credential_validity_manager,
            config,
        }
    }

    async fn reactivate_expired_suspensions(
        &self,
    ) -> Result<(Vec<shared_types::CredentialId>, u64), ServiceError> {
        let credential_list = self
            .credential_repository
            .get_credential_list(CredentialListQuery {
                filtering: Some(
                    CredentialFilterValue::States(vec![CredentialStateEnum::Suspended]).condition()
                        & CredentialFilterValue::Roles(vec![CredentialRole::Issuer])
                        & CredentialFilterValue::Types(vec![
                            CredentialType::Single,
                            CredentialType::BatchItem,
                        ])
                        & CredentialFilterValue::SuspendEndDate(ValueComparison {
                            comparison: ComparisonType::LessThan,
                            value: crate::clock::now_utc(),
                        })
                        & CredentialFilterValue::Deleted(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting credentials")?;

        for credential in &credential_list.values {
            self.credential_validity_manager
                .change_credential_validity_state(&credential.id, RevocationState::Valid)
                .await
                .error_while("reactivating credential")?;
        }

        let total_checks = credential_list.total_items;
        let reactivated_ids = credential_list
            .values
            .iter()
            .map(|credential| credential.id)
            .collect();

        Ok((reactivated_ids, total_checks))
    }

    async fn expire_stale_credentials(
        &self,
        now: OffsetDateTime,
    ) -> Result<(Vec<shared_types::CredentialId>, u64), ServiceError> {
        let credential_list = self
            .credential_repository
            .get_credential_list(CredentialListQuery {
                filtering: Some(
                    CredentialFilterValue::States(
                        CredentialStateEnum::non_terminal_states().to_vec(),
                    )
                    .condition()
                        & CredentialFilterValue::Roles(vec![
                            CredentialRole::Holder,
                            CredentialRole::Issuer,
                        ])
                        & CredentialFilterValue::Types(vec![
                            CredentialType::Single,
                            CredentialType::BatchParent,
                        ])
                        & CredentialFilterValue::Deleted(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting credentials")?;

        let total_checks = credential_list.total_items;

        let mut expired_ids = vec![];
        for credential in credential_list.values {
            let credential_schema = credential.schema.as_ref().await?;
            let format = credential_schema.format().await?;
            let format_type = self
                .config
                .format
                .get_fields(&format)
                .error_while("getting format config")?
                .r#type;

            // mdoc validity is handled entirely through the MSO refresh cycle, not here
            if format_type == FormatType::Mdoc {
                continue;
            }

            match credential.r#type {
                CredentialType::Single => {
                    if self.expire_if_stale(&credential, now).await? {
                        expired_ids.push(credential.id);
                    }
                }
                CredentialType::BatchParent => {
                    let batch_items = self
                        .credential_repository
                        .get_credential_list(CredentialListQuery {
                            filtering: Some(
                                CredentialFilterValue::ParentCredential(credential.id).condition()
                                    & CredentialFilterValue::Deleted(false),
                            ),
                            ..Default::default()
                        })
                        .await
                        .error_while("getting batch items")?
                        .values;

                    let mut all_items_expired = true;
                    for item in batch_items {
                        let item_now_expired = self.expire_if_stale(&item, now).await?;
                        if item_now_expired {
                            expired_ids.push(item.id);
                        }
                        all_items_expired &=
                            item_now_expired || item.state == CredentialStateEnum::Expired;
                    }

                    // the parent is only expired once every item has individually expired, and
                    // its own business-level `expires_at` has passed or the shared OAuth refresh
                    // token has already expired - a still-valid refresh token past `expires_at`
                    // does not keep the batch alive, but a single still-valid item does
                    if all_items_expired && !credential.state.is_terminal() {
                        let interaction = match credential.interaction.as_ref() {
                            Some(interaction) => Some(interaction.as_ref().await?.to_owned()),
                            None => None,
                        };

                        if is_batch_parent_expired(&credential, interaction.as_ref(), now)
                            .error_while("checking batch parent expiry")?
                        {
                            self.credential_repository
                                .update_credential(
                                    credential.id,
                                    UpdateCredentialRequest {
                                        state: Some(CredentialStateEnum::Expired),
                                        ..Default::default()
                                    },
                                )
                                .await
                                .error_while("updating batch parent credential")?;
                            expired_ids.push(credential.id);
                        }
                    }
                }
                CredentialType::BatchItem => {}
            }
        }

        Ok((expired_ids, total_checks))
    }

    async fn expire_if_stale(
        &self,
        credential: &Credential,
        now: OffsetDateTime,
    ) -> Result<bool, ServiceError> {
        if credential.state.is_terminal() {
            return Ok(false);
        }

        if credential
            .expires_at
            .is_none_or(|expires_at| expires_at >= now)
        {
            return Ok(false);
        }

        self.credential_repository
            .update_credential(
                credential.id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Expired),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;

        Ok(true)
    }
}

#[async_trait::async_trait]
impl Task for LifecycleCheckProvider {
    async fn run(&self, _params: Option<Value>) -> Result<Value, ServiceError> {
        let (reactivated_credential_ids, total_reactivation_checks) =
            self.reactivate_expired_suspensions().await?;

        let now = crate::clock::now_utc();
        let (expired_credential_ids, total_expiration_checks) =
            self.expire_stale_credentials(now).await?;

        let result = LifecycleCheckResultDTO {
            reactivated_credential_ids,
            total_reactivation_checks,
            expired_credential_ids,
            total_expiration_checks,
        };

        serde_json::to_value(result).map_err(|e| ServiceError::MappingError(e.to_string()))
    }
}
