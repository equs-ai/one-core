use crate::model::key::Key;
use one_dto_mapper::From;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, From)]
#[from(Key)]
pub struct KeyListItemResponseDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
    #[from(rename = "key_reference", with_fn_ref = "Option::is_none")]
    pub is_remote: bool,
}
