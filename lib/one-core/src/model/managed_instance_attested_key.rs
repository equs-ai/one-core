use one_dto_mapper::From;
use proc_macros::Model;
use shared_types::{ManagedInstanceAttestedKeyId, ManagedInstanceId, RevocationListEntryId};
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;

use crate::model::relation::Related;
use crate::model::revocation_list::RevocationList;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ManagedInstanceAttestedKey {
    #[model(id)]
    pub id: ManagedInstanceAttestedKeyId,
    pub instance_id: ManagedInstanceId, // cannot be a relation, because wallet instance defines a reverse relation already
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub public_key_jwk: PublicJwk,

    // Relations
    pub revocation: Option<Related<ManagedInstanceAttestedKeyRevocationInfo>>,
}

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ManagedInstanceAttestedKeyRevocationInfo {
    #[model(id)]
    pub id: RevocationListEntryId,
    pub revocation_list: Related<RevocationList>,
    pub revocation_list_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, From)]
#[from(ManagedInstanceAttestedKey)]
pub struct ManagedInstanceAttestedKeyUpsertRequest {
    pub id: ManagedInstanceAttestedKeyId,
    pub instance_id: ManagedInstanceId,
    pub expiration_date: OffsetDateTime,
    pub public_key_jwk: PublicJwk,
}
