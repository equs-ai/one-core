use one_dto_mapper::From;
use shared_types::{ManagedInstanceAttestedKeyId, ManagedInstanceId};
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;

use crate::model::revocation_list::{RevocationList, RevocationListRelations};

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ManagedInstanceAttestedKey {
    pub id: ManagedInstanceAttestedKeyId,
    pub instance_id: ManagedInstanceId, // cannot be a relation, because wallet instance defines a reverse relation already
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub expiration_date: OffsetDateTime,
    pub public_key_jwk: PublicJwk,

    // Relations
    pub revocation: Option<ManagedInstanceAttestedKeyRevocationInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ManagedInstanceAttestedKeyRelations {
    pub revocation: Option<RevocationListRelations>,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ManagedInstanceAttestedKeyRevocationInfo {
    pub revocation_list: RevocationList,
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
