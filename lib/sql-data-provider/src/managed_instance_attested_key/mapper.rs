use one_core::model::managed_instance_attested_key::{
    ManagedInstanceAttestedKey, ManagedInstanceAttestedKeyUpsertRequest,
};
use one_core::repository::error::DataLayerError;
use sea_orm::Set;

use crate::entity::managed_instance_attested_key::{ActiveModel, Model};

impl TryFrom<Model> for ManagedInstanceAttestedKey {
    type Error = DataLayerError;

    fn try_from(value: Model) -> Result<Self, DataLayerError> {
        Ok(Self {
            id: value.id,
            instance_id: value.managed_instance_id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            expiration_date: value.expiration_date,
            public_key_jwk: serde_json::from_str(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?,
            revocation: None,
        })
    }
}

impl TryFrom<ManagedInstanceAttestedKey> for ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: ManagedInstanceAttestedKey) -> Result<Self, DataLayerError> {
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            expiration_date: Set(value.expiration_date),
            public_key_jwk: Set(serde_json::to_string(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?),
            managed_instance_id: Set(value.instance_id),
            revocation_list_entry_id: Set(None),
        })
    }
}

impl TryFrom<ManagedInstanceAttestedKeyUpsertRequest> for ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: ManagedInstanceAttestedKeyUpsertRequest) -> Result<Self, DataLayerError> {
        let now = one_core::clock::now_utc();
        Ok(Self {
            id: Set(value.id),
            created_date: Set(now),
            last_modified: Set(now),
            expiration_date: Set(value.expiration_date),
            public_key_jwk: Set(serde_json::to_string(&value.public_key_jwk)
                .map_err(|_| DataLayerError::MappingError)?),
            managed_instance_id: Set(value.instance_id),
            revocation_list_entry_id: Set(None),
        })
    }
}
