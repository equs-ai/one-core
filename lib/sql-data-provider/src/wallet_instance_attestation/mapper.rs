use std::sync::Arc;

use one_core::model::relation::Related;
use one_core::model::wallet_instance_attestation::WalletInstanceAttestation;
use one_core::repository::key_repository::KeyRepository;
use sea_orm::Set;

use crate::entity::wallet_instance_attestation::{ActiveModel, Model};

impl From<WalletInstanceAttestation> for ActiveModel {
    fn from(wallet_unit_attestation: WalletInstanceAttestation) -> Self {
        Self {
            id: Set(wallet_unit_attestation.id),
            created_date: Set(wallet_unit_attestation.created_date),
            last_modified: Set(wallet_unit_attestation.last_modified),
            expiration_date: Set(wallet_unit_attestation.expiration_date),
            attestation: Set(wallet_unit_attestation.attestation.into_bytes()),
            revocation_list_url: Set(wallet_unit_attestation.revocation_list_url),
            revocation_list_index: Set(wallet_unit_attestation.revocation_list_index),
            instance_id: Set(wallet_unit_attestation.holder_wallet_unit_id),
            attested_key_id: Set(wallet_unit_attestation.attested_key.id()),
        }
    }
}

pub(super) fn wallet_instance_attestation_from_model(
    value: Model,
    key_repository: &Arc<dyn KeyRepository>,
) -> WalletInstanceAttestation {
    WalletInstanceAttestation {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        expiration_date: value.expiration_date,
        attestation: String::from_utf8_lossy(&value.attestation).to_string(),
        holder_wallet_unit_id: value.instance_id,
        revocation_list_url: value.revocation_list_url,
        revocation_list_index: value.revocation_list_index,
        attested_key: Related::new(value.attested_key_id, key_repository.to_owned()),
    }
}
