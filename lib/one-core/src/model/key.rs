use standardized_types::jwk::PrivateJwk;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::common::GetListResponse;
pub use one_core_portable::model::key::*;
use one_core_portable::service::key::dto::KeyListItemResponseDTO;
use one_dto_mapper::convert_inner;

pub type GetKeyList = GetListResponse<Key>;

pub trait PrivateJwkExt {
    fn supported_key_type(&self) -> KeyAlgorithmType;
}

impl PrivateJwkExt for PrivateJwk {
    fn supported_key_type(&self) -> KeyAlgorithmType {
        match self {
            PrivateJwk::Ec(_) => KeyAlgorithmType::Ecdsa,
            PrivateJwk::Okp(_) => KeyAlgorithmType::Eddsa,
            PrivateJwk::Akp(_) => KeyAlgorithmType::MlDsa,
        }
    }
}

pub type GetKeyListResponseDTO = GetListResponse<KeyListItemResponseDTO>;

impl From<GetKeyList> for GetKeyListResponseDTO {
    fn from(value: GetKeyList) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}
