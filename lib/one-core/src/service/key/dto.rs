use one_core_portable::model::common::GetListQueryParams;
use one_dto_mapper::Into;
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

use one_core_portable::model::key::SortableKeyColumn;

pub use one_core_portable::service::key::dto::*;

pub struct KeyRequestDTO {
    pub organisation_id: OrganisationId,
    pub key_type: String,
    pub key_params: serde_json::Value,
    pub name: String,
    pub storage_type: String,
    pub storage_params: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct KeyResponseDTO {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub organisation_id: OrganisationId,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
    pub is_remote: bool,
}

pub type GetKeyQueryDTO = GetListQueryParams<SortableKeyColumn>;

#[derive(Debug, Clone, Into)]
#[into(crate::proto::csr_creator::GenerateCsrRequest)]
pub struct KeyGenerateCSRRequestDTO {
    pub profile: KeyGenerateCSRRequestProfile,
    pub subject: KeyGenerateCSRRequestSubjectDTO,
}

#[derive(Debug, Clone, Into, PartialEq, Eq)]
#[into(crate::proto::csr_creator::CsrRequestProfile)]
pub enum KeyGenerateCSRRequestProfile {
    Generic,
    Mdl,
    Ca,
}

#[derive(Debug, Clone, Into)]
#[into(crate::proto::csr_creator::CsrRequestSubject)]
pub struct KeyGenerateCSRRequestSubjectDTO {
    pub country_name: Option<String>,
    pub common_name: Option<String>,

    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug)]
pub struct KeyGenerateCSRResponseDTO {
    pub content: String,
}
