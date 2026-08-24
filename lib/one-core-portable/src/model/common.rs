use shared_types::OrganisationId;
use strum::EnumString;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, EnumString)]
pub enum ExactColumn {
    #[strum(serialize = "name")]
    Name,
}

#[derive(Clone, Debug)]
pub struct GetListQueryParams<SortableColumn> {
    // pagination
    pub page: u32,
    pub page_size: u32,

    // sorting
    pub sort: Option<SortableColumn>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    pub name: Option<String>,
    pub organisation_id: OrganisationId,
    pub exact: Option<Vec<ExactColumn>>,
    pub ids: Option<Vec<Uuid>>,
}

pub enum LockType {
    /// Exclusive lock
    Update,
    /// Shared lock
    Share,
}
