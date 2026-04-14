pub use one_core_asdk::model::common::*;

/// The following entities are moved to one-core-asdk:
///     1. SortDirection
///     2. ExactColumn
///     3. GetListQueryParams

#[derive(Clone, Debug)]
pub struct GetListResponse<ResponseItem> {
    pub values: Vec<ResponseItem>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockType {
    /// Exclusive lock
    Update,
    /// Shared lock
    Share,
}
