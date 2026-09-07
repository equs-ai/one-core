pub use one_core_portable::model::common::*;

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
