use one_dto_mapper::Into;
use strum::{Display, EnumString};

use crate::model::managed_instance::ManagedInstanceOs;

#[derive(Debug, Display, EnumString, Into, Clone, Copy)]
#[into(ManagedInstanceOs)]
#[strum(ascii_case_insensitive, serialize_all = "UPPERCASE")]
pub enum OSName {
    Android,
    Ios,
    Web,
}
