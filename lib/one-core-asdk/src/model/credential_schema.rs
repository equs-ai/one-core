use serde::{Deserialize, Serialize};
use strum::Display;

#[derive(
    Clone, Copy, Debug, Eq, Serialize, Deserialize, PartialEq, Display, Hash, PartialOrd, Ord,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyStorageSecurity {
    High,
    Moderate,
    EnhancedBasic,
    Basic,
}