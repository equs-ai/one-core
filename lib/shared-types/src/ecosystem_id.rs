use std::convert::Infallible;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::macros::{impl_display, impl_from};

/// Identifier of an ecosystem based in CoreConfig.ecosystem
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct EcosystemId(String);

impl FromStr for EcosystemId {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl From<&str> for EcosystemId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for EcosystemId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl_display!(EcosystemId);
impl_from!(EcosystemId; String);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;
#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(EcosystemId);
