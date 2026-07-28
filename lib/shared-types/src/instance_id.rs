use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::macros::impls_for_uuid_newtype;

/// Identifier of wallet/verifier instance stored on holder/verifier side
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(transparent)]
#[repr(transparent)]
pub struct InstanceId(Uuid);

impls_for_uuid_newtype!(InstanceId);

#[cfg(feature = "sea-orm")]
use crate::macros::impls_for_seaorm_newtype;

#[cfg(feature = "sea-orm")]
impls_for_seaorm_newtype!(InstanceId);
