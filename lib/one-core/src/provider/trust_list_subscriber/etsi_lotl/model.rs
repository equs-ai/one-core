use serde::{Deserialize, Serialize};

use crate::provider::trust_list_subscriber::cert_index::CertIndex;

/// A resolved TS 119 612 trust-service entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TslServiceEntry {
    pub service_name: String,
    pub service_type_identifier: String,
    pub service_status: String,
}

/// Aggregated, signature-verified index built by the LOTL resolver and cached.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PreprocessedLotl {
    pub entries: Vec<TslServiceEntry>,
    /// Map of SKI / fingerprint to indices into `entries`.
    pub cert_index: CertIndex,
    /// Member lists handed to delegate subscribers at resolve time, each pinned to the
    /// certificates its LoTL pointer names.
    #[serde(default)]
    pub delegated_members: Vec<DelegatedMember>,
    /// The root was accepted on its own embedded signer (no configured anchor).
    #[serde(default)]
    pub unpinned: bool,
}

/// A non-TSL member list (e.g. a TS 119 602 LoTE) reached through a LoTL pointer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegatedMember {
    pub url: String,
    /// PEMs of the certificates the pointer names; the member's signer must be one of them.
    pub signer_pems: Vec<String>,
    /// The list type the pointer declares (its `TSLType`), which the member must match.
    #[serde(default)]
    pub declared_type: Option<String>,
    /// The media type the pointer declares, if any.
    #[serde(default)]
    pub mime_type: Option<String>,
}
