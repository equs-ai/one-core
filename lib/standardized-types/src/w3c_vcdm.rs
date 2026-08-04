//! W3C Verifiable Credentials Data Model
//!
//! Spec <https://www.w3.org/TR/vc-data-model-2.0/>

use serde::{Deserialize, Serialize};
use url::Url;

/// Entry of the `@context` property, which is either a URL pointing at a context document or an
/// embedded context object.
///
/// Spec <https://www.w3.org/TR/vc-data-model-2.0/#contexts>
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(untagged)]
pub enum Context {
    Url(Url),
    Object(serde_json::Map<String, serde_json::Value>),
}

impl From<Url> for Context {
    fn from(value: Url) -> Self {
        Self::Url(value)
    }
}
