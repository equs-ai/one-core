//! Legacy OpenID4VP Draft 20 authorization request.
//!
//! Kept solely so the proximity verifier can keep serving wallets that negotiate
//! [`ProtocolVersion::V1`](super::dto::ProtocolVersion::V1). Nothing on the holder side
//! speaks Draft 20 any more.

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use standardized_types::openid4vp::ResponseMode;
use url::Url;

use crate::provider::verification_protocol::openid4vp::mapper::deserialize_with_serde_json;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VPPresentationDefinition,
};

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub(crate) struct OpenID4VP20AuthorizationRequest {
    pub client_id: String,
    #[serde(default)]
    pub client_id_scheme: Option<ClientIdScheme>,

    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,

    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub response_mode: Option<ResponseMode>,
    #[serde(default)]
    pub response_uri: Option<Url>,

    #[serde(default, deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,
    #[serde(default)]
    pub presentation_definition_uri: Option<Url>,

    #[serde(default)]
    pub redirect_uri: Option<String>,
}
