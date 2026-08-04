//! Notification Endpoint
//!
//! Spec <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-endpoint>

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use strum::Display;

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct NotificationRequest {
    pub notification_id: String,
    pub event: NotificationEvent,
    pub event_description: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Display, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[strum(serialize_all = "snake_case")]
pub enum NotificationEvent {
    CredentialAccepted,
    CredentialFailure,
    CredentialDeleted,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_notification_event_serde_names() {
        assert_eq!(
            serde_json::json!("credential_accepted"),
            serde_json::to_value(NotificationEvent::CredentialAccepted).unwrap()
        );
        assert_eq!(
            NotificationEvent::CredentialDeleted,
            serde_json::from_value(serde_json::json!("credential_deleted")).unwrap()
        );
    }
}
