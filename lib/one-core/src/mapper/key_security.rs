use standardized_types::openid4vci::KeyStorageSecurityLevel;

use crate::config::core_config::KeySecurityLevelType;
use crate::model::credential_schema::KeyStorageSecurity;

impl From<KeyStorageSecurityLevel> for KeySecurityLevelType {
    fn from(value: KeyStorageSecurityLevel) -> Self {
        match value {
            KeyStorageSecurityLevel::High => KeySecurityLevelType::High,
            KeyStorageSecurityLevel::Moderate => KeySecurityLevelType::Moderate,
            KeyStorageSecurityLevel::EnhancedBasic => KeySecurityLevelType::EnhancedBasic,
            KeyStorageSecurityLevel::Basic => KeySecurityLevelType::Basic,
        }
    }
}

impl From<KeyStorageSecurityLevel> for KeyStorageSecurity {
    fn from(value: KeyStorageSecurityLevel) -> Self {
        match value {
            KeyStorageSecurityLevel::High => KeyStorageSecurity::High,
            KeyStorageSecurityLevel::Moderate => KeyStorageSecurity::Moderate,
            KeyStorageSecurityLevel::EnhancedBasic => KeyStorageSecurity::EnhancedBasic,
            KeyStorageSecurityLevel::Basic => KeyStorageSecurity::Basic,
        }
    }
}

impl From<KeyStorageSecurity> for KeyStorageSecurityLevel {
    fn from(value: KeyStorageSecurity) -> Self {
        match value {
            KeyStorageSecurity::High => KeyStorageSecurityLevel::High,
            KeyStorageSecurity::Moderate => KeyStorageSecurityLevel::Moderate,
            KeyStorageSecurity::EnhancedBasic => KeyStorageSecurityLevel::EnhancedBasic,
            KeyStorageSecurity::Basic => KeyStorageSecurityLevel::Basic,
        }
    }
}
