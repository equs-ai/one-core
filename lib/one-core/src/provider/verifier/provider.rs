use std::collections::HashMap;
use std::sync::Arc;

use thiserror::Error;

use super::model::VerifierParams;
use crate::config::ConfigValidationError;
use crate::config::core_config::CoreConfig;
use crate::error::{ErrorCode, ErrorCodeMixin};

#[derive(Debug, Error)]
pub(crate) enum VerifierRegistryError {
    #[error("Cannot find verifier provider `{0}`")]
    NotFound(String),
}

impl ErrorCodeMixin for VerifierRegistryError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound(_) => ErrorCode::BR_0380,
        }
    }
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub(crate) trait VerifierProvider: Send + Sync {
    fn get_by_id(&self, id: &str) -> Result<VerifierParams, VerifierRegistryError>;
}

struct VerifierProviderImpl {
    verifiers: HashMap<String, VerifierParams>,
}

impl VerifierProvider for VerifierProviderImpl {
    fn get_by_id(&self, id: &str) -> Result<VerifierParams, VerifierRegistryError> {
        match self.verifiers.get(id) {
            Some(value) => Ok(value.clone()),
            None => Err(VerifierRegistryError::NotFound(id.to_owned())),
        }
    }
}

pub(crate) fn verifier_provider_from_config(
    config: &CoreConfig,
) -> Result<Arc<dyn VerifierProvider>, ConfigValidationError> {
    let mut verifiers = HashMap::new();
    for (name, fields) in config.verifier_provider.iter() {
        let verifier: VerifierParams = serde_json::from_value(
            fields
                .params
                .as_ref()
                .and_then(|params| params.merge())
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|e| ConfigValidationError::FieldsDeserialization {
            key: name.clone(),
            source: e,
        })?;
        verifiers.insert(name.clone(), verifier);
    }

    Ok(Arc::new(VerifierProviderImpl { verifiers }))
}
