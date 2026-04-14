pub mod validator;

pub use one_core_asdk::config::*;

#[cfg(test)]
#[cfg(all(
    feature = "config_yaml",
    feature = "config_json",
    feature = "config_env"
))]
mod test;

// The following entities are moved to one-core-asdk:
// 1. ConfigParsingError
// 2. IncompatibleProviderRef
// 3. ProviderReference
// 4. ProviderReference
// 5. ConfigValidationError

