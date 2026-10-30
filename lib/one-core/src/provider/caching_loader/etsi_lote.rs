use std::sync::Arc;

use crate::error::ContextWithErrorCode;
use crate::proto::clock::Clock;
use crate::provider::caching_loader::{CacheError, CachingLoader, Resolver, ResolverError};
use crate::provider::remote_entity_storage::{RemoteEntityStorage, RemoteEntityType};

/// Cache of pre-processed ETSI LoTE lists.
pub struct EtsiLoteCache {
    inner: CachingLoader,
}

impl EtsiLoteCache {
    pub fn new(
        storage: Arc<dyn RemoteEntityStorage>,
        cache_size: usize,
        cache_refresh_timeout: time::Duration,
        refresh_after: time::Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner: CachingLoader::new(
                RemoteEntityType::TrustList,
                storage,
                cache_size,
                cache_refresh_timeout,
                refresh_after,
            )
            .with_clock(clock),
        }
    }

    pub async fn get_with(
        &self,
        key: &str,
        resolver: Arc<dyn Resolver<Error = ResolverError>>,
    ) -> Result<Vec<u8>, CacheError> {
        let (content, _) = self
            .inner
            .get(key, resolver, false)
            .await
            .error_while("getting ETSI LoTE")?;
        Ok(content)
    }
}
