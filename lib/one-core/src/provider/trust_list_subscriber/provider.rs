use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use shared_types::TrustListSubscriberId;
use time::Duration;

use crate::config::ConfigValidationError;
use crate::config::core_config::{
    CacheEntityCacheType, CacheEntityConfig, CoreConfig, TrustListSubscriberType,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::clock::Clock;
use crate::proto::http_client::HttpClient;
use crate::proto::xades::XAdESProto;
use crate::provider::caching_loader::etsi_lote::EtsiLoteCache;
use crate::provider::caching_loader::etsi_lotl::EtsiLotlCache;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::remote_entity_storage::RemoteEntityStorage;
use crate::provider::remote_entity_storage::db_storage::DbStorage;
use crate::provider::remote_entity_storage::in_memory::InMemoryStorage;
use crate::provider::trust_list_subscriber::TrustListSubscriber;
use crate::provider::trust_list_subscriber::etsi_lote::resolver::{
    EtsiLoteResolver, EtsiLoteResolverOptions,
};
use crate::provider::trust_list_subscriber::etsi_lote::{EtsiLoteParams, EtsiLoteSubscriber};
use crate::provider::trust_list_subscriber::etsi_lotl::resolver::{
    EtsiLotlResolver, EtsiLotlResolverOptions,
};
use crate::provider::trust_list_subscriber::etsi_lotl::{EtsiLotlParams, EtsiLotlSubscriber};
use crate::provider::trust_list_subscriber::fetch::FetchLimits;
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;

#[cfg_attr(test, mockall::automock)]
pub trait TrustListSubscriberProvider: Send + Sync {
    fn get(&self, subscriber_id: &TrustListSubscriberId) -> Option<Arc<dyn TrustListSubscriber>>;
}

struct TrustListSubscriberProviderImpl {
    subscribers: HashMap<TrustListSubscriberId, Arc<dyn TrustListSubscriber>>,
}

impl TrustListSubscriberProvider for TrustListSubscriberProviderImpl {
    fn get(&self, subscriber_id: &TrustListSubscriberId) -> Option<Arc<dyn TrustListSubscriber>> {
        self.subscribers.get(subscriber_id).cloned()
    }
}

pub(crate) fn trust_list_subscriber_provider_from_config(
    config: &mut CoreConfig,
    clock: Arc<dyn Clock>,
    client: Arc<dyn HttpClient>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    xades_proto: Arc<dyn XAdESProto>,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> Result<Arc<dyn TrustListSubscriberProvider>, ConfigValidationError> {
    let mut subscribers: HashMap<TrustListSubscriberId, Arc<dyn TrustListSubscriber>> =
        HashMap::new();

    // pass 1: build non-LOTL subscribers. LOTL is deferred to pass 2 since it may
    // delegate to a subscriber built here
    for (key, fields) in config.trust_list_subscriber.iter() {
        if !fields.enabled {
            continue;
        }
        let subscriber: Arc<dyn TrustListSubscriber> = match fields.r#type {
            TrustListSubscriberType::EtsiLote => {
                let params: EtsiLoteParams = config.trust_list_subscriber.get(key)?;
                let resolver = Arc::new(EtsiLoteResolver::new(
                    clock.clone(),
                    client.clone(),
                    key_algorithm_provider.clone(),
                    certificate_validator.clone(),
                    xades_proto.clone(),
                    EtsiLoteResolverOptions {
                        content_type: params.accepts,
                        leeway: params.leeway_seconds,
                        max_pointer_depth: params.max_pointer_depth,
                        trust_anchors: params.trust_anchors,
                        allow_unpinned_root: params.allow_unpinned_root,
                        limits: FetchLimits::default(),
                    },
                ));
                let etsi_lote_cache = initialize_etsi_lote_cache(
                    config,
                    remote_entity_cache_repository.clone(),
                    clock.clone(),
                );
                Arc::new(EtsiLoteSubscriber::new(
                    etsi_lote_cache,
                    resolver,
                    certificate_validator.clone(),
                    key_algorithm_provider.clone(),
                )) as _
            }
            // built in pass 2, once its delegates are available
            TrustListSubscriberType::EtsiLotl => continue,
        };
        subscribers.insert(key.clone(), subscriber);
    }

    // pass 2: build LOTL subscribers, wiring their delegates from pass 1
    let lotl_keys: Vec<TrustListSubscriberId> = config
        .trust_list_subscriber
        .iter()
        .filter(|(_, fields)| fields.enabled && fields.r#type == TrustListSubscriberType::EtsiLotl)
        .map(|(key, _)| key.clone())
        .collect();

    for key in lotl_keys {
        let params: EtsiLotlParams = config.trust_list_subscriber.get(&key)?;

        // delegates are tried in their configured order
        let delegate_order = |id: &TrustListSubscriberId| {
            config
                .trust_list_subscriber
                .get_fields(id)
                .ok()
                .and_then(|fields| fields.order)
                .unwrap_or(0)
        };
        let mut delegate_ids = params.delegate_subscribers.clone();
        delegate_ids.sort_by_key(|id| delegate_order(id));
        let delegates = delegate_ids
            .iter()
            .map(|id| {
                subscribers
                    .get(id)
                    .cloned()
                    .ok_or_else(|| ConfigValidationError::EntryNotFound(id.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let resolver = Arc::new(EtsiLotlResolver::new(
            clock.clone(),
            client.clone(),
            certificate_validator.clone(),
            xades_proto.clone(),
            EtsiLotlResolverOptions {
                trust_anchors: params.trust_anchors.clone(),
                allow_unpinned_root: params.allow_unpinned_root,
                leeway: params.leeway_seconds,
                limits: FetchLimits::default(),
            },
        ));
        let cache = initialize_etsi_lotl_cache(
            config,
            remote_entity_cache_repository.clone(),
            clock.clone(),
        );
        subscribers.insert(
            key,
            Arc::new(EtsiLotlSubscriber::new(
                cache,
                resolver,
                certificate_validator.clone(),
                delegates,
            )) as _,
        );
    }

    for (key, value) in config.trust_list_subscriber.iter_mut() {
        if let Some(entity) = subscribers.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    Ok(Arc::new(TrustListSubscriberProviderImpl { subscribers }))
}

fn trust_list_cache_config(config: &CoreConfig) -> CacheEntityConfig {
    config
        .cache_entities
        .entities
        .get("TRUST_LIST")
        .cloned()
        .unwrap_or(CacheEntityConfig {
            cache_refresh_timeout: Duration::days(1),
            cache_size: 100,
            cache_type: CacheEntityCacheType::Db,
            refresh_after: Duration::minutes(5),
        })
}

fn trust_list_storage(
    config: &CacheEntityConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
) -> Arc<dyn RemoteEntityStorage> {
    match config.cache_type {
        CacheEntityCacheType::Db => Arc::new(DbStorage::new(remote_entity_cache_repository)),
        CacheEntityCacheType::InMemory => Arc::new(InMemoryStorage::new(HashMap::new())),
    }
}

fn initialize_etsi_lote_cache(
    config: &CoreConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
    clock: Arc<dyn Clock>,
) -> EtsiLoteCache {
    let config = trust_list_cache_config(config);
    EtsiLoteCache::new(
        trust_list_storage(&config, remote_entity_cache_repository),
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
        clock,
    )
}

fn initialize_etsi_lotl_cache(
    config: &CoreConfig,
    remote_entity_cache_repository: Arc<dyn RemoteEntityCacheRepository>,
    clock: Arc<dyn Clock>,
) -> EtsiLotlCache {
    let config = trust_list_cache_config(config);
    EtsiLotlCache::new(
        trust_list_storage(&config, remote_entity_cache_repository),
        config.cache_size as usize,
        config.cache_refresh_timeout,
        config.refresh_after,
        clock,
    )
}

#[cfg(test)]
mod test;
