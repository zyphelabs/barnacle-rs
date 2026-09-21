use async_trait::async_trait;
#[cfg(feature = "redis")]
use deadpool_redis::redis::{AsyncCommands, Script};
#[cfg(feature = "redis")]
use deadpool_redis::{Connection, Pool};
#[cfg(feature = "redis")]
use std::sync::Arc;

use crate::error::BarnacleError;
use crate::types::{ApiKeyValidationResult, BarnacleConfig, StaticApiKeyConfig};
#[cfg(feature = "redis")]
use crate::types::{hash_api_key, redact_api_key};

/// Trait for API key validation and configuration retrieval
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Validate an API key and return its configuration.
    ///
    /// `Ok(ApiKeyValidationResult::invalid())` means the key does not exist; an
    /// infrastructure failure (the store is unreachable, a query failed) must be
    /// reported as `Err`, so that a backend outage is answered with a 5xx instead of
    /// looking like an invalid key.
    async fn validate_key(&self, api_key: &str) -> Result<ApiKeyValidationResult, BarnacleError>;

    /// Optional: Get rate limit configuration for a specific key
    /// This allows for dynamic per-key configuration
    async fn get_rate_limit_config(&self, api_key: &str) -> Option<BarnacleConfig> {
        // Default implementation returns None, letting validate_key handle config
        let _ = api_key;
        None
    }

    /// Optional: Cache a validated API key for future requests
    /// Default implementation does nothing - stores can override if they support caching
    async fn try_cache_key(
        &self,
        api_key: &str,
        config: &BarnacleConfig,
        ttl_seconds: Option<u64>,
    ) -> Result<(), BarnacleError> {
        let _ = (api_key, config, ttl_seconds);
        Ok(()) // Default: do nothing
    }
}

/// Reads an API key entry and its config, migrating what 0.3 wrote in clear text.
///
/// KEYS[1] = key entry, KEYS[2] = config entry (both under the SHA-256 of the key),
/// KEYS[3] and KEYS[4] = the same two entries under 0.3's clear text names.
/// Returns `{exists (0/1), config or ''}`.
///
/// `RENAME` keeps the remaining TTL of the entry it moves (a key provisioned without
/// expiry stays without one) and removes the clear text name in the same step, so an
/// upgraded deployment keeps working and drains its clear text entries as they are used.
#[cfg(feature = "redis")]
const LOOKUP_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 and redis.call('EXISTS', KEYS[3]) == 1 then
  redis.call('RENAME', KEYS[3], KEYS[1])
  if redis.call('EXISTS', KEYS[2]) == 0 and redis.call('EXISTS', KEYS[4]) == 1 then
    redis.call('RENAME', KEYS[4], KEYS[2])
  end
end
return {redis.call('EXISTS', KEYS[1]), redis.call('GET', KEYS[2]) or ''}
"#;

#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisApiKeyStore {
    pool: Pool,
    default_config: BarnacleConfig,
    key_prefix: String,
    lookup_script: Arc<Script>,
}

#[cfg(feature = "redis")]
impl RedisApiKeyStore {
    pub fn new(pool: Pool) -> Self {
        Self::new_with_config(pool, BarnacleConfig::default())
    }

    pub fn new_with_config(pool: Pool, config: BarnacleConfig) -> Self {
        Self {
            pool,
            default_config: config,
            key_prefix: "barnacle:api_keys".to_string(),
            lookup_script: Arc::new(Script::new(LOOKUP_SCRIPT)),
        }
    }

    /// Create a store from a Redis URL, with the default [`crate::RedisPoolOptions`]
    pub fn from_url(url: &str) -> Result<Self, deadpool_redis::PoolError> {
        Self::from_url_with_options(url, crate::RedisPoolOptions::default())
    }

    /// Create a store from a Redis URL with the given pool size and timeouts
    pub fn from_url_with_options(
        url: &str,
        options: crate::RedisPoolOptions,
    ) -> Result<Self, deadpool_redis::PoolError> {
        Ok(Self::new(crate::redis_store::create_pool(url, &options)?))
    }

    pub fn with_key_prefix(mut self, prefix: String) -> Self {
        self.key_prefix = prefix;
        self
    }

    async fn get_connection(&self) -> Result<Connection, deadpool_redis::PoolError> {
        self.pool.get().await
    }

    // API keys are hashed so they are never stored in clear text
    fn get_redis_key(&self, api_key: &str) -> String {
        format!("{}:{}", self.key_prefix, hash_api_key(api_key))
    }

    fn get_config_key(&self, api_key: &str) -> String {
        format!("{}:config:{}", self.key_prefix, hash_api_key(api_key))
    }

    /// Name 0.3 stored the key under, in clear text
    fn get_legacy_redis_key(&self, api_key: &str) -> String {
        format!("{}:{}", self.key_prefix, api_key)
    }

    /// Name 0.3 stored the key's config under, in clear text
    fn get_legacy_config_key(&self, api_key: &str) -> String {
        format!("{}:config:{}", self.key_prefix, api_key)
    }

    /// Whether the key exists and its raw config, migrating clear text entries left
    /// by 0.3 (see [`LOOKUP_SCRIPT`]).
    async fn lookup(
        &self,
        conn: &mut Connection,
        api_key: &str,
    ) -> Result<(bool, Option<String>), BarnacleError> {
        let (exists, config): (i64, String) = self
            .lookup_script
            .key(self.get_redis_key(api_key))
            .key(self.get_config_key(api_key))
            .key(self.get_legacy_redis_key(api_key))
            .key(self.get_legacy_config_key(api_key))
            .invoke_async(conn)
            .await
            .map_err(|e| {
                BarnacleError::store_error_with_source("Failed to look up API key", Box::new(e))
            })?;

        Ok((exists == 1, (!config.is_empty()).then_some(config)))
    }

    /// The stored config, falling back to the default one when it is absent or corrupt
    fn parse_config(&self, config: Option<String>) -> BarnacleConfig {
        let Some(config_json) = config else {
            return self.default_config.clone();
        };
        serde_json::from_str::<BarnacleConfig>(&config_json).unwrap_or_else(|e| {
            tracing::warn!("Failed to parse config for API key, using default: {}", e);
            self.default_config.clone()
        })
    }

    pub async fn save_key(
        &self,
        api_key: &str,
        config: Option<&BarnacleConfig>,
        ttl_seconds: Option<u64>,
    ) -> Result<(), BarnacleError> {
        let redis_key = self.get_redis_key(api_key);
        let config_key = self.get_config_key(api_key);
        let default_ttl: u64 = 24 * 60 * 60; // 24 hours
        let ttl_api_key_secs: u64 = ttl_seconds.unwrap_or(default_ttl);

        tracing::debug!("Saving API key: {}", redact_api_key(api_key));

        let mut conn = self.get_connection().await.map_err(|e| {
            BarnacleError::connection_pool_error("Failed to get Redis connection", Box::new(e))
        })?;

        conn.set_ex::<_, _, ()>(&redis_key, 1, ttl_api_key_secs)
            .await
            .map_err(|e| {
                BarnacleError::store_error_with_source("Failed to save API key", Box::new(e))
            })?;

        if let Some(cfg) = config {
            let config_json = serde_json::to_string(cfg)
                .map_err(|e| BarnacleError::json_error("Failed to serialize config", e))?;
            conn.set_ex::<_, _, ()>(&config_key, config_json, ttl_api_key_secs)
                .await
                .map_err(|e| {
                    BarnacleError::store_error_with_source(
                        "Failed to save API key config",
                        Box::new(e),
                    )
                })?;
        }

        Ok(())
    }

    /// Validates an API key with a fallback mechanism:
    /// 1. First checks if the key exists in Redis
    /// 2. If not (or if Redis is unreachable), calls the provided validator function
    /// 3. If the validator returns a valid result, saves the key to Redis
    ///
    /// This is useful for validating API keys against a database only when needed
    pub async fn validate_key_with_fallback<F, Fut, E>(
        &self,
        api_key: &str,
        validator: F,
        config: Option<&BarnacleConfig>,
        ttl_seconds: Option<u64>,
    ) -> Result<ApiKeyValidationResult, E>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<Option<String>, E>>,
        E: std::fmt::Debug,
    {
        // First try Redis
        match self.validate_key(api_key).await {
            Ok(validation_result) if validation_result.valid => {
                tracing::debug!("API key found in Redis cache: {}", redact_api_key(api_key));
                return Ok(validation_result);
            }
            Ok(_) => {}
            // The cache is unavailable, not the source of truth: ask the validator
            // instead of rejecting a key that may well be valid
            Err(e) => tracing::warn!("API key cache lookup failed, validating externally: {}", e),
        }

        // If not in Redis, validate with the provided function
        tracing::debug!(
            "API key not found in Redis, validating externally: {}",
            redact_api_key(api_key)
        );

        match validator(api_key.to_string()).await {
            Ok(Some(key_id)) => {
                tracing::debug!("API key validated successfully: {}", redact_api_key(api_key));

                // Save to Redis for future use
                let rate_limit_config = config
                    .cloned()
                    .unwrap_or_else(|| self.default_config.clone());

                if let Err(e) = self
                    .save_key(api_key, Some(&rate_limit_config), ttl_seconds)
                    .await
                {
                    tracing::warn!("Failed to cache API key in Redis: {}", e);
                    // Continue even if caching fails
                }

                Ok(ApiKeyValidationResult::valid_with_config(
                    key_id,
                    rate_limit_config,
                ))
            }
            Ok(None) => {
                tracing::warn!("API key validation failed: {}", redact_api_key(api_key));
                Ok(ApiKeyValidationResult::invalid())
            }
            Err(e) => {
                tracing::error!("API key validation error: {:?}", e);
                Ok(ApiKeyValidationResult::invalid())
            }
        }
    }

    /// Removes one API key from the Redis cache, including any entry 0.3 wrote in
    /// clear text, and returns how many entries were deleted.
    pub async fn invalidate_key(&self, api_key: &str) -> Result<u32, BarnacleError> {
        tracing::debug!("Invalidating API key: {}", redact_api_key(api_key));

        let mut conn = self.get_connection().await.map_err(|e| {
            BarnacleError::connection_pool_error("Failed to get Redis connection", Box::new(e))
        })?;

        let keys = [
            self.get_redis_key(api_key),
            self.get_config_key(api_key),
            self.get_legacy_redis_key(api_key),
            self.get_legacy_config_key(api_key),
        ];
        conn.del(&keys).await.map_err(|e| {
            BarnacleError::store_error_with_source("Failed to delete API key", Box::new(e))
        })
    }

    /// Invalidates all API keys from the Redis cache
    /// This is useful when API keys are modified in the database
    ///
    /// The pattern covers both the hashed entries and any clear text entry left by 0.3.
    pub async fn invalidate_all_keys(&self) -> Result<u32, BarnacleError> {
        tracing::trace!("Invalidating all API keys from Redis cache");

        let mut conn = self.get_connection().await.map_err(|e| {
            BarnacleError::connection_pool_error("Failed to get Redis connection", Box::new(e))
        })?;

        // Find all keys matching our prefix pattern
        let pattern = format!("{}:*", self.key_prefix);
        let keys: Vec<String> = conn.keys(&pattern).await.map_err(|e| {
            BarnacleError::store_error_with_source("Failed to get keys pattern", Box::new(e))
        })?;

        if keys.is_empty() {
            tracing::debug!("No API keys found to invalidate");
            return Ok(0);
        }

        // Delete all found keys
        let deleted_count: u32 = conn.del(&keys).await.map_err(|e| {
            BarnacleError::store_error_with_source("Failed to delete keys", Box::new(e))
        })?;

        tracing::debug!("Invalidated {} API key cache entries", deleted_count);
        Ok(deleted_count)
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl ApiKeyStore for RedisApiKeyStore {
    async fn validate_key(&self, api_key: &str) -> Result<ApiKeyValidationResult, BarnacleError> {
        tracing::debug!("Validating API key: {}", redact_api_key(api_key));

        // A Redis outage is an infrastructure failure, not an invalid key: reporting it
        // as invalid would answer 401 and, with a failed validation limit configured,
        // count the blip against the client
        let mut conn = self.get_connection().await.map_err(|e| {
            BarnacleError::connection_pool_error(
                "Failed to get Redis connection during API key validation",
                Box::new(e),
            )
        })?;

        let (key_exists, config) = self.lookup(&mut conn, api_key).await?;
        if !key_exists {
            tracing::debug!("API key not found: {}", redact_api_key(api_key));
            return Ok(ApiKeyValidationResult::invalid());
        }

        Ok(ApiKeyValidationResult::valid_with_config(
            api_key.to_string(),
            self.parse_config(config),
        ))
    }

    async fn get_rate_limit_config(&self, api_key: &str) -> Option<BarnacleConfig> {
        let mut conn = self.get_connection().await.ok()?;
        // Same read-and-migrate path as validate_key, so a key provisioned by 0.3
        // doesn't lose its per-key configuration
        let (_, config) = self.lookup(&mut conn, api_key).await.ok()?;

        config.and_then(|config_json| serde_json::from_str::<BarnacleConfig>(&config_json).ok())
    }

    async fn try_cache_key(
        &self,
        api_key: &str,
        config: &BarnacleConfig,
        ttl_seconds: Option<u64>,
    ) -> Result<(), BarnacleError> {
        self.save_key(api_key, Some(config), ttl_seconds).await
    }
}

/// Static API key store that uses a predefined set of keys
/// Useful for simple configurations where keys are known at compile time
pub struct StaticApiKeyStore {
    config: StaticApiKeyConfig,
}

impl StaticApiKeyStore {
    pub fn new(config: StaticApiKeyConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl ApiKeyStore for StaticApiKeyStore {
    async fn validate_key(&self, api_key: &str) -> Result<ApiKeyValidationResult, BarnacleError> {
        // Keys are known up front, so a lookup can never fail for infrastructure reasons
        if self.config.key_configs.contains_key(api_key) {
            let config = self.config.get_config_for_key(api_key);
            Ok(ApiKeyValidationResult::valid_with_config(
                api_key.to_string(),
                config.clone(),
            ))
        } else {
            Ok(ApiKeyValidationResult::invalid())
        }
    }

    async fn get_rate_limit_config(&self, api_key: &str) -> Option<BarnacleConfig> {
        if self.config.key_configs.contains_key(api_key) {
            Some(self.config.get_config_for_key(api_key).clone())
        } else {
            None
        }
    }
}
