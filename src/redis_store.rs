#[cfg(feature = "redis")]
use std::sync::Arc;
#[cfg(feature = "redis")]
use std::time::Duration;

#[cfg(feature = "redis")]
use async_trait::async_trait;
#[cfg(feature = "redis")]
use deadpool_redis::redis::Script;
#[cfg(feature = "redis")]
use deadpool_redis::{Connection, Pool};

use crate::{
    error::BarnacleError,
    types::{hash_api_key, BarnacleConfig, BarnacleContext, BarnacleKey, BarnacleResult},
    BarnacleStore, BARNACLE_API_KEY_PREFIX, BARNACLE_CUSTOM_PREFIX, BARNACLE_EMAIL_KEY_PREFIX,
    BARNACLE_IP_PREFIX,
};

/// Checks and increments a fixed-window counter in a single atomic step.
///
/// KEYS[1] = counter key, ARGV[1] = max requests, ARGV[2] = window in seconds.
/// Returns `{allowed (0/1), count, ttl}`.
///
/// A counter left without expiry (TTL -1, e.g. by a failed `EXPIRE` in older versions)
/// gets its expiry restored, so it can never block a key forever.
#[cfg(feature = "redis")]
const INCREMENT_SCRIPT: &str = r#"
local max = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local ttl = redis.call('TTL', KEYS[1])
if current >= max then
  if ttl == -1 then
    redis.call('EXPIRE', KEYS[1], window)
    ttl = window
  elseif ttl < 0 then
    ttl = window
  end
  return {0, current, ttl}
end
local count = redis.call('INCR', KEYS[1])
if ttl < 0 then
  redis.call('EXPIRE', KEYS[1], window)
  ttl = window
end
return {1, count, ttl}
"#;

/// Reads a counter without incrementing it, restoring a missing expiry like
/// [`INCREMENT_SCRIPT`] so a counter over the limit can't be stuck by `peek` alone.
///
/// KEYS[1] = counter key, ARGV[1] = window in seconds. Returns `{count, ttl}`.
#[cfg(feature = "redis")]
const PEEK_SCRIPT: &str = r#"
local window = tonumber(ARGV[1])
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local ttl = redis.call('TTL', KEYS[1])
if ttl == -1 then
  redis.call('EXPIRE', KEYS[1], window)
  ttl = window
end
return {current, ttl}
"#;

#[cfg(feature = "redis")]
struct RedisBarnacleStoreInner {
    pool: Pool,
    increment_script: Script,
    peek_script: Script,
}

#[cfg(feature = "redis")]
impl RedisBarnacleStoreInner {
    fn new(pool: Pool) -> Self {
        Self {
            pool,
            increment_script: Script::new(INCREMENT_SCRIPT),
            peek_script: Script::new(PEEK_SCRIPT),
        }
    }

    async fn get_connection(&self) -> Result<Connection, BarnacleError> {
        self.pool.get().await.map_err(|e| {
            BarnacleError::connection_pool_error("Failed to get Redis connection", Box::new(e))
        })
    }

    fn get_redis_key(&self, context: &BarnacleContext) -> String {
        let base_key = match &context.key {
            BarnacleKey::Email(email) => format!("{BARNACLE_EMAIL_KEY_PREFIX}:{}", email),
            // API keys are hashed so they are never stored in clear text
            BarnacleKey::ApiKey(api_key) => {
                format!("{BARNACLE_API_KEY_PREFIX}:{}", hash_api_key(api_key))
            }
            BarnacleKey::Ip(ip) => format!("{BARNACLE_IP_PREFIX}:{}", ip),
            BarnacleKey::Custom(custom_data) => format!("{BARNACLE_CUSTOM_PREFIX}:{}", custom_data),
        };

        // Include path and method in the Redis key
        format!("{}:{}:{}", base_key, context.method, context.path)
    }
}

/// Window length in seconds, at least 1 (`EXPIRE 0` would delete the counter).
#[cfg(feature = "redis")]
fn window_seconds(config: &BarnacleConfig) -> u64 {
    config.window.as_secs().max(1)
}

/// Seconds until the window resets (at least 1, as Redis reports 0 in the last second),
/// falling back to the full window when Redis reports no expiry.
#[cfg(feature = "redis")]
fn reset_after(ttl: i64, config: &BarnacleConfig) -> Duration {
    if ttl >= 0 {
        Duration::from_secs(ttl.max(1) as u64)
    } else {
        Duration::from_secs(window_seconds(config))
    }
}

/// Connection pool settings for [`RedisBarnacleStore::from_url_with_options`] and
/// [`crate::RedisApiKeyStore::from_url_with_options`].
///
/// Without timeouts a slow or unreachable Redis makes every rate limited request
/// wait indefinitely for a connection. The defaults are meant to survive a slow TLS
/// handshake or a cross-AZ connect: use [`crate::StoreFailurePolicy::FailOpen`] or
/// `with_store_timeout` to bound the wait a request is willing to accept, rather than
/// timeouts so short that opening a connection normally fails.
#[cfg(feature = "redis")]
#[derive(Clone, Debug)]
pub struct RedisPoolOptions {
    /// Maximum number of connections (deadpool default: 2 × CPU cores)
    pub max_size: Option<usize>,
    /// Maximum time to wait for a free connection (default: 2s)
    pub wait_timeout: Option<Duration>,
    /// Maximum time to open a new connection (default: 5s)
    pub create_timeout: Option<Duration>,
    /// Maximum time to check a connection before reusing it (default: 2s)
    pub recycle_timeout: Option<Duration>,
}

#[cfg(feature = "redis")]
impl Default for RedisPoolOptions {
    fn default() -> Self {
        Self {
            max_size: None,
            wait_timeout: Some(Duration::from_secs(2)),
            // Opening a connection is the slowest step (DNS, TCP, TLS, AUTH): a short
            // timeout here turns a healthy but distant Redis into a 503
            create_timeout: Some(Duration::from_secs(5)),
            recycle_timeout: Some(Duration::from_secs(2)),
        }
    }
}

/// Builds a pool with the given options, shared by both Redis-backed stores.
#[cfg(feature = "redis")]
pub(crate) fn create_pool(
    url: &str,
    options: &RedisPoolOptions,
) -> Result<Pool, deadpool_redis::PoolError> {
    let mut pool_config = deadpool_redis::PoolConfig::default();
    if let Some(max_size) = options.max_size {
        pool_config.max_size = max_size;
    }
    pool_config.timeouts = deadpool_redis::Timeouts {
        wait: options.wait_timeout,
        create: options.create_timeout,
        recycle: options.recycle_timeout,
    };

    let mut cfg = deadpool_redis::Config::from_url(url);
    cfg.pool = Some(pool_config);
    cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .map_err(|e| {
            deadpool_redis::PoolError::Backend(deadpool_redis::redis::RedisError::from(
                std::io::Error::other(e),
            ))
        })
}

/// Implementation of BarnacleStore using Redis with connection pooling.
/// This struct encapsulates Arc internally, so consumers don't need to wrap it.
#[cfg(feature = "redis")]
#[derive(Clone)]
pub struct RedisBarnacleStore {
    inner: Arc<RedisBarnacleStoreInner>,
}

#[cfg(feature = "redis")]
impl RedisBarnacleStore {
    /// Create a new Redis store with connection pooling
    pub fn new(pool: Pool) -> Self {
        Self {
            inner: Arc::new(RedisBarnacleStoreInner::new(pool)),
        }
    }

    /// Create a new Redis store from a Redis URL, with the default [`RedisPoolOptions`]
    pub fn from_url(url: &str) -> Result<Self, deadpool_redis::PoolError> {
        Self::from_url_with_options(url, RedisPoolOptions::default())
    }

    /// Create a new Redis store with the given pool size and the default timeouts
    pub fn with_pool_config(url: &str, max_size: usize) -> Result<Self, deadpool_redis::PoolError> {
        Self::from_url_with_options(
            url,
            RedisPoolOptions {
                max_size: Some(max_size),
                ..Default::default()
            },
        )
    }

    /// Create a new Redis store with pool size and timeouts
    pub fn from_url_with_options(
        url: &str,
        options: RedisPoolOptions,
    ) -> Result<Self, deadpool_redis::PoolError> {
        Ok(Self::new(create_pool(url, &options)?))
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl BarnacleStore for RedisBarnacleStore {
    async fn increment(
        &self,
        context: &BarnacleContext,
        config: &BarnacleConfig,
    ) -> Result<BarnacleResult, BarnacleError> {
        let redis_key = self.inner.get_redis_key(context);
        let mut conn = self.inner.get_connection().await?;

        let (allowed, count, ttl): (i64, u32, i64) = self
            .inner
            .increment_script
            .key(&redis_key)
            .arg(config.max_requests)
            .arg(window_seconds(config))
            .invoke_async(&mut conn)
            .await
            .map_err(|e| {
                BarnacleError::store_error_with_source("Redis increment script failed", Box::new(e))
            })?;

        let reset_after = reset_after(ttl, config);

        if allowed == 0 {
            tracing::debug!(
                "Rate limit exceeded for key: {:?}, current: {}, max: {}, retry_after: {}s",
                context.key,
                count,
                config.max_requests,
                reset_after.as_secs()
            );
            return Err(BarnacleError::rate_limit_exceeded(
                0,
                reset_after.as_secs(),
                config.max_requests,
            ));
        }

        Ok(BarnacleResult {
            allowed: true,
            remaining: config.max_requests.saturating_sub(count),
            retry_after: Some(reset_after),
        })
    }

    async fn reset(&self, context: &BarnacleContext) -> Result<(), BarnacleError> {
        let redis_key = self.inner.get_redis_key(context);
        let mut conn = self.inner.get_connection().await?;

        let _: () = deadpool_redis::redis::cmd("DEL")
            .arg(&redis_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                BarnacleError::store_error_with_source("Failed to delete key from Redis", Box::new(e))
            })?;

        Ok(())
    }

    async fn peek(
        &self,
        context: &BarnacleContext,
        config: &BarnacleConfig,
    ) -> Result<BarnacleResult, BarnacleError> {
        let redis_key = self.inner.get_redis_key(context);
        let mut conn = self.inner.get_connection().await?;

        let (count, ttl): (u32, i64) = self
            .inner
            .peek_script
            .key(&redis_key)
            .arg(window_seconds(config))
            .invoke_async(&mut conn)
            .await
            .map_err(|e| {
                BarnacleError::store_error_with_source("Redis peek script failed", Box::new(e))
            })?;

        let reset_after = reset_after(ttl, config);
        if count >= config.max_requests {
            return Err(BarnacleError::rate_limit_exceeded(
                0,
                reset_after.as_secs(),
                config.max_requests,
            ));
        }

        Ok(BarnacleResult {
            allowed: true,
            remaining: config.max_requests - count,
            retry_after: Some(reset_after),
        })
    }
}
