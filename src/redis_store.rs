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

#[cfg(feature = "redis")]
use crate::{
    counters::{
        bucket_states, counter_key, increment_result, peek_result, window_seconds,
        INCREMENT_ALL_SCRIPT, PEEK_SCRIPT,
    },
    error::BarnacleError,
    limits::{Bucket, BucketState},
    types::{BarnacleConfig, BarnacleContext, BarnacleResult},
    BarnacleStore,
};

#[cfg(feature = "redis")]
struct RedisBarnacleStoreInner {
    pool: Pool,
    increment_all_script: Script,
    peek_script: Script,
}

#[cfg(feature = "redis")]
impl RedisBarnacleStoreInner {
    fn new(pool: Pool) -> Self {
        Self {
            pool,
            increment_all_script: Script::new(INCREMENT_ALL_SCRIPT),
            peek_script: Script::new(PEEK_SCRIPT),
        }
    }

    async fn get_connection(&self) -> Result<Connection, BarnacleError> {
        self.pool.get().await.map_err(|e| {
            BarnacleError::connection_pool_error("Failed to get Redis connection", Box::new(e))
        })
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
        let bucket = Bucket {
            context: context.clone(),
            max_requests: config.max_requests,
            window: config.window,
        };
        let state = self
            .increment_all(std::slice::from_ref(&bucket))
            .await?
            .pop()
            .ok_or_else(|| BarnacleError::store_error("Redis increment script returned nothing"))?;
        increment_result(state, context, config)
    }

    async fn increment_all(&self, buckets: &[Bucket]) -> Result<Vec<BucketState>, BarnacleError> {
        if buckets.is_empty() {
            return Ok(Vec::new());
        }
        let mut invocation = self.inner.increment_all_script.prepare_invoke();
        for bucket in buckets {
            invocation
                .key(counter_key(&bucket.context))
                .arg(bucket.max_requests)
                .arg(window_seconds(bucket.window));
        }
        let mut conn = self.inner.get_connection().await?;
        let reply: Vec<i64> = invocation.invoke_async(&mut conn).await.map_err(|e| {
            BarnacleError::store_error_with_source("Redis increment script failed", Box::new(e))
        })?;

        bucket_states(buckets, &reply)
    }

    async fn reset(&self, context: &BarnacleContext) -> Result<(), BarnacleError> {
        let redis_key = counter_key(context);
        let mut conn = self.inner.get_connection().await?;

        let _: () = deadpool_redis::redis::cmd("DEL")
            .arg(&redis_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                BarnacleError::store_error_with_source(
                    "Failed to delete key from Redis",
                    Box::new(e),
                )
            })?;

        Ok(())
    }

    async fn peek(
        &self,
        context: &BarnacleContext,
        config: &BarnacleConfig,
    ) -> Result<BarnacleResult, BarnacleError> {
        let redis_key = counter_key(context);
        let mut conn = self.inner.get_connection().await?;

        let (count, ttl): (u32, i64) = self
            .inner
            .peek_script
            .key(&redis_key)
            .arg(window_seconds(config.window))
            .invoke_async(&mut conn)
            .await
            .map_err(|e| {
                BarnacleError::store_error_with_source("Redis peek script failed", Box::new(e))
            })?;

        peek_result(count, ttl, config)
    }
}
