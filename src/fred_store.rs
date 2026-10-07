use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use fred::{
    clients::Pool,
    interfaces::{ClientLike, KeysInterface, LuaInterface},
    types::{
        config::{Config, ReconnectPolicy},
        Builder, FromValue,
    },
};

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

/// Settings for the pool [`FredBarnacleStore::from_url_with_options`] opens.
///
/// A store built with [`FredBarnacleStore::new`] uses the pool it is given as configured.
#[derive(Clone, Debug)]
pub struct FredPoolOptions {
    /// Number of connections (default: 4)
    pub size: usize,
    /// Maximum time to open a connection (default: 5s)
    pub connection_timeout: Duration,
    /// Maximum time a command may take, waiting for a reconnection included (default: 2s).
    /// Without it a command sent while Redis is unreachable waits for the reconnection.
    pub command_timeout: Duration,
}

impl Default for FredPoolOptions {
    fn default() -> Self {
        Self {
            size: 4,
            // Opening a connection is the slowest step (DNS, TCP, TLS, AUTH): a short
            // timeout here turns a healthy but distant Redis into a 503
            connection_timeout: Duration::from_secs(5),
            command_timeout: Duration::from_secs(2),
        }
    }
}

/// A Lua script run by its hash, so a request does not send the whole script.
struct Script {
    lua: &'static str,
    hash: String,
}

impl Script {
    fn new(lua: &'static str) -> Self {
        Self {
            lua,
            hash: fred::util::sha1_hash(lua),
        }
    }

    /// `EVALSHA`, falling back to `EVAL` when Redis does not know the script (after a restart,
    /// a failover or a `SCRIPT FLUSH`). `EVAL` caches it again, and unlike `SCRIPT LOAD`
    /// followed by `EVALSHA` it cannot lose the script to a flush in between.
    async fn run<R: FromValue>(
        &self,
        pool: &Pool,
        keys: Vec<String>,
        args: Vec<String>,
    ) -> Result<R, fred::error::Error> {
        match pool
            .evalsha(self.hash.as_str(), keys.clone(), args.clone())
            .await
        {
            Err(error) if error.details().starts_with("NOSCRIPT") => {
                pool.eval(self.lua, keys, args).await
            }
            result => result,
        }
    }
}

struct FredBarnacleStoreInner {
    pool: Pool,
    increment_all_script: Script,
    peek_script: Script,
}

/// [`BarnacleStore`] on a [fred](https://docs.rs/fred) connection pool, with the same counters,
/// keys and scripts as [`crate::RedisBarnacleStore`]: the two can share a Redis.
///
/// Clones share the pool.
#[derive(Clone)]
pub struct FredBarnacleStore {
    inner: Arc<FredBarnacleStoreInner>,
}

impl FredBarnacleStore {
    /// Shares `pool`, which the caller connects (`Pool::init`) and configures.
    pub fn new(pool: Pool) -> Self {
        Self {
            inner: Arc::new(FredBarnacleStoreInner {
                pool,
                increment_all_script: Script::new(INCREMENT_ALL_SCRIPT),
                peek_script: Script::new(PEEK_SCRIPT),
            }),
        }
    }

    /// Opens a pool on `url` with the default [`FredPoolOptions`] and connects it.
    pub async fn from_url(url: &str) -> Result<Self, fred::error::Error> {
        Self::from_url_with_options(url, FredPoolOptions::default()).await
    }

    /// Opens a pool on `url` with `options` and connects it.
    pub async fn from_url_with_options(
        url: &str,
        options: FredPoolOptions,
    ) -> Result<Self, fred::error::Error> {
        let pool = Builder::from_config(Config::from_url(url)?)
            .with_connection_config(|config| {
                config.connection_timeout = options.connection_timeout;
            })
            .with_performance_config(|config| {
                config.default_command_timeout = options.command_timeout;
            })
            // Exponential backoff from 100ms to 30s, with no limit on the attempts
            .set_policy(ReconnectPolicy::new_exponential(0, 100, 30_000, 2))
            .build_pool(options.size)?;
        pool.init().await?;
        Ok(Self::new(pool))
    }

    /// The pool the store runs on.
    pub fn pool(&self) -> &Pool {
        &self.inner.pool
    }
}

fn store_error(message: &'static str) -> impl FnOnce(fred::error::Error) -> BarnacleError {
    move |e| BarnacleError::store_error_with_source(message, Box::new(e))
}

#[async_trait]
impl BarnacleStore for FredBarnacleStore {
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
        let keys: Vec<String> = buckets
            .iter()
            .map(|bucket| counter_key(&bucket.context))
            .collect();
        let args: Vec<String> = buckets
            .iter()
            .flat_map(|bucket| {
                [
                    bucket.max_requests.to_string(),
                    window_seconds(bucket.window).to_string(),
                ]
            })
            .collect();
        let reply: Vec<i64> = self
            .inner
            .increment_all_script
            .run(&self.inner.pool, keys, args)
            .await
            .map_err(store_error("Redis increment script failed"))?;
        bucket_states(buckets, &reply)
    }

    async fn reset(&self, context: &BarnacleContext) -> Result<(), BarnacleError> {
        self.inner
            .pool
            .del::<(), _>(counter_key(context))
            .await
            .map_err(store_error("Failed to delete key from Redis"))
    }

    async fn peek(
        &self,
        context: &BarnacleContext,
        config: &BarnacleConfig,
    ) -> Result<BarnacleResult, BarnacleError> {
        let reply: Vec<i64> = self
            .inner
            .peek_script
            .run(
                &self.inner.pool,
                vec![counter_key(context)],
                vec![window_seconds(config.window).to_string()],
            )
            .await
            .map_err(store_error("Redis peek script failed"))?;
        let [count, ttl] = reply[..] else {
            return Err(BarnacleError::store_error(
                "Unexpected Redis peek script reply",
            ));
        };
        peek_result(u32::try_from(count).unwrap_or(u32::MAX), ttl, config)
    }
}
