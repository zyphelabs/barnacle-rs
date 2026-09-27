//! Custom rate limiting library with Redis and Axum support
//!
//! This library provides middleware for API rate limiting and API key validation.
//!
//! ## Features
//!
//! - **Rate Limiting**: Configurable rate limiting with Redis backend
//! - **API Key Validation**: Validate requests using x-api-key header
//! - **Per-Principal Rate Limits**: Buckets and limits per authenticated principal
//!   (see [`BarnacleLayerBuilder::with_identifier`])
//! - **Multiple Atomic Limits**: Several [`Limit`]s per request, all or nothing
//! - **Shadow Mode**: Measure limits before enforcing them (see [`Mode::Shadow`])
//! - **Extensible Design**: Custom key stores and rate limiting strategies
//! - **Redis Integration**: Default Redis-based storage for keys and rate limits
//! - **Axum Middleware**: Ready-to-use middleware for Axum web framework
//!
//! ## Basic Usage
//!
//! ```rust,no_run
//! use barnacle_rs::{BarnacleLayer, ApiKeyConfig, BarnacleConfig};
//! #[cfg(feature = "redis")]
//! use barnacle_rs::{RedisApiKeyStore, RedisBarnacleStore, deadpool_redis};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create Redis stores (requires "redis" feature)
//! #[cfg(feature = "redis")]
//! let redis_pool = deadpool_redis::Config::from_url("redis://localhost")
//!     .create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
//!
//! #[cfg(feature = "redis")]
//! let api_key_store = RedisApiKeyStore::new(redis_pool.clone());
//! #[cfg(feature = "redis")]
//! let rate_limit_store = RedisBarnacleStore::new(redis_pool);
//!
//! // Create a Barnacle layer using the builder pattern
//! #[cfg(feature = "redis")]
//! let layer: BarnacleLayer<RedisBarnacleStore> = BarnacleLayer::builder()
//!     .with_store(rate_limit_store)
//!     .with_config(BarnacleConfig::default())
//!     .build()?;
//!
//! // Use with Axum router
//! // let app = axum::Router::new()
//! //     .route("/api/data", axum::routing::get(handler))
//! //     .layer(layer);
//! # Ok(())
//! # }
//! ```

mod api_key_store;
mod error;
mod limits;
mod middleware;
mod redis_store;
mod types;

// Re-export key items for easier access
pub use api_key_store::{ApiKeyStore, StaticApiKeyStore};
pub use error::BarnacleError;
pub use limits::{
    Bucket, BucketState, DecisionOutcome, Identity, Limit, LimitOutcome, Mode, RateLimitDecision,
};
pub use middleware::{
    client_ip, client_ip_key, BarnacleLayer, BarnacleLayerBuilder, BarnacleLayerBuilderError,
    BarnacleMiddleware, IdentityResolver, KeyExtractable, FAILED_VALIDATION_SCOPE,
};
pub use tracing;
pub use types::{
    hash_api_key, redact_api_key, ApiKeyConfig, ApiKeyValidationResult, BarnacleConfig,
    BarnacleContext, BarnacleKey, BarnacleResult, ClientIpStrategy, RateLimitScope, ResetOnSuccess,
    StaticApiKeyConfig, StoreFailurePolicy, ANY_METHOD,
};

// Redis-specific exports (only available with "redis" feature)
#[cfg(feature = "redis")]
pub use api_key_store::RedisApiKeyStore;
#[cfg(feature = "redis")]
pub use redis_store::{RedisBarnacleStore, RedisPoolOptions};
// Re-export commonly used external dependencies (only with redis feature)
#[cfg(feature = "redis")]
pub use deadpool_redis;
pub use ipnet;

use async_trait::async_trait;
use std::time::Duration;

pub const BARNACLE_EMAIL_KEY_PREFIX: &str = "barnacle:email";
pub const BARNACLE_API_KEY_PREFIX: &str = "barnacle:api_keys";
pub const BARNACLE_IP_PREFIX: &str = "barnacle:ip";
pub const BARNACLE_CUSTOM_PREFIX: &str = "barnacle:custom";

/// Trait to abstract the rate limiter storage backend (e.g., Redis)
#[async_trait]
pub trait BarnacleStore: Clone + Send + Sync {
    /// Increments the counter for the key and returns the current number of requests and remaining time until reset.
    async fn increment(
        &self,
        context: &BarnacleContext,
        config: &BarnacleConfig,
    ) -> Result<types::BarnacleResult, BarnacleError>;
    /// Resets the counter for the key (e.g., after successful login).
    async fn reset(&self, context: &BarnacleContext) -> Result<(), BarnacleError>;

    /// Reads the counter for the key without incrementing it.
    ///
    /// Returns `Err(BarnacleError::RateLimitExceeded)` when the limit is already reached.
    /// Used to reject clients that exceeded the failed API key validation limit before
    /// running the validator again. The default implementation returns a store error,
    /// so a store without `peek` is handled by the layer's [`StoreFailurePolicy`]
    /// (rejected with the default `FailClosed`) instead of silently skipping the limit.
    ///
    /// It cannot be merged with the [`BarnacleStore::increment`] of the request: the
    /// validator runs in between (that is the point of reading the counter first), and
    /// the increment that follows targets a different bucket with a different config.
    /// A request carrying an API key therefore costs one round trip here and one there
    /// when a failed validation limit is configured.
    async fn peek(
        &self,
        context: &BarnacleContext,
        config: &BarnacleConfig,
    ) -> Result<types::BarnacleResult, BarnacleError> {
        let _ = (context, config);
        Err(BarnacleError::store_error(
            "This store does not implement `peek`, required by the failed validation limit",
        ))
    }

    /// Checks every bucket and increments them all, atomically and all or nothing: when
    /// one bucket is full, none is incremented.
    ///
    /// Returns one [`BucketState`] per bucket, in the same order. A full bucket is
    /// reported with [`BucketState::exceeded`], not as an error: errors are reserved for
    /// store failures.
    ///
    /// The layer counts every request through this method. The default implementation
    /// handles a single bucket with [`BarnacleStore::increment`], so a custom store keeps
    /// working with one limit per request; it returns a store error for more than one,
    /// since counting them one by one would not be atomic.
    async fn increment_all(&self, buckets: &[Bucket]) -> Result<Vec<BucketState>, BarnacleError> {
        match buckets {
            [] => Ok(Vec::new()),
            [bucket] => {
                let config = BarnacleConfig::new(bucket.max_requests, bucket.window);
                let state = match self.increment(&bucket.context, &config).await {
                    Ok(result) => BucketState {
                        exceeded: false,
                        remaining: result.remaining,
                        reset_after: result.retry_after.unwrap_or(bucket.window),
                    },
                    Err(BarnacleError::RateLimitExceeded { retry_after, .. }) => BucketState {
                        exceeded: true,
                        remaining: 0,
                        reset_after: Duration::from_secs(retry_after),
                    },
                    Err(error) => return Err(error),
                };
                Ok(vec![state])
            }
            _ => Err(BarnacleError::store_error(
                "This store does not implement `increment_all`, required by multiple limits per request",
            )),
        }
    }
}
