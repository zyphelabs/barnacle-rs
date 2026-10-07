//! What the Redis-backed stores share, whichever client runs them: the counter scripts, the
//! counter key layout, and how a script reply becomes a [`BucketState`] or a [`BarnacleResult`].

use std::time::Duration;

use crate::{
    error::BarnacleError,
    limits::{Bucket, BucketState},
    types::{hash_api_key, BarnacleConfig, BarnacleContext, BarnacleKey, BarnacleResult},
    BARNACLE_API_KEY_PREFIX, BARNACLE_CUSTOM_PREFIX, BARNACLE_EMAIL_KEY_PREFIX, BARNACLE_IP_PREFIX,
};

/// Checks fixed-window counters and increments them all in a single atomic step, only
/// when every one of them has room: a full counter blocks the others from being counted.
///
/// KEYS[i] = counter key, ARGV[2i - 1] = max requests, ARGV[2i] = window in seconds.
/// Returns `{allowed (0/1), then per key: exceeded (0/1), count, ttl}`, where count is
/// the value after the increment when the request was allowed.
///
/// A counter left without expiry (TTL -1, e.g. by a failed `EXPIRE` in older versions)
/// gets its expiry restored, so it can never block a key forever.
///
/// Every key must live in the same hash slot, so this is not supported on Redis Cluster.
pub(crate) const INCREMENT_ALL_SCRIPT: &str = r#"
local allowed = 1
local counts, ttls, windows, exceeded = {}, {}, {}, {}
for i = 1, #KEYS do
  local max = tonumber(ARGV[2 * i - 1])
  local window = tonumber(ARGV[2 * i])
  local current = tonumber(redis.call('GET', KEYS[i]) or '0')
  local ttl = redis.call('TTL', KEYS[i])
  if ttl == -1 then
    redis.call('EXPIRE', KEYS[i], window)
    ttl = window
  end
  exceeded[i] = 0
  if current >= max then
    exceeded[i] = 1
    allowed = 0
  end
  counts[i] = current
  ttls[i] = ttl
  windows[i] = window
end
local reply = {allowed}
for i = 1, #KEYS do
  if allowed == 1 then
    counts[i] = redis.call('INCR', KEYS[i])
    if ttls[i] < 0 then
      redis.call('EXPIRE', KEYS[i], windows[i])
    end
  end
  if ttls[i] < 0 then
    ttls[i] = windows[i]
  end
  table.insert(reply, exceeded[i])
  table.insert(reply, counts[i])
  table.insert(reply, ttls[i])
end
return reply
"#;

/// Reads a counter without incrementing it, restoring a missing expiry like
/// [`INCREMENT_ALL_SCRIPT`] so a counter over the limit can't be stuck by `peek` alone.
///
/// KEYS[1] = counter key, ARGV[1] = window in seconds. Returns `{count, ttl}`.
pub(crate) const PEEK_SCRIPT: &str = r#"
local window = tonumber(ARGV[1])
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local ttl = redis.call('TTL', KEYS[1])
if ttl == -1 then
  redis.call('EXPIRE', KEYS[1], window)
  ttl = window
end
return {current, ttl}
"#;

/// The Redis key of the counter for `context`.
pub(crate) fn counter_key(context: &BarnacleContext) -> String {
    let base_key = match &context.key {
        // Email addresses and API keys are hashed so they are never stored in clear text
        BarnacleKey::Email(email) => {
            format!("{BARNACLE_EMAIL_KEY_PREFIX}:{}", hash_api_key(email))
        }
        BarnacleKey::ApiKey(api_key) => {
            format!("{BARNACLE_API_KEY_PREFIX}:{}", hash_api_key(api_key))
        }
        BarnacleKey::Ip(ip) => format!("{BARNACLE_IP_PREFIX}:{}", ip),
        BarnacleKey::Custom(custom_data) => format!("{BARNACLE_CUSTOM_PREFIX}:{}", custom_data),
    };

    // Include path and method in the Redis key
    format!("{}:{}:{}", base_key, context.method, context.path)
}

/// Window length in seconds, at least 1 (`EXPIRE 0` would delete the counter).
pub(crate) fn window_seconds(window: Duration) -> u64 {
    window.as_secs().max(1)
}

/// Seconds until the window resets (at least 1, as Redis reports 0 in the last second),
/// falling back to the full window when Redis reports no expiry.
pub(crate) fn reset_after(ttl: i64, window: Duration) -> Duration {
    if ttl >= 0 {
        Duration::from_secs(ttl.max(1) as u64)
    } else {
        Duration::from_secs(window_seconds(window))
    }
}

/// The [`INCREMENT_ALL_SCRIPT`] reply for `buckets`, one state per bucket in their order.
pub(crate) fn bucket_states(
    buckets: &[Bucket],
    reply: &[i64],
) -> Result<Vec<BucketState>, BarnacleError> {
    // The leading `allowed` flag is implied by the per-key `exceeded` flags
    let counters = reply
        .get(1..)
        .filter(|counters| counters.len() == buckets.len() * 3)
        .ok_or_else(|| BarnacleError::store_error("Unexpected Redis increment script reply"))?;
    Ok(buckets
        .iter()
        .zip(counters.chunks_exact(3))
        .map(|(bucket, counter)| {
            let (exceeded, count, ttl) = (counter[0] == 1, counter[1], counter[2]);
            BucketState {
                exceeded,
                // When another limit rejected the request, `count` was not incremented
                remaining: if exceeded {
                    0
                } else {
                    bucket
                        .max_requests
                        .saturating_sub(u32::try_from(count).unwrap_or(u32::MAX))
                },
                reset_after: reset_after(ttl, bucket.window),
            }
        })
        .collect())
}

/// The [`crate::BarnacleStore::increment`] answer for the single bucket the script counted.
pub(crate) fn increment_result(
    state: BucketState,
    context: &BarnacleContext,
    config: &BarnacleConfig,
) -> Result<BarnacleResult, BarnacleError> {
    if state.exceeded {
        tracing::debug!(
            "Rate limit exceeded for key: {:?}, max: {}, retry_after: {}s",
            context.key,
            config.max_requests,
            state.reset_after.as_secs()
        );
        return Err(BarnacleError::rate_limit_exceeded(
            0,
            state.reset_after.as_secs(),
            config.max_requests,
        ));
    }

    Ok(BarnacleResult {
        allowed: true,
        remaining: state.remaining,
        retry_after: Some(state.reset_after),
    })
}

/// The [`crate::BarnacleStore::peek`] answer for the [`PEEK_SCRIPT`] reply `{count, ttl}`.
pub(crate) fn peek_result(
    count: u32,
    ttl: i64,
    config: &BarnacleConfig,
) -> Result<BarnacleResult, BarnacleError> {
    let reset_after = reset_after(ttl, config.window);
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
