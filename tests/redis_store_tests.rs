//! Requires a Redis instance on 127.0.0.1:6379.

use std::time::Duration;

use barnacle_rs::{
    deadpool_redis, hash_api_key, BarnacleConfig, BarnacleContext, BarnacleError, BarnacleKey,
    BarnacleStore, Bucket, RedisBarnacleStore, RedisPoolOptions, ResetOnSuccess,
};
use uuid::Uuid;

const REDIS_URL: &str = "redis://127.0.0.1:6379";

fn store() -> RedisBarnacleStore {
    RedisBarnacleStore::from_url_with_options(REDIS_URL, RedisPoolOptions::default()).unwrap()
}

async fn connection() -> deadpool_redis::Connection {
    deadpool_redis::Config::from_url(REDIS_URL)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .unwrap()
        .get()
        .await
        .unwrap()
}

fn limit(max_requests: u32, window_secs: u64) -> BarnacleConfig {
    BarnacleConfig {
        max_requests,
        window: Duration::from_secs(window_secs),
        reset_on_success: ResetOnSuccess::Not,
    }
}

fn unique_context() -> BarnacleContext {
    BarnacleContext {
        key: BarnacleKey::Custom(Uuid::new_v4().to_string()),
        path: "/test".into(),
        method: "GET".into(),
    }
}

fn redis_key(context: &BarnacleContext) -> String {
    let BarnacleKey::Custom(id) = &context.key else {
        unreachable!()
    };
    format!("barnacle:custom:{}:{}:{}", id, context.method, context.path)
}

#[tokio::test]
async fn concurrent_requests_never_exceed_the_limit() {
    let store = store();
    let context = unique_context();
    let config = limit(10, 60);

    let attempts = (0..100).map(|_| {
        let store = store.clone();
        let context = context.clone();
        let config = config.clone();
        tokio::spawn(async move { store.increment(&context, &config).await })
    });
    let results = futures::future::join_all(attempts).await;
    let allowed = results
        .iter()
        .filter(|result| matches!(result, Ok(Ok(_))))
        .count();
    assert_eq!(allowed, 10);
}

#[tokio::test]
async fn counters_without_expiry_are_repaired() {
    let store = store();
    let context = unique_context();
    let config = limit(2, 30);
    let mut conn = connection().await;

    // A counter stuck over the limit with no TTL, as left by a failed EXPIRE
    let _: () = deadpool_redis::redis::cmd("SET")
        .arg(redis_key(&context))
        .arg(5)
        .query_async(&mut conn)
        .await
        .unwrap();

    let error = store.increment(&context, &config).await.unwrap_err();
    assert!(matches!(
        error,
        BarnacleError::RateLimitExceeded {
            retry_after: 30,
            ..
        }
    ));
    let ttl: i64 = deadpool_redis::redis::cmd("TTL")
        .arg(redis_key(&context))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(ttl > 0 && ttl <= 30, "ttl = {ttl}");
}

#[tokio::test]
async fn peek_repairs_counters_without_expiry() {
    let store = store();
    let context = unique_context();
    let config = limit(2, 30);
    let mut conn = connection().await;

    // Over the limit with no TTL: peek rejects before increment could repair it
    let _: () = deadpool_redis::redis::cmd("SET")
        .arg(redis_key(&context))
        .arg(5)
        .query_async(&mut conn)
        .await
        .unwrap();

    let error = store.peek(&context, &config).await.unwrap_err();
    assert!(matches!(
        error,
        BarnacleError::RateLimitExceeded {
            retry_after: 30,
            ..
        }
    ));
    let ttl: i64 = deadpool_redis::redis::cmd("TTL")
        .arg(redis_key(&context))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(ttl > 0 && ttl <= 30, "ttl = {ttl}");
}

#[tokio::test]
async fn increments_report_remaining_and_reset() {
    let store = store();
    let context = unique_context();
    let config = limit(3, 30);

    let first = store.increment(&context, &config).await.unwrap();
    assert_eq!(first.remaining, 2);
    assert!(first
        .retry_after
        .is_some_and(|reset| reset.as_secs() <= 30 && reset.as_secs() > 0));
    let peeked = store.peek(&context, &config).await.unwrap();
    assert_eq!(peeked.remaining, 2, "peek must not increment");

    store.increment(&context, &config).await.unwrap();
    store.increment(&context, &config).await.unwrap();
    assert!(store.increment(&context, &config).await.is_err());
    assert!(store.peek(&context, &config).await.is_err());

    store.reset(&context).await.unwrap();
    assert_eq!(
        store.increment(&context, &config).await.unwrap().remaining,
        2
    );
}

#[tokio::test]
async fn api_keys_are_not_stored_in_clear_text() {
    let store = store();
    let api_key = format!("secret-{}", Uuid::new_v4());
    let context = BarnacleContext {
        key: BarnacleKey::ApiKey(api_key.clone()),
        path: "/test".into(),
        method: "GET".into(),
    };
    store.increment(&context, &limit(5, 30)).await.unwrap();

    let mut conn = connection().await;
    let clear: Vec<String> = deadpool_redis::redis::cmd("KEYS")
        .arg(format!("*{api_key}*"))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(clear.is_empty(), "found {clear:?}");
    let hashed: Vec<String> = deadpool_redis::redis::cmd("KEYS")
        .arg(format!(
            "barnacle:api_keys:{}:GET:/test",
            hash_api_key(&api_key)
        ))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(hashed.len(), 1);
    store.reset(&context).await.unwrap();
}

#[tokio::test]
async fn emails_are_not_stored_in_clear_text() {
    let store = store();
    let email = format!("{}@example.com", Uuid::new_v4());
    let context = BarnacleContext {
        key: BarnacleKey::Email(email.clone()),
        path: "/test".into(),
        method: "POST".into(),
    };
    store.increment(&context, &limit(5, 30)).await.unwrap();

    let mut conn = connection().await;
    let clear: Vec<String> = deadpool_redis::redis::cmd("KEYS")
        .arg(format!("*{email}*"))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(clear.is_empty(), "found {clear:?}");
    let hashed: Vec<String> = deadpool_redis::redis::cmd("KEYS")
        .arg(format!(
            "barnacle:email:{}:POST:/test",
            hash_api_key(&email)
        ))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(hashed.len(), 1);
    store.reset(&context).await.unwrap();
}

#[tokio::test]
async fn unreachable_redis_fails_fast_with_pool_timeouts() {
    let store = RedisBarnacleStore::from_url_with_options(
        "redis://10.255.255.1:6379",
        RedisPoolOptions {
            create_timeout: Some(Duration::from_millis(100)),
            ..Default::default()
        },
    )
    .unwrap();
    let started = std::time::Instant::now();
    assert!(store
        .increment(&unique_context(), &limit(5, 30))
        .await
        .is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// Two buckets of the same client: a tight one and a loose one
fn tight_and_loose() -> [Bucket; 2] {
    let key = BarnacleKey::Custom(Uuid::new_v4().to_string());
    let bucket = |path: &str, max_requests, window_secs| Bucket {
        context: BarnacleContext::named(key.clone(), path),
        max_requests,
        window: Duration::from_secs(window_secs),
    };
    [bucket("tight", 5, 30), bucket("loose", 100, 60)]
}

async fn count(bucket: &Bucket) -> Option<u32> {
    let BarnacleKey::Custom(id) = &bucket.context.key else {
        unreachable!()
    };
    let key = format!(
        "barnacle:custom:{}:{}:{}",
        id, bucket.context.method, bucket.context.path
    );
    let mut conn = connection().await;
    deadpool_redis::redis::cmd("GET")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_rejection_does_not_consume_the_other_limits() {
    let store = store();
    let buckets = tight_and_loose();

    for _ in 0..5 {
        let states = store.increment_all(&buckets).await.unwrap();
        assert!(states.iter().all(|state| !state.exceeded));
    }
    let states = store.increment_all(&buckets).await.unwrap();
    assert!(states[0].exceeded);
    assert_eq!(states[0].remaining, 0);
    assert!(!states[1].exceeded);
    assert_eq!(states[1].remaining, 95);
    assert_eq!(count(&buckets[1]).await, Some(5));
    // Each bucket reports its own window
    assert!(states[0].reset_after.as_secs() <= 30);
    assert!(states[1].reset_after.as_secs() > 30);
}

#[tokio::test]
async fn concurrent_requests_are_counted_all_or_nothing() {
    let store = store();
    let buckets = tight_and_loose();

    let attempts = (0..50).map(|_| {
        let store = store.clone();
        let buckets = buckets.clone();
        tokio::spawn(async move { store.increment_all(&buckets).await.unwrap() })
    });
    let results = futures::future::join_all(attempts).await;
    let allowed = results
        .iter()
        .filter(|states| states.as_ref().unwrap().iter().all(|state| !state.exceeded))
        .count();
    assert_eq!(allowed, 5);
    // The 45 rejected requests did not consume the loose bucket
    assert_eq!(count(&buckets[1]).await, Some(5));
}

#[tokio::test]
async fn increment_all_with_no_buckets_touches_nothing() {
    assert!(store().increment_all(&[]).await.unwrap().is_empty());
}
