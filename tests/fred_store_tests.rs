//! Requires a Redis instance on 127.0.0.1:6379, or at `REDIS_URL`. Run with `--features fred`.
#![cfg(feature = "fred")]

use std::time::Duration;

use barnacle_rs::{
    fred::{
        interfaces::{ClientLike, KeysInterface},
        types::CustomCommand,
    },
    hash_api_key, BarnacleConfig, BarnacleContext, BarnacleError, BarnacleKey, BarnacleStore,
    Bucket, FredBarnacleStore, FredPoolOptions, ResetOnSuccess,
};
use uuid::Uuid;

fn redis_url() -> String {
    std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

async fn store() -> FredBarnacleStore {
    FredBarnacleStore::from_url(&redis_url()).await.unwrap()
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
    let store = store().await;
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
    let store = store().await;
    let context = unique_context();
    let config = limit(2, 30);

    // A counter stuck over the limit with no TTL, as left by a failed EXPIRE
    let _: () = store
        .pool()
        .set(redis_key(&context), 5, None, None, false)
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
    let ttl: i64 = store.pool().ttl(redis_key(&context)).await.unwrap();
    assert!(ttl > 0 && ttl <= 30, "ttl = {ttl}");
}

#[tokio::test]
async fn peek_repairs_counters_without_expiry() {
    let store = store().await;
    let context = unique_context();
    let config = limit(2, 30);

    // Over the limit with no TTL: peek rejects before increment could repair it
    let _: () = store
        .pool()
        .set(redis_key(&context), 5, None, None, false)
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
    let ttl: i64 = store.pool().ttl(redis_key(&context)).await.unwrap();
    assert!(ttl > 0 && ttl <= 30, "ttl = {ttl}");
}

#[tokio::test]
async fn increments_report_remaining_and_reset() {
    let store = store().await;
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
    let store = store().await;
    let api_key = format!("secret-{}", Uuid::new_v4());
    let context = BarnacleContext {
        key: BarnacleKey::ApiKey(api_key.clone()),
        path: "/test".into(),
        method: "GET".into(),
    };
    store.increment(&context, &limit(5, 30)).await.unwrap();

    let keys = |pattern: String| {
        let store = store.clone();
        async move {
            store
                .pool()
                .custom::<Vec<String>, _>(
                    CustomCommand::new_static("KEYS", None, false),
                    vec![pattern],
                )
                .await
                .unwrap()
        }
    };
    let clear = keys(format!("*{api_key}*")).await;
    assert!(clear.is_empty(), "found {clear:?}");
    let hashed = keys(format!(
        "barnacle:api_keys:{}:GET:/test",
        hash_api_key(&api_key)
    ))
    .await;
    assert_eq!(hashed.len(), 1);
    store.reset(&context).await.unwrap();
}

#[tokio::test]
async fn emails_are_not_stored_in_clear_text() {
    let store = store().await;
    let email = format!("{}@example.com", Uuid::new_v4());
    let context = BarnacleContext {
        key: BarnacleKey::Email(email.clone()),
        path: "/test".into(),
        method: "POST".into(),
    };
    store.increment(&context, &limit(5, 30)).await.unwrap();

    let keys = |pattern: String| {
        let store = store.clone();
        async move {
            store
                .pool()
                .custom::<Vec<String>, _>(
                    CustomCommand::new_static("KEYS", None, false),
                    vec![pattern],
                )
                .await
                .unwrap()
        }
    };
    let clear = keys(format!("*{email}*")).await;
    assert!(clear.is_empty(), "found {clear:?}");
    let hashed = keys(format!(
        "barnacle:email:{}:POST:/test",
        hash_api_key(&email)
    ))
    .await;
    assert_eq!(hashed.len(), 1);
    store.reset(&context).await.unwrap();
}

#[tokio::test]
async fn unreachable_redis_fails_fast() {
    let started = std::time::Instant::now();
    let store = FredBarnacleStore::from_url_with_options(
        "redis://10.255.255.1:6379",
        FredPoolOptions {
            size: 1,
            connection_timeout: Duration::from_millis(100),
            ..Default::default()
        },
    )
    .await;
    assert!(store.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// The scripts are run by hash: a Redis that lost them (restart, failover, `SCRIPT FLUSH`)
/// gets them loaded again instead of failing every request.
#[tokio::test]
async fn scripts_are_reloaded_after_a_flush() {
    let store = store().await;
    let context = unique_context();
    let config = limit(5, 30);
    store.increment(&context, &config).await.unwrap();

    let _: () = store
        .pool()
        .custom(
            CustomCommand::new_static("SCRIPT", None, false),
            vec!["FLUSH"],
        )
        .await
        .unwrap();

    assert_eq!(
        store.increment(&context, &config).await.unwrap().remaining,
        3
    );
    let _: () = store
        .pool()
        .custom(
            CustomCommand::new_static("SCRIPT", None, false),
            vec!["FLUSH"],
        )
        .await
        .unwrap();
    assert_eq!(store.peek(&context, &config).await.unwrap().remaining, 3);
}

/// Same keys and scripts as the deadpool store: a deployment can switch store without
/// resetting its counters.
#[cfg(feature = "redis")]
#[tokio::test]
async fn shares_counters_with_the_redis_store() {
    let fred = store().await;
    let redis = barnacle_rs::RedisBarnacleStore::from_url(&redis_url()).unwrap();
    let context = unique_context();
    let config = limit(3, 30);

    redis.increment(&context, &config).await.unwrap();
    assert_eq!(
        fred.increment(&context, &config).await.unwrap().remaining,
        1
    );
    assert_eq!(redis.peek(&context, &config).await.unwrap().remaining, 1);
    fred.reset(&context).await.unwrap();
    assert_eq!(
        redis.increment(&context, &config).await.unwrap().remaining,
        2
    );
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

async fn count(store: &FredBarnacleStore, bucket: &Bucket) -> Option<u32> {
    store.pool().get(redis_key(&bucket.context)).await.unwrap()
}

#[tokio::test]
async fn a_rejection_does_not_consume_the_other_limits() {
    let store = store().await;
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
    assert_eq!(count(&store, &buckets[1]).await, Some(5));
    // Each bucket reports its own window
    assert!(states[0].reset_after.as_secs() <= 30);
    assert!(states[1].reset_after.as_secs() > 30);
}

#[tokio::test]
async fn concurrent_requests_are_counted_all_or_nothing() {
    let store = store().await;
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
    assert_eq!(count(&store, &buckets[1]).await, Some(5));
}

#[tokio::test]
async fn increment_all_with_no_buckets_touches_nothing() {
    assert!(store().await.increment_all(&[]).await.unwrap().is_empty());
}
