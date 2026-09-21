//! Requires a Redis instance on 127.0.0.1:6379.

use std::time::Duration;

use barnacle_rs::{
    deadpool_redis, hash_api_key, ApiKeyStore, BarnacleConfig, RedisApiKeyStore, RedisPoolOptions,
};
use uuid::Uuid;

const REDIS_URL: &str = "redis://127.0.0.1:6379";
const PREFIX: &str = "barnacle:api_keys";

fn store() -> RedisApiKeyStore {
    RedisApiKeyStore::new_with_config(pool(), BarnacleConfig::new(20, Duration::from_secs(60)))
}

fn pool() -> deadpool_redis::Pool {
    deadpool_redis::Config::from_url(REDIS_URL)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .unwrap()
}

async fn connection() -> deadpool_redis::Connection {
    pool().get().await.unwrap()
}

/// An API key nobody else is using
fn unique_key() -> String {
    format!("legacy-{}", Uuid::new_v4())
}

fn clear_text_key(api_key: &str) -> String {
    format!("{PREFIX}:{api_key}")
}

fn clear_text_config_key(api_key: &str) -> String {
    format!("{PREFIX}:config:{api_key}")
}

fn hashed_key(api_key: &str) -> String {
    format!("{PREFIX}:{}", hash_api_key(api_key))
}

fn hashed_config_key(api_key: &str) -> String {
    format!("{PREFIX}:config:{}", hash_api_key(api_key))
}

/// Provisions a key the way 0.3 did: in clear text, optionally with a TTL
async fn provision_clear_text(api_key: &str, config: Option<&BarnacleConfig>, ttl: Option<u64>) {
    let mut conn = connection().await;
    let mut entries = vec![(clear_text_key(api_key), "1".to_string())];
    if let Some(config) = config {
        entries.push((
            clear_text_config_key(api_key),
            serde_json::to_string(config).unwrap(),
        ));
    }
    for (key, value) in entries {
        let _: () = deadpool_redis::redis::cmd("SET")
            .arg(&key)
            .arg(value)
            .query_async(&mut conn)
            .await
            .unwrap();
        if let Some(ttl) = ttl {
            let _: () = deadpool_redis::redis::cmd("EXPIRE")
                .arg(&key)
                .arg(ttl)
                .query_async(&mut conn)
                .await
                .unwrap();
        }
    }
}

async fn exists(key: &str) -> bool {
    let mut conn = connection().await;
    deadpool_redis::redis::cmd("EXISTS")
        .arg(key)
        .query_async::<i64>(&mut conn)
        .await
        .unwrap()
        == 1
}

async fn ttl(key: &str) -> i64 {
    let mut conn = connection().await;
    deadpool_redis::redis::cmd("TTL")
        .arg(key)
        .query_async(&mut conn)
        .await
        .unwrap()
}

async fn delete_all(api_key: &str) {
    let mut conn = connection().await;
    let _: () = deadpool_redis::redis::cmd("DEL")
        .arg(clear_text_key(api_key))
        .arg(clear_text_config_key(api_key))
        .arg(hashed_key(api_key))
        .arg(hashed_config_key(api_key))
        .query_async(&mut conn)
        .await
        .unwrap();
}

#[tokio::test]
async fn keys_provisioned_in_clear_text_stay_valid_and_are_migrated() {
    let api_key = unique_key();
    let config = BarnacleConfig::new(7, Duration::from_secs(300));
    provision_clear_text(&api_key, Some(&config), Some(600)).await;

    let result = store().validate_key(&api_key).await.unwrap();
    assert!(result.valid);
    let cached = result.rate_limit_config.unwrap();
    assert_eq!(cached.max_requests, 7, "the per-key config must survive");
    assert_eq!(cached.window, Duration::from_secs(300));

    // Moved to the hashed names, with the remaining TTL, and gone from the clear ones
    assert!(exists(&hashed_key(&api_key)).await);
    assert!(exists(&hashed_config_key(&api_key)).await);
    assert!(!exists(&clear_text_key(&api_key)).await);
    assert!(!exists(&clear_text_config_key(&api_key)).await);
    let remaining = ttl(&hashed_key(&api_key)).await;
    assert!(remaining > 0 && remaining <= 600, "ttl = {remaining}");
    assert!(ttl(&hashed_config_key(&api_key)).await > 0);

    // And the key keeps validating once migrated
    assert!(store().validate_key(&api_key).await.unwrap().valid);
    delete_all(&api_key).await;
}

#[tokio::test]
async fn migrated_keys_without_expiry_keep_none() {
    let api_key = unique_key();
    provision_clear_text(&api_key, None, None).await;

    assert!(store().validate_key(&api_key).await.unwrap().valid);
    assert_eq!(ttl(&hashed_key(&api_key)).await, -1);
    delete_all(&api_key).await;
}

#[tokio::test]
async fn config_lookups_follow_the_same_migration_path() {
    let api_key = unique_key();
    let config = BarnacleConfig::new(3, Duration::from_secs(120));
    provision_clear_text(&api_key, Some(&config), Some(600)).await;

    let found = store().get_rate_limit_config(&api_key).await.unwrap();
    assert_eq!(found.max_requests, 3);
    assert!(!exists(&clear_text_config_key(&api_key)).await);
    assert!(exists(&hashed_config_key(&api_key)).await);
    delete_all(&api_key).await;
}

#[tokio::test]
async fn unknown_keys_are_invalid_without_migrating_anything() {
    let api_key = unique_key();
    let result = store().validate_key(&api_key).await.unwrap();
    assert!(!result.valid);
    assert!(!exists(&hashed_key(&api_key)).await);
}

#[tokio::test]
async fn invalidating_a_key_removes_its_clear_text_entries() {
    let api_key = unique_key();
    let config = BarnacleConfig::new(5, Duration::from_secs(60));
    provision_clear_text(&api_key, Some(&config), None).await;
    let store = store();
    store
        .save_key(&api_key, Some(&config), Some(600))
        .await
        .unwrap();

    assert_eq!(store.invalidate_key(&api_key).await.unwrap(), 4);
    assert!(!exists(&clear_text_key(&api_key)).await);
    assert!(!exists(&clear_text_config_key(&api_key)).await);
    assert!(!exists(&hashed_key(&api_key)).await);
    assert!(!exists(&hashed_config_key(&api_key)).await);
    assert!(!store.validate_key(&api_key).await.unwrap().valid);
}

#[tokio::test]
async fn store_failures_are_errors_not_invalid_keys() {
    let store = RedisApiKeyStore::from_url_with_options(
        "redis://10.255.255.1:6379",
        RedisPoolOptions {
            create_timeout: Some(Duration::from_millis(100)),
            ..Default::default()
        },
    )
    .unwrap();

    // An unreachable Redis must not look like a key that does not exist
    let error = store.validate_key("any-key").await.unwrap_err();
    assert!(
        error.status_code().is_server_error(),
        "expected a 5xx, got {error}"
    );
}
