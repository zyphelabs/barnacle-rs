use axum::{response::Json, routing::get, Router};
use barnacle_rs::{
    ApiKeyConfig, ApiKeyStore, ApiKeyValidationResult, BarnacleConfig, BarnacleError, BarnacleLayer,
    RedisBarnacleStore,
};
use serde_json::json;
use std::time::Duration;
use tower::ServiceBuilder;
use std::sync::Arc;
use axum::http::request::Parts;

/// Example custom API key store that validates against a "database"
/// (in this case, just hardcoded keys for demonstration)
#[derive(Clone)]
pub struct PostgresApiKeyStore {
    // In a real implementation, this would be a database connection pool
    valid_keys: std::collections::HashMap<String, String>,
    // Set SIMULATE_DB_OUTAGE=1 to see what an unreachable database answers
    unavailable: bool,
}

impl PostgresApiKeyStore {
    pub fn new() -> Self {
        let mut valid_keys = std::collections::HashMap::new();
        valid_keys.insert("test-key-1".to_string(), "user_1".to_string());
        valid_keys.insert("test-key-2".to_string(), "user_2".to_string());
        valid_keys.insert("test-key-3".to_string(), "user_3".to_string());

        Self {
            valid_keys,
            unavailable: std::env::var("SIMULATE_DB_OUTAGE").is_ok(),
        }
    }
}

impl Default for PostgresApiKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ApiKeyStore for PostgresApiKeyStore {
    async fn validate_key(&self, api_key: &str) -> Result<ApiKeyValidationResult, BarnacleError> {
        // A query that fails is an infrastructure error, never an invalid key: reporting
        // it as invalid would answer 401 and count the outage against the client's
        // failed validation limit
        if self.unavailable {
            return Err(BarnacleError::store_error("PostgreSQL is unavailable"));
        }

        match self.valid_keys.get(api_key) {
            Some(key_id) => Ok(ApiKeyValidationResult::valid_with_default_config(
                key_id.clone(),
            )),
            // The key really is not in the database
            None => Ok(ApiKeyValidationResult::invalid()),
        }
    }
}

async fn protected_handler() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Hello! This endpoint is protected by API key validation and rate limiting",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({"status": "ok"}))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for better logging
    tracing_subscriber::fmt().init();

    println!("🚀 Starting Custom Validator Example");
    println!("📋 This example demonstrates:");
    println!("   1. Redis cache for fast API key validation");
    println!("   2. PostgreSQL fallback for unknown keys");
    println!("   3. Automatic caching of validated keys");
    println!();

    // Create Redis connection pool
    let redis_config = deadpool_redis::Config::from_url("redis://localhost:6379");
    let redis_pool = redis_config
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("Failed to create Redis pool");

    // Create the stores
    let store = RedisBarnacleStore::new(redis_pool.clone());
    let postgres_store = PostgresApiKeyStore::new();
    let state = Arc::new(postgres_store.clone());
    // Default rate limit if not specified by store
    let config = BarnacleConfig::new(5, Duration::from_secs(60));
    let api_key_validator = |api_key: String, _api_key_config: ApiKeyConfig, _parts: Arc<Parts>, state: Arc<PostgresApiKeyStore>| async move {
        // `?` propagates a store failure as a 5xx, so a database blip is not answered
        // with 401 and not counted against the client
        if state.validate_key(&api_key).await?.valid {
            Ok(())
        } else {
            Err(BarnacleError::invalid_api_key(api_key))
        }
    };
    // Example request modifier that adds a custom header after validation
    let request_modifier = |mut parts: Parts, _state: Arc<PostgresApiKeyStore>| async move {
        // Add a custom header to show the request was modified
        parts.headers.insert(
            "x-modified-by",
            "barnacle-request-modifier".parse().unwrap()
        );
        Ok(parts)
    };

    let auth_layer: BarnacleLayer<(), _, _, _, _, _> = BarnacleLayer::builder()
        .with_store(store)
        .with_config(config)
        .with_state(state.clone())
        .with_api_key_validator(api_key_validator)
        .with_request_modifier(request_modifier)
        .build()
        .unwrap();

    // Build the router
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(ServiceBuilder::new().layer(auth_layer))
        .route("/health", get(health_handler)); // Health endpoint without auth

    println!("🌐 Server starting on http://localhost:3000");
    println!();
    println!("🧪 Test commands:");
    println!("   # Health check (no auth required)");
    println!("   curl http://localhost:3000/health");
    println!();
    println!("   # First request (will hit PostgreSQL, then cache in Redis)");
    println!("   curl -H 'x-api-key: test-key-1' http://localhost:3000/protected");
    println!();
    println!("   # Second request (will hit Redis cache, faster)");
    println!("   curl -H 'x-api-key: test-key-1' http://localhost:3000/protected");
    println!();
    println!("   # Invalid key (401)");
    println!("   curl -H 'x-api-key: invalid-key' http://localhost:3000/protected");
    println!();
    println!("   # Database outage (503, not 401): restart with SIMULATE_DB_OUTAGE=1");
    println!();
    println!("   # Rate limit test (make 6+ requests quickly)");
    println!("   for i in {{1..7}}; do curl -H 'x-api-key: test-key-1' http://localhost:3000/protected; echo; done");
    println!();

    // Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
