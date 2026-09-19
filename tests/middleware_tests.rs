use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{request::Parts, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use barnacle_rs::{
    client_ip, ApiKeyConfig, BarnacleConfig, BarnacleContext, BarnacleError, BarnacleKey,
    BarnacleLayer, BarnacleResult, BarnacleStore, ClientIpStrategy, KeyExtractable,
    RateLimitScope, ResetOnSuccess, StoreFailurePolicy, FAILED_VALIDATION_SCOPE,
};
use http_body_util::BodyExt;
use serde::Deserialize;
use tower::ServiceExt;

type Bucket = (BarnacleKey, String, String);

/// In-memory store recording every context it counts
#[derive(Clone, Default)]
struct MemoryStore {
    counters: Arc<Mutex<HashMap<Bucket, u32>>>,
}

impl MemoryStore {
    fn count(&self, key: BarnacleKey, path: &str, method: &str) -> u32 {
        let counters = self.counters.lock().unwrap();
        counters
            .get(&(key, path.to_string(), method.to_string()))
            .copied()
            .unwrap_or(0)
    }

    fn keys(&self) -> Vec<Bucket> {
        self.counters.lock().unwrap().keys().cloned().collect()
    }

    fn entry(context: &BarnacleContext) -> Bucket {
        (context.key.clone(), context.path.clone(), context.method.clone())
    }
}

#[async_trait::async_trait]
impl BarnacleStore for MemoryStore {
    async fn increment(
        &self,
        context: &BarnacleContext,
        config: &BarnacleConfig,
    ) -> Result<BarnacleResult, BarnacleError> {
        let mut counters = self.counters.lock().unwrap();
        let count = counters.entry(Self::entry(context)).or_insert(0);
        if *count >= config.max_requests {
            return Err(BarnacleError::rate_limit_exceeded(0, 42, config.max_requests));
        }
        *count += 1;
        Ok(BarnacleResult {
            allowed: true,
            remaining: config.max_requests - *count,
            retry_after: Some(Duration::from_secs(42)),
        })
    }

    async fn reset(&self, context: &BarnacleContext) -> Result<(), BarnacleError> {
        self.counters.lock().unwrap().remove(&Self::entry(context));
        Ok(())
    }

    async fn peek(
        &self,
        context: &BarnacleContext,
        config: &BarnacleConfig,
    ) -> Result<BarnacleResult, BarnacleError> {
        let counters = self.counters.lock().unwrap();
        let count = counters.get(&Self::entry(context)).copied().unwrap_or(0);
        if count >= config.max_requests {
            return Err(BarnacleError::rate_limit_exceeded(0, 42, config.max_requests));
        }
        Ok(BarnacleResult {
            allowed: true,
            remaining: config.max_requests - count,
            retry_after: None,
        })
    }
}

/// Store that is always down or slow
#[derive(Clone)]
struct BrokenStore {
    delay: Option<Duration>,
}

#[async_trait::async_trait]
impl BarnacleStore for BrokenStore {
    async fn increment(
        &self,
        _context: &BarnacleContext,
        _config: &BarnacleConfig,
    ) -> Result<BarnacleResult, BarnacleError> {
        match self.delay {
            Some(delay) => {
                tokio::time::sleep(delay).await;
                Ok(BarnacleResult { allowed: true, remaining: 1, retry_after: None })
            }
            None => Err(BarnacleError::store_error("store down")),
        }
    }

    async fn reset(&self, _context: &BarnacleContext) -> Result<(), BarnacleError> {
        Ok(())
    }
}

/// Custom error type that, like most application errors, drops Barnacle's headers
struct AppError(StatusCode);

impl From<BarnacleError> for AppError {
    fn from(error: BarnacleError) -> Self {
        AppError(error.status_code())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

fn limit(max_requests: u32) -> BarnacleConfig {
    BarnacleConfig {
        max_requests,
        window: Duration::from_secs(60),
        reset_on_success: ResetOnSuccess::Not,
    }
}

const VALID_KEY: &str = "valid-key";

type ValidationFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BarnacleError>> + Send>>;

fn validator(
) -> impl Fn(String, ApiKeyConfig, Arc<Parts>, ()) -> ValidationFuture + Clone + Send + Sync + 'static {
    |api_key: String, _config: ApiKeyConfig, _parts: Arc<Parts>, _state: ()| {
        Box::pin(async move {
            if api_key.is_empty() {
                Err(BarnacleError::ApiKeyMissing)
            } else if api_key != VALID_KEY {
                Err(BarnacleError::invalid_api_key(api_key))
            } else {
                Ok(())
            }
        })
    }
}

fn request(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder().method(method).uri(uri)
}

fn with_peer(mut req: Request<Body>, peer: &str) -> Request<Body> {
    let addr: SocketAddr = peer.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

async fn send(app: &Router, req: Request<Body>) -> Response {
    app.clone().oneshot(req).await.unwrap()
}

async fn body_text(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

mod scope {
    use super::*;

    fn app(store: MemoryStore, scope: RateLimitScope) -> Router {
        let layer: BarnacleLayer<(), MemoryStore> = BarnacleLayer::builder()
            .with_store(store)
            .with_config(limit(2))
            .with_scope(scope)
            .build()
            .unwrap();
        Router::new()
            .route("/users/{id}", get(|| async { "ok" }))
            .route("/users/{id}/avatar", post(|| async { "ok" }))
            .route_layer(layer)
    }

    #[tokio::test]
    async fn path_scope_counts_each_concrete_path() {
        let store = MemoryStore::default();
        let app = app(store.clone(), RateLimitScope::Path);
        for id in 0..5 {
            let req = with_peer(request("GET", &format!("/users/{id}")).body(Body::empty()).unwrap(), "1.1.1.1:1");
            assert_eq!(send(&app, req).await.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn route_scope_counts_the_route_template() {
        let store = MemoryStore::default();
        let app = app(store.clone(), RateLimitScope::Route);
        let statuses = {
            let mut statuses = vec![];
            for id in 0..3 {
                let req = with_peer(request("GET", &format!("/users/{id}")).body(Body::empty()).unwrap(), "1.1.1.1:1");
                statuses.push(send(&app, req).await.status());
            }
            statuses
        };
        assert_eq!(statuses, [StatusCode::OK, StatusCode::OK, StatusCode::TOO_MANY_REQUESTS]);
        assert_eq!(store.count(BarnacleKey::Ip("1.1.1.1".into()), "/users/{id}", "GET"), 2);
    }

    #[tokio::test]
    async fn named_scope_shares_one_bucket_across_routes_and_methods() {
        let store = MemoryStore::default();
        let app = app(store.clone(), RateLimitScope::Named("sdk".into()));
        let first = with_peer(request("GET", "/users/1").body(Body::empty()).unwrap(), "1.1.1.1:1");
        let second = with_peer(request("POST", "/users/2/avatar").body(Body::empty()).unwrap(), "1.1.1.1:1");
        let third = with_peer(request("GET", "/users/3").body(Body::empty()).unwrap(), "1.1.1.1:1");
        assert_eq!(send(&app, first).await.status(), StatusCode::OK);
        assert_eq!(send(&app, second).await.status(), StatusCode::OK);
        assert_eq!(send(&app, third).await.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(store.count(BarnacleKey::Ip("1.1.1.1".into()), "sdk", "*"), 2);
    }
}

mod client_ip_strategy {
    use super::*;

    fn app(store: MemoryStore, strategy: ClientIpStrategy) -> Router {
        let layer: BarnacleLayer<(), MemoryStore> = BarnacleLayer::builder()
            .with_store(store)
            .with_config(limit(100))
            .with_client_ip_strategy(strategy)
            .build()
            .unwrap();
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route("/ip", get(|req: Request<Body>| async move {
                let (parts, _) = req.into_parts();
                client_ip(&parts).unwrap_or_default()
            }))
            .route_layer(layer)
    }

    fn counted_ips(store: &MemoryStore) -> Vec<String> {
        store
            .keys()
            .into_iter()
            .filter_map(|(key, _, _)| match key {
                BarnacleKey::Ip(ip) => Some(ip),
                _ => None,
            })
            .collect()
    }

    fn trusted() -> ClientIpStrategy {
        ClientIpStrategy::trusted_proxies(["10.0.0.0/8", "192.168.1.1"]).unwrap()
    }

    #[tokio::test]
    async fn legacy_uses_the_peer_address() {
        let store = MemoryStore::default();
        let app = app(store.clone(), ClientIpStrategy::Legacy);
        let req = request("GET", "/")
            .header("x-forwarded-for", "6.6.6.6")
            .body(Body::empty())
            .unwrap();
        send(&app, with_peer(req, "10.0.0.5:4000")).await;
        assert_eq!(counted_ips(&store), ["10.0.0.5"]);
    }

    #[tokio::test]
    async fn trusted_proxies_take_the_client_appended_by_the_proxy() {
        let store = MemoryStore::default();
        let app = app(store.clone(), trusted());
        // The client forged the first entry, the load balancer appended the real address
        let req = request("GET", "/")
            .header("x-forwarded-for", "6.6.6.6, 203.0.113.7")
            .body(Body::empty())
            .unwrap();
        send(&app, with_peer(req, "10.0.0.5:4000")).await;
        assert_eq!(counted_ips(&store), ["203.0.113.7"]);
    }

    #[tokio::test]
    async fn trusted_proxies_skip_every_trusted_hop() {
        let store = MemoryStore::default();
        let app = app(store.clone(), trusted());
        let req = request("GET", "/")
            .header("x-forwarded-for", "203.0.113.7, 192.168.1.1")
            .header("x-forwarded-for", "10.1.2.3")
            .body(Body::empty())
            .unwrap();
        send(&app, with_peer(req, "10.0.0.5:4000")).await;
        assert_eq!(counted_ips(&store), ["203.0.113.7"]);
    }

    #[tokio::test]
    async fn trusted_proxies_ignore_headers_from_untrusted_peers() {
        let store = MemoryStore::default();
        let app = app(store.clone(), trusted());
        let req = request("GET", "/")
            .header("x-forwarded-for", "6.6.6.6")
            .body(Body::empty())
            .unwrap();
        send(&app, with_peer(req, "198.51.100.9:4000")).await;
        assert_eq!(counted_ips(&store), ["198.51.100.9"]);
    }

    #[tokio::test]
    async fn client_ip_uses_the_layer_strategy_in_handlers_and_extractors() {
        let app = app(MemoryStore::default(), trusted());
        let req = request("GET", "/ip")
            .header("x-forwarded-for", "6.6.6.6, 203.0.113.7")
            .body(Body::empty())
            .unwrap();
        let response = send(&app, with_peer(req, "10.0.0.5:4000")).await;
        assert_eq!(body_text(response).await, "203.0.113.7");
    }

    #[test]
    fn trusted_proxies_reject_invalid_ranges() {
        assert!(ClientIpStrategy::trusted_proxies(["not-an-ip"]).is_err());
    }
}

mod api_keys {
    use super::*;

    fn app(store: MemoryStore) -> Router {
        let layer: BarnacleLayer<(), MemoryStore, (), BarnacleError, _> = BarnacleLayer::builder()
            .with_store(store)
            .with_config(limit(100))
            .with_state(())
            .with_api_key_validator(validator())
            .with_failed_validation_limit(limit(3))
            .build()
            .unwrap();
        Router::new().route("/", get(|| async { "ok" })).route_layer(layer)
    }

    fn keyed(key: &str, peer: &str) -> Request<Body> {
        with_peer(request("GET", "/").header("x-api-key", key).body(Body::empty()).unwrap(), peer)
    }

    #[tokio::test]
    async fn failed_validations_are_limited_per_ip() {
        let store = MemoryStore::default();
        let app = app(store.clone());

        for attempt in 0..3 {
            let response = send(&app, keyed(&format!("guess-{attempt}"), "1.1.1.1:1")).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        // Over the limit: rejected before the validator runs, even with a valid key
        let response = send(&app, keyed(VALID_KEY, "1.1.1.1:1")).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key("retry-after"));
        assert_eq!(
            store.count(BarnacleKey::Ip("1.1.1.1".into()), FAILED_VALIDATION_SCOPE, "*"),
            3
        );

        // Other clients are not affected
        let response = send(&app, keyed(VALID_KEY, "2.2.2.2:1")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_keys_are_not_counted_as_failed_validations() {
        let store = MemoryStore::default();
        let app = app(store.clone());
        for _ in 0..5 {
            let req = with_peer(request("GET", "/").body(Body::empty()).unwrap(), "1.1.1.1:1");
            assert_eq!(send(&app, req).await.status(), StatusCode::UNAUTHORIZED);
        }
        assert_eq!(
            store.count(BarnacleKey::Ip("1.1.1.1".into()), FAILED_VALIDATION_SCOPE, "*"),
            0
        );
    }

    #[tokio::test]
    async fn valid_keys_are_counted_by_key() {
        let store = MemoryStore::default();
        let app = app(store.clone());
        assert_eq!(send(&app, keyed(VALID_KEY, "1.1.1.1:1")).await.status(), StatusCode::OK);
        assert_eq!(store.count(BarnacleKey::ApiKey(VALID_KEY.into()), "/", "GET"), 1);
    }

    #[tokio::test]
    async fn api_key_header_is_ignored_without_a_validator() {
        let store = MemoryStore::default();
        let layer: BarnacleLayer<(), MemoryStore> = BarnacleLayer::builder()
            .with_store(store.clone())
            .with_config(limit(2))
            .build()
            .unwrap();
        let app = Router::new().route("/", get(|| async { "ok" })).route_layer(layer);

        // A different made-up key per request must not give a fresh bucket
        let mut statuses = vec![];
        for attempt in 0..3 {
            statuses.push(send(&app, keyed(&format!("random-{attempt}"), "1.1.1.1:1")).await.status());
        }
        assert_eq!(statuses, [StatusCode::OK, StatusCode::OK, StatusCode::TOO_MANY_REQUESTS]);
    }
}

mod store_failures {
    use super::*;

    fn app(store: BrokenStore, policy: StoreFailurePolicy) -> Router {
        let layer: BarnacleLayer<(), BrokenStore> = BarnacleLayer::builder()
            .with_store(store)
            .with_config(limit(10))
            .with_store_failure_policy(policy)
            .with_store_timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        Router::new().route("/", get(|| async { "ok" })).route_layer(layer)
    }

    fn plain() -> Request<Body> {
        with_peer(request("GET", "/").body(Body::empty()).unwrap(), "1.1.1.1:1")
    }

    #[tokio::test]
    async fn fail_closed_rejects_when_the_store_is_down() {
        let app = app(BrokenStore { delay: None }, StoreFailurePolicy::FailClosed);
        assert_eq!(send(&app, plain()).await.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn fail_open_lets_requests_through_when_the_store_is_down() {
        let app = app(BrokenStore { delay: None }, StoreFailurePolicy::FailOpen);
        let response = send(&app, plain()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("x-ratelimit-limit"));
    }

    #[tokio::test]
    async fn slow_stores_time_out() {
        let slow = BrokenStore { delay: Some(Duration::from_secs(5)) };
        let closed = app(slow.clone(), StoreFailurePolicy::FailClosed);
        let started = std::time::Instant::now();
        assert_eq!(send(&closed, plain()).await.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(started.elapsed() < Duration::from_secs(1));

        let open = app(slow, StoreFailurePolicy::FailOpen);
        assert_eq!(send(&open, plain()).await.status(), StatusCode::OK);
    }
}

mod responses {
    use super::*;

    #[tokio::test]
    async fn rate_limit_headers_survive_custom_error_types() {
        let layer: BarnacleLayer<(), MemoryStore, (), AppError> = BarnacleLayer::builder()
            .with_store(MemoryStore::default())
            .with_config(limit(1))
            .build()
            .unwrap();
        let app = Router::new().route("/", get(|| async { "ok" })).route_layer(layer);

        let first = send(&app, with_peer(request("GET", "/").body(Body::empty()).unwrap(), "1.1.1.1:1")).await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = send(&app, with_peer(request("GET", "/").body(Body::empty()).unwrap(), "1.1.1.1:1")).await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        let headers = second.headers();
        assert_eq!(headers["retry-after"], "42");
        assert_eq!(headers["x-ratelimit-limit"], "1");
        assert_eq!(headers["x-ratelimit-remaining"], "0");
        assert_eq!(headers["x-ratelimit-reset"], "42");
    }

    #[tokio::test]
    async fn barnacle_error_response_has_retry_after() {
        let response = BarnacleError::rate_limit_exceeded(0, 30, 5).into_response();
        assert_eq!(response.headers()["retry-after"], "30");
    }
}

mod payload {
    use super::*;

    #[derive(Deserialize)]
    struct Login {
        email: String,
    }

    impl KeyExtractable for Login {
        fn extract_key(&self, _parts: &Parts) -> BarnacleKey {
            BarnacleKey::Email(self.email.clone())
        }
    }

    fn app(store: MemoryStore) -> Router {
        let layer: BarnacleLayer<Login, MemoryStore> = BarnacleLayer::builder()
            .with_store(store)
            .with_config(limit(10))
            .with_max_body_size(64)
            .build()
            .unwrap();
        Router::new()
            .route("/login", post(|body: String| async move { body }))
            .route_layer(layer)
    }

    #[tokio::test]
    async fn payload_key_is_extracted_and_body_forwarded() {
        let store = MemoryStore::default();
        let app = app(store.clone());
        let body = r#"{"email":"a@b.c"}"#;
        let req = request("POST", "/login").body(Body::from(body)).unwrap();
        let response = send(&app, with_peer(req, "1.1.1.1:1")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, body);
        assert_eq!(store.count(BarnacleKey::Email("a@b.c".into()), "/login", "POST"), 1);
    }

    #[tokio::test]
    async fn oversized_bodies_are_rejected() {
        let app = app(MemoryStore::default());
        let body = format!(r#"{{"email":"{}"}}"#, "a".repeat(100));

        // Declared length over the limit
        let req = request("POST", "/login").body(Body::from(body.clone())).unwrap();
        assert_eq!(send(&app, with_peer(req, "1.1.1.1:1")).await.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Streamed body without a declared length
        let stream = futures::stream::iter([Ok::<_, std::io::Error>(axum::body::Bytes::from(body))]);
        let req = request("POST", "/login").body(Body::from_stream(stream)).unwrap();
        assert_eq!(send(&app, with_peer(req, "1.1.1.1:1")).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn bodies_are_not_buffered_when_the_key_is_not_in_the_payload() {
        let layer: BarnacleLayer<(), MemoryStore> = BarnacleLayer::builder()
            .with_store(MemoryStore::default())
            .with_config(limit(10))
            .with_max_body_size(8)
            .build()
            .unwrap();
        let app = Router::new()
            .route("/upload", post(|body: String| async move { body.len().to_string() }))
            .route_layer(layer);
        // The limit only applies to bodies Barnacle reads, this one goes straight to the handler
        let req = request("POST", "/upload").body(Body::from("x".repeat(1000))).unwrap();
        let response = send(&app, with_peer(req, "1.1.1.1:1")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_text(response).await, "1000");
    }
}
