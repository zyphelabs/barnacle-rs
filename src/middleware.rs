use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, MatchedPath, OriginalUri, Request};
use axum::http::request::Parts;
use axum::http::{header::CONTENT_LENGTH, Extensions, HeaderMap, Method, Response};
use axum::response::IntoResponse;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use serde::de::DeserializeOwned;
use std::any::TypeId;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::{Layer, Service};
use tracing::{debug, warn};

use crate::error::BarnacleError;
use crate::types::{
    ApiKeyConfig, ClientIpStrategy, RateLimitScope, ResetOnSuccess, StoreFailurePolicy, NO_KEY,
};
use crate::RedisBarnacleStore;
use crate::{
    types::{BarnacleConfig, BarnacleContext, BarnacleKey},
    BarnacleStore,
};

/// Bucket used to count failed API key validations per client IP.
///
/// It is shared by every layer configured with
/// [`BarnacleLayerBuilder::with_failed_validation_limit`].
pub const FAILED_VALIDATION_SCOPE: &str = "@failed_api_key_validation";

/// Method recorded in contexts that are not tied to a single route and method.
const ANY_METHOD: &str = "*";

/// Trait to extract the key from any payload type
pub trait KeyExtractable {
    fn extract_key(&self, request_parts: &Parts) -> BarnacleKey;
}

/// Error type for BarnacleLayerBuilder
#[derive(Debug, thiserror::Error)]
pub enum BarnacleLayerBuilderError {
    #[error("Missing store")]
    MissingStore,
    #[error("Missing config")]
    MissingConfig,
}

/// Layer settings that don't depend on the generic parameters
#[derive(Debug, Default)]
struct LayerOptions {
    scope: RateLimitScope,
    client_ip_strategy: Arc<ClientIpStrategy>,
    failed_validation_limit: Option<BarnacleConfig>,
    store_failure_policy: StoreFailurePolicy,
    store_timeout: Option<Duration>,
    max_body_size: Option<usize>,
}

/// Builder for BarnacleLayer
pub struct BarnacleLayerBuilder<T = (), S = RedisBarnacleStore, State = (), E = BarnacleError, V = (), M = ()> {
    store: Option<S>,
    config: Option<BarnacleConfig>,
    state: Option<State>,
    api_key_validator: Option<V>,
    api_key_middleware_config: Option<ApiKeyConfig>,
    request_modifier: Option<M>,
    options: LayerOptions,
    _phantom: PhantomData<(T, E)>,
}

impl<T, S, State, E, V, M> BarnacleLayerBuilder<T, S, State, E, V, M>
where
    S: BarnacleStore + 'static,
    State: Clone +Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    pub fn with_store(mut self, store: S) -> Self {
        self.store = Some(store);
        self
    }
    pub fn with_config(mut self, config: BarnacleConfig) -> Self {
        self.config = Some(config);
        self
    }
    pub fn with_state(mut self, state: State) -> Self {
        self.state = Some(state);
        self
    }
    pub fn with_api_key_validator(mut self, validator: V) -> Self {
        self.api_key_validator = Some(validator);
        self
    }
    pub fn with_api_key_middleware_config(mut self, config: ApiKeyConfig) -> Self {
        self.api_key_middleware_config = Some(config);
        self
    }
    pub fn with_request_modifier(mut self, modifier: M) -> Self {
        self.request_modifier = Some(modifier);
        self
    }
    /// Which requests share a bucket, see [`RateLimitScope`] (default: concrete path).
    pub fn with_scope(mut self, scope: RateLimitScope) -> Self {
        self.options.scope = scope;
        self
    }
    /// How the client IP is resolved for IP-based keys, see [`ClientIpStrategy`].
    pub fn with_client_ip_strategy(mut self, strategy: ClientIpStrategy) -> Self {
        self.options.client_ip_strategy = Arc::new(strategy);
        self
    }
    /// Count failed API key validations per client IP and reject clients over `limit`
    /// with 429 before the validator runs again.
    ///
    /// Only requests that carry a non-empty API key are counted. The counter is shared
    /// by every layer that sets a limit (see [`FAILED_VALIDATION_SCOPE`]).
    pub fn with_failed_validation_limit(mut self, limit: BarnacleConfig) -> Self {
        self.options.failed_validation_limit = Some(limit);
        self
    }
    /// What to do when the store fails or times out (default: fail closed).
    pub fn with_store_failure_policy(mut self, policy: StoreFailurePolicy) -> Self {
        self.options.store_failure_policy = policy;
        self
    }
    /// Maximum time a single store operation may take; slower operations count as
    /// store failures and follow the [`StoreFailurePolicy`].
    pub fn with_store_timeout(mut self, timeout: Duration) -> Self {
        self.options.store_timeout = Some(timeout);
        self
    }
    /// Maximum body size buffered to extract a payload key; larger bodies get 413.
    ///
    /// The body is only buffered when the key comes from the payload (`T` is not `()`
    /// and no API key was validated); in every other case it is streamed to the handler
    /// untouched and its size is up to the application.
    pub fn with_max_body_size(mut self, limit: usize) -> Self {
        self.options.max_body_size = Some(limit);
        self
    }
    pub fn build(self) -> Result<BarnacleLayer<T, S, State, E, V, M>, BarnacleLayerBuilderError> {
        Ok(BarnacleLayer {
            store: self.store.ok_or(BarnacleLayerBuilderError::MissingStore)?,
            config: self.config.ok_or(BarnacleLayerBuilderError::MissingConfig)?,
            state: self.state,
            api_key_validator: self.api_key_validator,
            api_key_middleware_config: self.api_key_middleware_config,
            request_modifier: self.request_modifier,
            options: Arc::new(self.options),
            _phantom: PhantomData,
        })
    }
}

/// Generic rate limiting and API key layer
pub struct BarnacleLayer<T = (), S = RedisBarnacleStore, State = (), E = BarnacleError, V = (), M = ()> {
    store: S,
    config: BarnacleConfig,
    state: Option<State>,
    api_key_validator: Option<V>,
    api_key_middleware_config: Option<ApiKeyConfig>,
    request_modifier: Option<M>,
    options: Arc<LayerOptions>,
    _phantom: PhantomData<(T, E)>,
}

impl<T, S, State, E, V, M> Clone for BarnacleLayer<T, S, State, E, V, M>
where
    S: Clone + BarnacleStore + 'static,
    State: Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            config: self.config.clone(),
            state: self.state.clone(),
            api_key_validator: self.api_key_validator.clone(),
            api_key_middleware_config: self.api_key_middleware_config.clone(),
            request_modifier: self.request_modifier.clone(),
            options: self.options.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T, S, State, E, V, M> BarnacleLayer<T, S, State, E, V, M>
where
    S: BarnacleStore + 'static,
    State: Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    pub fn builder() -> BarnacleLayerBuilder<T, S, State, E, V, M> {
        BarnacleLayerBuilder {
            store: None,
            config: None,
            state: None,
            api_key_validator: None,
            api_key_middleware_config: None,
            request_modifier: None,
            options: LayerOptions::default(),
            _phantom: PhantomData,
        }
    }
}

impl<Inner, T, S, State, E, V, M> Layer<Inner> for BarnacleLayer<T, S, State, E, V, M>
where
    T: DeserializeOwned + KeyExtractable + Send + 'static,
    S: Clone + BarnacleStore + 'static,
    State: Clone + Send + Sync + 'static,
    E: IntoResponse + Send + Sync + 'static,
    Inner: Clone,
    V: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type Service = BarnacleMiddleware<Inner, T, S, State, E, V, M>;
    fn layer(&self, inner: Inner) -> Self::Service {
        BarnacleMiddleware {
            inner,
            store: self.store.clone(),
            config: self.config.clone(),
            state: self.state.clone(),
            api_key_validator: self.api_key_validator.clone(),
            api_key_config: self.api_key_middleware_config.clone(),
            request_modifier: self.request_modifier.clone(),
            options: self.options.clone(),
            _phantom: PhantomData,
        }
    }
}

/// Runs a store operation, turning a timeout into a store error
async fn call_store<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, BarnacleError>>,
) -> Result<T, BarnacleError> {
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, operation)
            .await
            .unwrap_or_else(|_| Err(BarnacleError::store_error("Rate limit store timed out"))),
        None => operation.await,
    }
}

/// Converts a rate limit error into `E`'s response, keeping the rate limit headers
/// even if `E` drops them.
fn rate_limited_response<E>(error: BarnacleError) -> Response<Body>
where
    E: IntoResponse + From<BarnacleError>,
{
    let rate_limit_headers = error.rate_limit_headers();
    let mut response = E::from(error).into_response();
    if let Some(rate_limit_headers) = rate_limit_headers {
        let headers = response.headers_mut();
        for (name, value) in rate_limit_headers.iter() {
            if !headers.contains_key(name) {
                headers.insert(name.clone(), value.clone());
            }
        }
    }
    response
}

/// Response for a failed store operation, or `None` when the failure policy lets
/// the request through.
fn store_error_response<E>(error: BarnacleError, policy: StoreFailurePolicy) -> Option<Response<Body>>
where
    E: IntoResponse + From<BarnacleError>,
{
    if matches!(error, BarnacleError::RateLimitExceeded { .. }) {
        return Some(rate_limited_response::<E>(error));
    }
    match policy {
        StoreFailurePolicy::FailClosed => Some(E::from(error).into_response()),
        StoreFailurePolicy::FailOpen => {
            warn!("Rate limit store unavailable, letting the request through: {}", error);
            None
        }
    }
}

/// Helper function to handle rate limit reset logic
async fn handle_rate_limit_reset<S>(
    store: &S,
    config: &BarnacleConfig,
    context: &BarnacleContext,
    status_code: u16,
    store_timeout: Option<Duration>,
) where
    S: BarnacleStore + 'static,
{
    if config.reset_on_success == ResetOnSuccess::Not {
        return;
    }

    if !config.is_success_status(status_code) {
        debug!(
            "Not resetting rate limit for key {:?} due to error status: {}",
            context.key,
            status_code
        );
        return;
    }

    let mut contexts = vec![context.clone()];

    if let ResetOnSuccess::Multiple(_, extra_contexts) = &config.reset_on_success {
        contexts.extend(extra_contexts.iter().cloned());
    }

    for ctx in contexts.iter_mut() {
        if ctx.key == BarnacleKey::Custom(NO_KEY.to_string()) {
            ctx.key = context.key.clone();
        }
        match call_store(store_timeout, store.reset(ctx)).await {
            Ok(_) => debug!(
                "Rate limit reset for key {:?} after successful request (status: {}) path: {}",
                ctx.key,
                status_code,
                ctx.path
            ),
            Err(e) => warn!(
                "Failed to reset rate limit for key {:?}: {} path: {}",
                ctx.key,
                e,
                ctx.path
            ),
        }
    }
}

/// The client IP strategy of the innermost Barnacle layer, stored in the request
/// extensions so that [`client_ip`] works inside key extractors.
#[derive(Clone)]
struct ClientIpStrategyExtension(Arc<ClientIpStrategy>);

fn header_ip(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    let ip = value.split(',').next().unwrap_or("").trim();
    (!ip.is_empty() && ip != "unknown").then(|| ip.to_string())
}

fn resolve_client_ip(
    extensions: &Extensions,
    headers: &HeaderMap,
    strategy: &ClientIpStrategy,
) -> Option<String> {
    let peer = extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_canonical());

    match strategy {
        ClientIpStrategy::Legacy => peer
            .map(|ip| ip.to_string())
            .or_else(|| header_ip(headers, "x-forwarded-for"))
            .or_else(|| header_ip(headers, "x-real-ip")),
        ClientIpStrategy::PeerOnly => peer.map(|ip| ip.to_string()),
        ClientIpStrategy::TrustedProxies(trusted) => {
            let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));
            if let Some(peer) = peer.filter(|peer| !is_trusted(peer)) {
                return Some(peer.to_string());
            }

            // The rightmost entries were appended by our proxies: the first entry that
            // is not a trusted proxy is the client, anything left of it is client input.
            let hops: Vec<&str> = headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .filter(|hop| !hop.is_empty())
                .collect();
            let mut leftmost_trusted = None;
            for hop in hops.iter().rev() {
                match hop.parse::<IpAddr>() {
                    Ok(ip) => {
                        let ip = ip.to_canonical();
                        if !is_trusted(&ip) {
                            return Some(ip.to_string());
                        }
                        leftmost_trusted = Some(ip.to_string());
                    }
                    // Not an address (e.g. a client value relayed as is): nothing left
                    // of it can be trusted, and it must not become a bucket key
                    Err(_) => break,
                }
            }
            leftmost_trusted.or_else(|| peer.map(|ip| ip.to_string()))
        }
    }
}

fn fallback_key(
    extensions: &Extensions,
    headers: &HeaderMap,
    path: &str,
    method: &Method,
) -> BarnacleKey {
    let strategy = extensions.get::<ClientIpStrategyExtension>();
    let default_strategy = ClientIpStrategy::default();
    let strategy = strategy.map_or(&default_strategy, |ext| ext.0.as_ref());

    match resolve_client_ip(extensions, headers, strategy) {
        Some(ip) => BarnacleKey::Ip(ip),
        // No client IP (e.g. local requests without ConnectInfo): one bucket per route + method
        None => BarnacleKey::Ip(format!("local:{}:{}", method.as_str(), path)),
    }
}

/// Client IP of the request, resolved with the [`ClientIpStrategy`] of the Barnacle
/// layer that wraps it (the legacy strategy outside of a Barnacle layer).
///
/// Useful in [`KeyExtractable`] implementations that fall back to the client IP.
pub fn client_ip(parts: &Parts) -> Option<String> {
    let default_strategy = ClientIpStrategy::default();
    let strategy = parts
        .extensions
        .get::<ClientIpStrategyExtension>()
        .map_or(&default_strategy, |ext| ext.0.as_ref());
    resolve_client_ip(&parts.extensions, &parts.headers, strategy)
}

/// The IP-based key Barnacle falls back to when no other key is available.
pub fn client_ip_key(parts: &Parts) -> BarnacleKey {
    fallback_key(&parts.extensions, &parts.headers, parts.uri.path(), &parts.method)
}

/// The actual middleware that handles payload-based key extraction
pub struct BarnacleMiddleware<Inner, T, S, State = (), E = BarnacleError, V = (), M = ()> {
    inner: Inner,
    store: S,
    config: BarnacleConfig,
    state: Option<State>,
    api_key_validator: Option<V>,
    api_key_config: Option<ApiKeyConfig>,
    request_modifier: Option<M>,
    options: Arc<LayerOptions>,
    _phantom: PhantomData<(T, E)>,
}

impl<Inner, T, S, State, E, V, M> Clone for BarnacleMiddleware<Inner, T, S, State, E, V, M>
where
    Inner: Clone,
    S: Clone + BarnacleStore + 'static,
    State: Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            store: self.store.clone(),
            config: self.config.clone(),
            state: self.state.clone(),
            api_key_validator: self.api_key_validator.clone(),
            api_key_config: self.api_key_config.clone(),
            request_modifier: self.request_modifier.clone(),
            options: self.options.clone(),
            _phantom: PhantomData,
        }
    }
}

// --- ValidatorCall trait for owned types ---
pub trait ValidatorCall<T, S, State, E> {
    fn call(
        &self,
        api_key: T,
        api_key_config: S,
        parts: Arc<Parts>,
        state: State,
    ) -> Pin<Box<dyn Future<Output = Result<(), E>> + Send>>;
}

// Implementation for closures
impl<F, Fut, T, S, State, E> ValidatorCall<T, S, State, E> for F
where
    F: Fn(T, S, Arc<Parts>, State) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    T: Send + 'static,
    S: Send + 'static,
    State: Send + 'static,
    E: Send + 'static,
{
    fn call(
        &self,
        api_key: T,
        api_key_config: S,
        parts: Arc<Parts>,
        state: State,
    ) -> Pin<Box<dyn Future<Output = Result<(), E>> + Send>> {
        Box::pin((self)(api_key, api_key_config, parts, state))
    }
}

// Implementation for ()
impl<T, S, State, E> ValidatorCall<T, S, State, E> for () {
    fn call(
        &self,
        _api_key: T,
        _api_key_config: S,
        _parts: Arc<Parts>,
        _state: State,
    ) -> Pin<Box<dyn Future<Output = Result<(), E>> + Send>> {
        Box::pin(async { Ok(()) })
    }
}

// --- RequestModifier trait for owned types ---
pub trait RequestModifier<Parts, State, E> {
    fn modify(
        &self,
        parts: Parts,
        state: State,
    ) -> Pin<Box<dyn Future<Output = Result<Parts, E>> + Send>>;
}

// Blanket impl to require Send for Parts
impl<Parts, State, E> RequestModifier<Parts, State, E> for ()
where
    Parts: Send + 'static,
{
    fn modify(
        &self,
        parts: Parts,
        _state: State,
    ) -> Pin<Box<dyn Future<Output = Result<Parts, E>> + Send>> {
        Box::pin(async { Ok(parts) })
    }
}

// Implementation for closures
impl<F, Fut, Parts, State, E> RequestModifier<Parts, State, E> for F
where
    F: Fn(Parts, State) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Parts, E>> + Send + 'static,
    Parts: Send + 'static,
    State: Send + 'static,
    E: Send + 'static,
{
    fn modify(
        &self,
        parts: Parts,
        state: State,
    ) -> Pin<Box<dyn Future<Output = Result<Parts, E>> + Send>> {
        Box::pin((self)(parts, state))
    }
}

// Provide a KeyExtractable impl for ()
impl KeyExtractable for () {
    fn extract_key(&self, request_parts: &Parts) -> BarnacleKey {
        client_ip_key(request_parts)
    }
}

/// Buffers the body up to `limit` bytes
async fn collect_body<B>(body: B, limit: Option<usize>) -> Result<Bytes, BarnacleError>
where
    B: axum::body::HttpBody<Data = Bytes> + Send + 'static,
    B::Error: Into<axum::BoxError>,
{
    let collected = match limit {
        Some(limit) => Limited::new(body, limit).collect().await.map_err(|e| {
            if e.is::<LengthLimitError>() {
                BarnacleError::PayloadTooLarge { limit }
            } else {
                BarnacleError::request_parsing_error(format!("Failed to read request body: {e}"))
            }
        })?,
        None => body.collect().await.map_err(|e| {
            BarnacleError::request_parsing_error(format!(
                "Failed to read request body: {}",
                e.into()
            ))
        })?,
    };
    Ok(collected.to_bytes())
}

impl<Inner, B, T, S, State, E, V, M> Service<Request<B>> for BarnacleMiddleware<Inner, T, S, State, E, V, M>
where
    Inner: Service<Request<axum::body::Body>, Response = Response<Body>> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
    B: axum::body::HttpBody<Data = Bytes> + Send + 'static,
    B::Error: Into<axum::BoxError>,
    S: Clone + BarnacleStore + 'static,
    State: Clone + Send + Sync + 'static,
    T: KeyExtractable + DeserializeOwned + Send + 'static,
    E: IntoResponse + Send + Sync + 'static + From<BarnacleError>,
    V: ValidatorCall<String, ApiKeyConfig, State, E> + Clone + Send + Sync + 'static,
    M: RequestModifier<Parts, State, E> + Clone + Send + Sync + 'static,
{
    type Response = Inner::Response;
    type Error = Inner::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let mut inner = self.inner.clone();
        let store = self.store.clone();
        let config = self.config.clone();
        let state = self.state.clone();
        let validator_state = state.clone(); // Separate clone for validator to avoid move issues
        let api_key_validator = self.api_key_validator.clone();
        let api_key_config = self.api_key_config.clone();
        let request_modifier = self.request_modifier.clone();
        let options = self.options.clone();
        Box::pin(async move {
            let current_path = req
                .extensions()
                .get::<OriginalUri>()
                .map(|original_url| original_url.path().to_owned())
                .unwrap_or(req.uri().path().to_owned());

            let (mut parts, body) = req.into_parts();
            parts
                .extensions
                .insert(ClientIpStrategyExtension(options.client_ip_strategy.clone()));

            // API key validation (if configured)
            let api_key_config = api_key_config.unwrap_or_default();
            let api_key = parts
                .headers
                .get(api_key_config.header_name.as_str())
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_owned();

            // Failed validations are counted per client IP, and only for requests that
            // carry a key: those are the ones that cost a lookup in the validator.
            let failed_validation = match (&api_key_validator, &options.failed_validation_limit) {
                (Some(_), Some(limit)) if !api_key.is_empty() => {
                    let context = BarnacleContext {
                        key: fallback_key(&parts.extensions, &parts.headers, &current_path, &parts.method),
                        path: FAILED_VALIDATION_SCOPE.to_string(),
                        method: ANY_METHOD.to_string(),
                    };
                    Some((context, limit))
                }
                _ => None,
            };

            if let Some((context, limit)) = &failed_validation {
                if let Err(e) = call_store(options.store_timeout, store.peek(context, limit)).await {
                    if let Some(response) = store_error_response::<E>(e, options.store_failure_policy) {
                        debug!("Rejecting key {:?}: too many failed API key validations", context.key);
                        return Ok(response);
                    }
                }
            }

            let validation_result = if let Some(validator) = api_key_validator.as_ref() {
                let is_stateless_validator = TypeId::of::<V>() == TypeId::of::<()>();
                let is_unit_state = TypeId::of::<State>() == TypeId::of::<()>();
                if is_stateless_validator && is_unit_state {
                    // Both validator and state are (), safe to call with zeroed State
                    validator.call(api_key.clone(), api_key_config, Arc::new(parts.clone()), unsafe { std::mem::zeroed() }).await
                } else {
                    match validator_state {
                        Some(validator_state) => {
                            validator.call(api_key.clone(), api_key_config, Arc::new(parts.clone()), validator_state).await
                        }
                        None => {
                            // Return a more appropriate error for missing validator state
                            Err(E::from(BarnacleError::custom("Barnacle: API key validator requires state, but none was provided. Use with_state() or use () for stateless validators.", None)))
                        }
                    }
                }
            } else {
                Ok(())
            };
            if let Err(e) = validation_result {
                debug!("API key validation failed");
                if let Some((context, limit)) = &failed_validation {
                    match call_store(options.store_timeout, store.increment(context, limit)).await {
                        Ok(_) => {}
                        // Another request reached the limit in the meantime
                        Err(limit_error @ BarnacleError::RateLimitExceeded { .. }) => {
                            return Ok(rate_limited_response::<E>(limit_error));
                        }
                        Err(store_error) => {
                            warn!("Failed to count failed API key validation: {}", store_error)
                        }
                    }
                }
                return Ok(e.into_response());
            }
            // Only a validated key identifies the client: without a validator anyone could
            // send a different key per request to get a fresh bucket every time
            let api_key_used = api_key_validator
                .is_some()
                .then_some(api_key)
                .filter(|api_key| !api_key.is_empty());

            // Apply request modifier after validation (if configured)
            let modified_parts = if let Some(modifier) = request_modifier.as_ref() {
                // Clone state for modifier to avoid move issues
                let modifier_state = state.clone();
                if let Some(modifier_state) = modifier_state {
                    modifier.modify(parts, modifier_state).await
                } else {
                    Err(E::from(BarnacleError::custom("Barnacle: Request modifier requires state, but none was provided.", None)))
                }
            } else {
                Ok(parts)
            };
            let parts = match modified_parts {
                Ok(modified_parts) => modified_parts,
                Err(e) => {
                    debug!("Request modifier returned an error");
                    return Ok(e.into_response());
                }
            };

            // The body is only buffered when the key has to be read from the payload
            let reads_payload = api_key_used.is_none() && TypeId::of::<T>() != TypeId::of::<()>();
            let (key, body) = if let Some(api_key) = api_key_used {
                (BarnacleKey::ApiKey(api_key), Body::new(body))
            } else if !reads_payload {
                (
                    fallback_key(&parts.extensions, &parts.headers, &current_path, &parts.method),
                    Body::new(body),
                )
            } else {
                if let Some(limit) = options.max_body_size {
                    let content_length = parts
                        .headers
                        .get(CONTENT_LENGTH)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<usize>().ok());
                    if content_length.is_some_and(|length| length > limit) {
                        return Ok(E::from(BarnacleError::PayloadTooLarge { limit }).into_response());
                    }
                }
                let bytes = match collect_body(body, options.max_body_size).await {
                    Ok(bytes) => bytes,
                    Err(e) => return Ok(E::from(e).into_response()),
                };
                let key = match serde_json::from_slice::<T>(&bytes) {
                    Ok(payload) => payload.extract_key(&parts),
                    Err(_) => {
                        debug!("Payload key not found, using the client IP");
                        fallback_key(&parts.extensions, &parts.headers, &current_path, &parts.method)
                    }
                };
                (key, Body::from(bytes))
            };

            let (path, method) = match &options.scope {
                RateLimitScope::Path => (current_path, parts.method.as_str().to_string()),
                RateLimitScope::Route => (
                    parts
                        .extensions
                        .get::<MatchedPath>()
                        .map(|matched| matched.as_str().to_owned())
                        .unwrap_or(current_path),
                    parts.method.as_str().to_string(),
                ),
                RateLimitScope::Named(name) => (name.clone(), ANY_METHOD.to_string()),
            };
            let rate_limit_context = BarnacleContext { key, path, method };

            let result = match call_store(options.store_timeout, store.increment(&rate_limit_context, &config)).await {
                Ok(result) => Some(result),
                Err(e) => {
                    debug!("Rate limit not passed for context {:?}: {}", rate_limit_context, e);
                    match store_error_response::<E>(e, options.store_failure_policy) {
                        Some(response) => return Ok(response),
                        None => None,
                    }
                }
            };

            let mut response = inner.call(Request::from_parts(parts, body)).await?;

            // Without a result the store failed open: no counter to report or reset
            let Some(result) = result else {
                return Ok(response);
            };
            let headers = response.headers_mut();
            if let Ok(remaining_header) = result.remaining.to_string().parse() {
                headers.insert("X-RateLimit-Remaining", remaining_header);
            }
            if let Ok(limit_header) = config.max_requests.to_string().parse() {
                headers.insert("X-RateLimit-Limit", limit_header);
            }
            if let Some(retry_after) = result.retry_after {
                if let Ok(reset_header) = retry_after.as_secs().to_string().parse() {
                    headers.insert("X-RateLimit-Reset", reset_header);
                }
            }
            handle_rate_limit_reset(
                &store,
                &config,
                &rate_limit_context,
                response.status().as_u16(),
                options.store_timeout,
            )
            .await;
            Ok(response)
        })
    }
}
