use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, MatchedPath, OriginalUri, Request};
use axum::http::request::Parts;
use axum::http::{
    header::CONTENT_LENGTH, Extensions, HeaderMap, HeaderValue, Method, Response, StatusCode,
};
use axum::response::IntoResponse;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use serde::de::DeserializeOwned;
use std::any::Any;
use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::{Layer, Service};
use tracing::{debug, info, warn};

use crate::error::BarnacleError;
use crate::limits::{
    strictest, Bucket, BucketState, DecisionOutcome, Identity, Limit, LimitOutcome, Mode,
    RateLimitDecision,
};
use crate::types::{
    ApiKeyConfig, BarnacleConfig, BarnacleContext, BarnacleKey, BarnacleResult, ClientIpStrategy,
    RateLimitScope, ResetOnSuccess, StoreFailurePolicy, NO_KEY,
};
use crate::BarnacleStore;
use crate::RedisBarnacleStore;

/// Bucket used to count failed API key validations per client IP.
///
/// It is shared by every layer configured with
/// [`BarnacleLayerBuilder::with_failed_validation_limit`].
pub const FAILED_VALIDATION_SCOPE: &str = "@failed_api_key_validation";

/// Trait to extract the key from any payload type
pub trait KeyExtractable {
    fn extract_key(&self, request_parts: &Parts) -> BarnacleKey;
}

/// Resolves who a request is counted for, and with which limits.
///
/// It runs after the API key validator and the request modifier, on the request as the
/// application's own middleware left it: add the Barnacle layer *inside* the
/// authentication middleware (in axum, call `.layer(barnacle)` before
/// `.layer(auth)`) to read the authenticated principal from the request extensions.
///
/// Returning `None` (e.g. an unauthenticated request) falls back to Barnacle's own key:
/// the validated API key, the payload key, or the client IP, with the layer's limits.
///
/// For a synchronous resolver, pass a closure to
/// [`BarnacleLayerBuilder::with_identifier`] instead of implementing this trait.
#[async_trait::async_trait]
pub trait IdentityResolver<State>: Send + Sync {
    async fn identify(&self, parts: &Parts, state: &State) -> Option<Identity>;
}

/// [`IdentityResolver`] for the closures given to [`BarnacleLayerBuilder::with_identifier`]
struct FnIdentifier<F>(F);

#[async_trait::async_trait]
impl<F, State> IdentityResolver<State> for FnIdentifier<F>
where
    F: Fn(&Parts, &State) -> Option<Identity> + Send + Sync,
    State: Sync,
{
    async fn identify(&self, parts: &Parts, state: &State) -> Option<Identity> {
        (self.0)(parts, state)
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// API key validator, with its error already turned into a response
type Validator<State> = dyn Fn(String, ApiKeyConfig, Arc<Parts>, State) -> BoxFuture<Result<(), Response<Body>>>
    + Send
    + Sync;

/// Request modifier, with its error already turned into a response
type Modifier<State> =
    dyn Fn(Parts, State) -> BoxFuture<Result<Parts, Response<Body>>> + Send + Sync;

/// Reads the key from a buffered request body
type PayloadKey = fn(&[u8], &Parts) -> Option<BarnacleKey>;

/// Turns Barnacle's own errors into responses
type ErrorResponse = fn(BarnacleError) -> Response<Body>;

type DecisionHook = dyn Fn(&RateLimitDecision) + Send + Sync;

fn error_response<E>(error: BarnacleError) -> Response<Body>
where
    E: From<BarnacleError> + IntoResponse,
{
    E::from(error).into_response()
}

fn payload_key<T>(bytes: &[u8], parts: &Parts) -> Option<BarnacleKey>
where
    T: DeserializeOwned + KeyExtractable,
{
    serde_json::from_slice::<T>(bytes)
        .ok()
        .map(|payload| payload.extract_key(parts))
}

/// `Some(())` when `State` is `()`, so that stateless hooks don't need `with_state(())`.
fn unit_state<State: Clone + 'static>() -> Option<State> {
    (&() as &dyn Any).downcast_ref::<State>().cloned()
}

/// Error type for BarnacleLayerBuilder
#[derive(Debug, thiserror::Error)]
pub enum BarnacleLayerBuilderError {
    #[error("Missing store")]
    MissingStore,
    #[error("Missing config: set the limits with `with_config` or `with_limits`")]
    MissingConfig,
    #[error(
        "The API key validator, request modifier or identifier needs a state: use `with_state`"
    )]
    MissingState,
    #[error("Two limits can count the same bucket ({0}): give each limit its own scope")]
    DuplicateLimitScope(String),
}

/// The callbacks that take the layer state
struct Hooks<State> {
    state: State,
    api_key_validator: Option<Box<Validator<State>>>,
    request_modifier: Option<Box<Modifier<State>>>,
    identifier: Option<Box<dyn IdentityResolver<State>>>,
}

/// Everything the layer knows besides its store, shared by every clone of it
struct Settings<State> {
    limits: Vec<Limit>,
    reset_on_success: ResetOnSuccess,
    scope: RateLimitScope,
    mode: Mode,
    api_key_config: ApiKeyConfig,
    hooks: Option<Hooks<State>>,
    payload_key: Option<PayloadKey>,
    error_response: ErrorResponse,
    decision_hook: Option<Box<DecisionHook>>,
    client_ip_strategy: Arc<ClientIpStrategy>,
    failed_validation_limit: Option<BarnacleConfig>,
    store_failure_policy: StoreFailurePolicy,
    store_timeout: Option<Duration>,
    max_body_size: Option<usize>,
}

/// Builder for [`BarnacleLayer`]
pub struct BarnacleLayerBuilder<S = RedisBarnacleStore, State = ()> {
    store: Option<S>,
    limits: Option<Vec<Limit>>,
    state: Option<State>,
    api_key_validator: Option<Box<Validator<State>>>,
    request_modifier: Option<Box<Modifier<State>>>,
    identifier: Option<Box<dyn IdentityResolver<State>>>,
    settings: Settings<State>,
}

impl<S, State> BarnacleLayerBuilder<S, State>
where
    S: BarnacleStore + 'static,
    State: Clone + Send + Sync + 'static,
{
    pub fn with_store(mut self, store: S) -> Self {
        self.store = Some(store);
        self
    }
    /// A single limit, and whether a successful response resets it.
    ///
    /// Shorthand for [`Self::with_limits`] and [`Self::with_reset_on_success`].
    pub fn with_config(mut self, config: BarnacleConfig) -> Self {
        self.limits = Some(vec![Limit::from(&config)]);
        self.settings.reset_on_success = config.reset_on_success;
        self
    }
    /// Limits applied to every request, checked together and all or nothing (see
    /// [`Limit`]). An identifier can replace them per request.
    pub fn with_limits(mut self, limits: impl IntoIterator<Item = Limit>) -> Self {
        self.limits = Some(limits.into_iter().collect());
        self
    }
    /// Reset the counters of a request when its response has one of these status codes
    /// (default: never).
    pub fn with_reset_on_success(mut self, reset_on_success: ResetOnSuccess) -> Self {
        self.settings.reset_on_success = reset_on_success;
        self
    }
    /// State passed to the API key validator, the request modifier and the identifier.
    /// Not needed when the state is `()`.
    pub fn with_state(mut self, state: State) -> Self {
        self.state = Some(state);
        self
    }
    /// Validate the API key read from the header of [`ApiKeyConfig`] (`x-api-key` by
    /// default). A validated key identifies the client, unless an identifier resolves
    /// the request.
    ///
    /// The validator's error is turned into the response as is.
    pub fn with_api_key_validator<F, Fut, E>(mut self, validator: F) -> Self
    where
        F: Fn(String, ApiKeyConfig, Arc<Parts>, State) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        E: IntoResponse + 'static,
    {
        self.api_key_validator = Some(Box::new(move |api_key, config, parts, state| {
            let validation = validator(api_key, config, parts, state);
            Box::pin(async move { validation.await.map_err(IntoResponse::into_response) })
                as BoxFuture<_>
        }));
        self
    }
    pub fn with_api_key_middleware_config(mut self, config: ApiKeyConfig) -> Self {
        self.settings.api_key_config = config;
        self
    }
    /// Modify the request after the API key validation, before it is counted.
    ///
    /// The modifier's error is turned into the response as is.
    pub fn with_request_modifier<F, Fut, E>(mut self, modifier: F) -> Self
    where
        F: Fn(Parts, State) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Parts, E>> + Send + 'static,
        E: IntoResponse + 'static,
    {
        self.request_modifier = Some(Box::new(move |parts, state| {
            let modification = modifier(parts, state);
            Box::pin(async move { modification.await.map_err(IntoResponse::into_response) })
                as BoxFuture<_>
        }));
        self
    }
    /// Resolve who the request is counted for, and with which limits, from the request
    /// (typically the principal the authentication middleware stored in its extensions).
    ///
    /// See [`IdentityResolver`] for where it runs and what `None` means; implement that
    /// trait and use [`Self::with_identity_resolver`] when resolving is asynchronous.
    pub fn with_identifier<F>(self, identifier: F) -> Self
    where
        F: Fn(&Parts, &State) -> Option<Identity> + Send + Sync + 'static,
    {
        self.with_identity_resolver(FnIdentifier(identifier))
    }
    /// Asynchronous version of [`Self::with_identifier`].
    pub fn with_identity_resolver(
        mut self,
        resolver: impl IdentityResolver<State> + 'static,
    ) -> Self {
        self.identifier = Some(Box::new(resolver));
        self
    }
    /// Read the key from the JSON body, as `T` (e.g. the email of a login request).
    ///
    /// Only used when neither an identifier nor a validated API key identify the
    /// request; when `T` can't be parsed the key falls back to the client IP.
    pub fn with_payload_key<T>(mut self) -> Self
    where
        T: DeserializeOwned + KeyExtractable + 'static,
    {
        self.settings.payload_key = Some(payload_key::<T>);
        self
    }
    /// Answer Barnacle's own errors (rate limited, store down, body too large) with `E`
    /// instead of [`BarnacleError`]. Rate limit headers are kept even if `E` drops them.
    pub fn with_error<E>(mut self) -> Self
    where
        E: From<BarnacleError> + IntoResponse + 'static,
    {
        self.settings.error_response = error_response::<E>;
        self
    }
    /// Enforce the limits, or only measure them (see [`Mode::Shadow`]).
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.settings.mode = mode;
        self
    }
    /// Called for every rate limit decision, including the failed validation limit.
    /// A request can produce both a failed validation limit decision and a regular
    /// request limit decision in shadow mode or with a fail-open store policy.
    /// It runs on the request path: keep it fast and non-blocking.
    pub fn on_decision(
        mut self,
        hook: impl Fn(&RateLimitDecision) + Send + Sync + 'static,
    ) -> Self {
        self.settings.decision_hook = Some(Box::new(hook));
        self
    }
    /// Which requests share a bucket, see [`RateLimitScope`] (default: concrete path).
    ///
    /// Applies to the limits that don't set their own scope.
    pub fn with_scope(mut self, scope: RateLimitScope) -> Self {
        self.settings.scope = scope;
        self
    }
    /// How the client IP is resolved for IP-based keys, see [`ClientIpStrategy`].
    pub fn with_client_ip_strategy(mut self, strategy: ClientIpStrategy) -> Self {
        self.settings.client_ip_strategy = Arc::new(strategy);
        self
    }
    /// Count failed API key validations per client IP and reject clients over `limit`
    /// with 429 before the validator runs again.
    ///
    /// Only requests that carry a non-empty API key and fail authentication (the
    /// validator's error is a 401 or a 403) are counted; a validator that fails because
    /// its own backend is down does not lock the client out. The counter is shared by
    /// every layer that sets a limit (see [`FAILED_VALIDATION_SCOPE`]).
    ///
    /// # The limit is only as precise as the client IP
    ///
    /// The bucket is the client IP, so this needs a [`ClientIpStrategy`] that resolves
    /// the real client: [`ClientIpStrategy::TrustedProxies`] behind a proxy, or
    /// [`ClientIpStrategy::PeerOnly`] when the application is directly exposed. With the
    /// default [`ClientIpStrategy::Legacy`] behind a load balancer every client is seen
    /// as the balancer, so they all share one counter and a single attacker can get
    /// everyone rejected for the length of the window.
    ///
    /// When no client IP can be resolved at all (e.g. no `ConnectInfo` and no usable
    /// header) the limit is skipped for that request rather than counted in a bucket
    /// shared by unrelated clients.
    pub fn with_failed_validation_limit(mut self, limit: BarnacleConfig) -> Self {
        self.settings.failed_validation_limit = Some(limit);
        self
    }
    /// What to do when the store fails or times out (default: fail closed).
    pub fn with_store_failure_policy(mut self, policy: StoreFailurePolicy) -> Self {
        self.settings.store_failure_policy = policy;
        self
    }
    /// Maximum time a single store operation may take; slower operations count as
    /// store failures and follow the [`StoreFailurePolicy`].
    pub fn with_store_timeout(mut self, timeout: Duration) -> Self {
        self.settings.store_timeout = Some(timeout);
        self
    }
    /// Maximum body size buffered to extract a payload key; larger bodies get 413.
    ///
    /// The body is only buffered when the key comes from the payload (see
    /// [`Self::with_payload_key`]); in every other case it is streamed to the handler
    /// untouched and its size is up to the application.
    pub fn with_max_body_size(mut self, limit: usize) -> Self {
        self.settings.max_body_size = Some(limit);
        self
    }
    pub fn build(self) -> Result<BarnacleLayer<S, State>, BarnacleLayerBuilderError> {
        let store = self.store.ok_or(BarnacleLayerBuilderError::MissingStore)?;
        let mut settings = self.settings;
        settings.limits = self
            .limits
            .ok_or(BarnacleLayerBuilderError::MissingConfig)?;
        if let Some(collision) = settings.colliding_scopes(&settings.limits) {
            return Err(BarnacleLayerBuilderError::DuplicateLimitScope(collision));
        }
        if self.api_key_validator.is_some()
            || self.request_modifier.is_some()
            || self.identifier.is_some()
        {
            settings.hooks = Some(Hooks {
                state: self
                    .state
                    .or_else(unit_state::<State>)
                    .ok_or(BarnacleLayerBuilderError::MissingState)?,
                api_key_validator: self.api_key_validator,
                request_modifier: self.request_modifier,
                identifier: self.identifier,
            });
        }
        Ok(BarnacleLayer {
            store,
            settings: Arc::new(settings),
        })
    }
}

/// Rate limiting and API key layer.
///
/// `S` is the rate limit store, `State` the state passed to the API key validator,
/// the request modifier and the identifier.
pub struct BarnacleLayer<S = RedisBarnacleStore, State = ()> {
    store: S,
    settings: Arc<Settings<State>>,
}

impl<S: Clone, State> Clone for BarnacleLayer<S, State> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            settings: self.settings.clone(),
        }
    }
}

impl<S, State> BarnacleLayer<S, State>
where
    S: BarnacleStore + 'static,
    State: Clone + Send + Sync + 'static,
{
    pub fn builder() -> BarnacleLayerBuilder<S, State> {
        BarnacleLayerBuilder {
            store: None,
            limits: None,
            state: None,
            api_key_validator: None,
            request_modifier: None,
            identifier: None,
            settings: Settings {
                limits: Vec::new(),
                reset_on_success: ResetOnSuccess::Not,
                scope: RateLimitScope::default(),
                mode: Mode::default(),
                api_key_config: ApiKeyConfig::default(),
                hooks: None,
                payload_key: None,
                error_response: error_response::<BarnacleError>,
                decision_hook: None,
                client_ip_strategy: Arc::default(),
                failed_validation_limit: None,
                store_failure_policy: StoreFailurePolicy::default(),
                store_timeout: None,
                max_body_size: None,
            },
        }
    }
}

impl<Inner, S: Clone, State> Layer<Inner> for BarnacleLayer<S, State> {
    type Service = BarnacleMiddleware<Inner, S, State>;
    fn layer(&self, inner: Inner) -> Self::Service {
        BarnacleMiddleware {
            inner,
            store: self.store.clone(),
            settings: self.settings.clone(),
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

/// Converts a rate limit error into the layer's error response, keeping the rate limit
/// headers even if the error type drops them.
fn rate_limited_response(respond: ErrorResponse, error: BarnacleError) -> Response<Body> {
    let rate_limit_headers = error.rate_limit_headers();
    let mut response = respond(error);
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

/// `X-RateLimit-*` headers of a request that went through, for the strictest limit
fn insert_rate_limit_headers(headers: &mut HeaderMap, max_requests: u32, state: &BucketState) {
    headers.insert("X-RateLimit-Remaining", HeaderValue::from(state.remaining));
    headers.insert("X-RateLimit-Limit", HeaderValue::from(max_requests));
    headers.insert(
        "X-RateLimit-Reset",
        HeaderValue::from(state.reset_after.as_secs()),
    );
}

/// The client IP strategy of the innermost Barnacle layer, stored in the request
/// extensions so that [`client_ip`] works inside key extractors.
#[derive(Clone)]
struct ClientIpStrategyExtension(Arc<ClientIpStrategy>);

/// Parses one `X-Forwarded-For` (or `X-Real-IP`) hop.
///
/// Besides a bare address, proxies write hops as `SocketAddr` (`203.0.113.9:51234`
/// from Azure Application Gateway, `[2001:db8::1]:443`) or as a bracketed v6 address
/// without a port. Anything else (an obfuscated or relayed client value) is rejected,
/// so it can never become a bucket key.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim();
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(ip);
    }
    match hop.strip_prefix('[') {
        // `[v6]` without a port: `SocketAddr` would reject it
        Some(bracketed) => match bracketed.split_once(']') {
            Some((address, "")) => address.parse::<IpAddr>().ok().filter(IpAddr::is_ipv6),
            _ => hop.parse::<SocketAddr>().ok().map(|addr| addr.ip()),
        },
        None => hop.parse::<SocketAddr>().ok().map(|addr| addr.ip()),
    }
}

/// First usable address of `name`, canonicalized; `None` when the header is missing
/// or holds something that is not an address.
fn header_ip(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    let hop = value.split(',').next().unwrap_or("");
    parse_hop(hop).map(|ip| ip.to_canonical().to_string())
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
                match parse_hop(hop) {
                    Some(ip) => {
                        let ip = ip.to_canonical();
                        if !is_trusted(&ip) {
                            return Some(ip.to_string());
                        }
                        leftmost_trusted = Some(ip.to_string());
                    }
                    // Not an address (e.g. a client value relayed as is): nothing left
                    // of it can be trusted, and it must not become a bucket key
                    None => break,
                }
            }
            leftmost_trusted.or_else(|| peer.map(|ip| ip.to_string()))
        }
    }
}

/// The IP-based key used when no other key is available.
///
/// The middleware passes its own strategy, so it never depends on the request
/// extensions; [`client_ip_key`] reads it from them.
fn fallback_key(
    strategy: &ClientIpStrategy,
    extensions: &Extensions,
    headers: &HeaderMap,
    path: &str,
    method: &Method,
) -> BarnacleKey {
    match resolve_client_ip(extensions, headers, strategy) {
        Some(ip) => BarnacleKey::Ip(ip),
        // No client IP (e.g. local requests without ConnectInfo): one bucket per route + method
        None => BarnacleKey::Ip(format!("local:{}:{}", method.as_str(), path)),
    }
}

/// Strategy of the innermost Barnacle layer wrapping the request, the legacy one
/// outside of a Barnacle layer.
fn request_strategy(extensions: &Extensions) -> &ClientIpStrategy {
    static LEGACY: ClientIpStrategy = ClientIpStrategy::Legacy;
    extensions
        .get::<ClientIpStrategyExtension>()
        .map_or(&LEGACY, |extension| extension.0.as_ref())
}

/// Path the request is counted on: the original one, so that a route nested under a
/// prefix keeps the same bucket inside and outside the middleware.
fn request_path(parts: &Parts) -> &str {
    parts
        .extensions
        .get::<OriginalUri>()
        .map_or_else(|| parts.uri.path(), |original| original.path())
}

/// Client IP of the request, resolved with the [`ClientIpStrategy`] of the Barnacle
/// layer that wraps it (the legacy strategy outside of a Barnacle layer).
///
/// Useful in [`KeyExtractable`] implementations that fall back to the client IP.
pub fn client_ip(parts: &Parts) -> Option<String> {
    resolve_client_ip(
        &parts.extensions,
        &parts.headers,
        request_strategy(&parts.extensions),
    )
}

/// The IP-based key Barnacle falls back to when no other key is available.
pub fn client_ip_key(parts: &Parts) -> BarnacleKey {
    fallback_key(
        request_strategy(&parts.extensions),
        &parts.extensions,
        &parts.headers,
        request_path(parts),
        &parts.method,
    )
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

// Provide a KeyExtractable impl for ()
impl KeyExtractable for () {
    fn extract_key(&self, request_parts: &Parts) -> BarnacleKey {
        client_ip_key(request_parts)
    }
}

impl<State> Settings<State> {
    /// Scope a limit is counted in
    fn scope_of<'a>(&'a self, limit: &'a Limit) -> &'a RateLimitScope {
        limit.scope.as_ref().unwrap_or(&self.scope)
    }

    /// Two limits whose scopes can count the same bucket, described for an error.
    ///
    /// Besides equal scopes, `Path` and `Route` collide: on a route without parameters
    /// the route template is the concrete path, so both count one counter.
    fn colliding_scopes(&self, limits: &[Limit]) -> Option<String> {
        let collide = |a: &RateLimitScope, b: &RateLimitScope| match (a, b) {
            (RateLimitScope::Named(a), RateLimitScope::Named(b)) => a == b,
            (RateLimitScope::Named(_), _) | (_, RateLimitScope::Named(_)) => false,
            // Path and Route, in any combination
            _ => true,
        };
        limits.iter().enumerate().find_map(|(index, limit)| {
            let scope = self.scope_of(limit);
            limits[..index]
                .iter()
                .map(|other| self.scope_of(other))
                .find(|other| collide(other, scope))
                .map(|other| format!("{other:?} and {scope:?}"))
        })
    }

    /// Response for a failed store operation, or `None` when the request goes through
    /// anyway: with [`StoreFailurePolicy::FailOpen`], or in [`Mode::Shadow`].
    fn store_failure(&self, error: BarnacleError) -> Option<Response<Body>> {
        if self.mode == Mode::Shadow || self.store_failure_policy == StoreFailurePolicy::FailOpen {
            warn!(
                "Rate limit store unavailable, letting the request through: {}",
                error
            );
            None
        } else {
            Some((self.error_response)(error))
        }
    }

    /// Calls the decision hook, if any; `limits` is only built when there is one
    fn report(
        &self,
        key: &BarnacleKey,
        outcome: DecisionOutcome,
        limits: impl FnOnce() -> Vec<LimitOutcome>,
    ) {
        if let Some(hook) = &self.decision_hook {
            hook(&RateLimitDecision {
                key_kind: key.kind(),
                key_hash: key.hashed(),
                mode: self.mode,
                outcome,
                limits: limits(),
            });
        }
    }

    fn decision_outcome(&self, exceeded: bool) -> DecisionOutcome {
        match (exceeded, self.mode) {
            (false, _) => DecisionOutcome::Allowed,
            (true, Mode::Enforce) => DecisionOutcome::Rejected,
            (true, Mode::Shadow) => DecisionOutcome::WouldReject,
        }
    }

    /// Reports the failed validation counter using the same decision format as request limits.
    fn report_failed_validation(
        &self,
        context: &BarnacleContext,
        limit: &BarnacleConfig,
        result: &Result<BarnacleResult, BarnacleError>,
    ) {
        let (exceeded, remaining, reset_after) = match result {
            Ok(counted) => (
                false,
                counted.remaining,
                counted.retry_after.unwrap_or(limit.window),
            ),
            Err(BarnacleError::RateLimitExceeded { retry_after, .. }) => {
                (true, 0, Duration::from_secs(*retry_after))
            }
            Err(_) => {
                self.report(&context.key, DecisionOutcome::StoreFailure, Vec::new);
                return;
            }
        };
        self.report(&context.key, self.decision_outcome(exceeded), || {
            vec![LimitOutcome {
                scope: RateLimitScope::Named(FAILED_VALIDATION_SCOPE.into()),
                bucket: context.path.clone(),
                max_requests: limit.max_requests,
                window: limit.window,
                remaining,
                reset_after,
                exceeded,
            }]
        });
    }

    fn context(
        &self,
        scope: &RateLimitScope,
        key: BarnacleKey,
        parts: &Parts,
        current_path: &str,
    ) -> BarnacleContext {
        match scope {
            RateLimitScope::Path => BarnacleContext {
                key,
                path: current_path.to_owned(),
                method: parts.method.as_str().to_string(),
            },
            RateLimitScope::Route => BarnacleContext {
                key,
                path: parts
                    .extensions
                    .get::<MatchedPath>()
                    .map_or(current_path, MatchedPath::as_str)
                    .to_owned(),
                method: parts.method.as_str().to_string(),
            },
            RateLimitScope::Named(name) => BarnacleContext::named(key, name.clone()),
        }
    }

    /// The bucket of every limit, in order
    fn buckets(
        &self,
        key: &BarnacleKey,
        limits: &[Limit],
        parts: &Parts,
        current_path: &str,
    ) -> Result<Vec<Bucket>, BarnacleError> {
        // Counting one counter twice in the same script would double count it. The layer's
        // limits were checked by `build`, an identity's are checked here, on the scopes
        // rather than the contexts so that the answer doesn't depend on the route.
        if let Some(collision) = self.colliding_scopes(limits) {
            return Err(BarnacleError::configuration_error(format!(
                "Two limits can count the same bucket ({collision}): give each limit its own \
                 scope; Path and Route share a bucket on routes without parameters"
            )));
        }
        Ok(limits
            .iter()
            .map(|limit| Bucket {
                context: self.context(self.scope_of(limit), key.clone(), parts, current_path),
                max_requests: limit.max_requests,
                window: limit.window,
            })
            .collect())
    }
}

impl<State> Settings<State>
where
    State: Clone + Send + Sync + 'static,
{
    /// Validates the request's API key, returning it when it is valid and not empty.
    async fn validate_api_key<S: BarnacleStore>(
        &self,
        store: &S,
        validator: &Validator<State>,
        state: &State,
        parts: &Parts,
    ) -> Result<Option<String>, Response<Body>> {
        let api_key = parts
            .headers
            .get(self.api_key_config.header_name.as_str())
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_owned();

        // Failed validations are counted per client IP, and only for requests that
        // carry a key: those are the ones that cost a lookup in the validator.
        // Without a client IP the only bucket left would be shared by unrelated
        // clients, so the limit is skipped instead of locking all of them out.
        let failed_validation = match &self.failed_validation_limit {
            Some(limit) if !api_key.is_empty() => {
                match resolve_client_ip(&parts.extensions, &parts.headers, &self.client_ip_strategy)
                {
                    Some(ip) => Some((
                        BarnacleContext::named(BarnacleKey::Ip(ip), FAILED_VALIDATION_SCOPE),
                        limit,
                    )),
                    None => {
                        debug!(
                            "No client IP resolved: skipping the failed API key validation limit"
                        );
                        None
                    }
                }
            }
            _ => None,
        };

        // Reading the counter before the validator runs is what keeps a brute-force
        // client from costing a key lookup per attempt: it can't be merged with the
        // increment below, which only happens after the validator answered.
        let mut failed_validation_reported = false;
        if let Some((context, limit)) = &failed_validation {
            let result = call_store(self.store_timeout, store.peek(context, limit)).await;
            if result.is_err() {
                self.report_failed_validation(context, limit, &result);
                failed_validation_reported = true;
            }
            match result {
                Ok(_) => {}
                Err(error @ BarnacleError::RateLimitExceeded { .. }) => {
                    if self.mode == Mode::Enforce {
                        debug!(
                            "Rejecting key {:?}: too many failed API key validations",
                            context.key
                        );
                        return Err(rate_limited_response(self.error_response, error));
                    }
                    info!(
                        "Shadow mode: too many failed API key validations for {}, letting the request through",
                        context.key.hashed()
                    );
                }
                Err(error) => {
                    if let Some(response) = self.store_failure(error) {
                        return Err(response);
                    }
                }
            }
        }

        let validation = validator(
            api_key.clone(),
            self.api_key_config.clone(),
            Arc::new(parts.clone()),
            state.clone(),
        )
        .await;
        if let Err(response) = validation {
            debug!(
                "API key validation failed with status {}",
                response.status()
            );
            // Only an authentication failure says anything about the client: a
            // validator that answers 500 or 503 because its own backend blipped
            // must not lock legitimate clients out for the whole window.
            let authentication_failed = matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            );
            if let Some((context, limit)) = failed_validation.filter(|_| authentication_failed) {
                let result = call_store(self.store_timeout, store.increment(&context, limit)).await;
                // Shadow mode or fail-open can reach this point after a failed precheck.
                // Keep its decision instead of reporting the same limit twice.
                if !failed_validation_reported {
                    self.report_failed_validation(&context, limit, &result);
                }
                match result {
                    Ok(_) => {}
                    // Another request reached the limit in the meantime
                    Err(error @ BarnacleError::RateLimitExceeded { .. }) => {
                        if self.mode == Mode::Enforce {
                            return Err(rate_limited_response(self.error_response, error));
                        }
                    }
                    Err(error) => warn!("Failed to count failed API key validation: {}", error),
                }
            }
            return Err(response);
        }
        Ok(Some(api_key).filter(|api_key| !api_key.is_empty()))
    }

    /// Barnacle's own key for a request no identifier resolved: the validated API key,
    /// the payload key or the client IP. Buffers the body only for a payload key.
    async fn request_key<B>(
        &self,
        parts: &Parts,
        body: B,
        api_key: Option<String>,
        current_path: &str,
    ) -> Result<(BarnacleKey, Body), Response<Body>>
    where
        B: axum::body::HttpBody<Data = Bytes> + Send + 'static,
        B::Error: Into<axum::BoxError>,
    {
        let ip_key = || {
            fallback_key(
                &self.client_ip_strategy,
                &parts.extensions,
                &parts.headers,
                current_path,
                &parts.method,
            )
        };
        // Only a validated key identifies the client: without a validator anyone could
        // send a different key per request to get a fresh bucket every time
        if let Some(api_key) = api_key {
            return Ok((BarnacleKey::ApiKey(api_key), Body::new(body)));
        }
        let Some(payload_key) = self.payload_key else {
            return Ok((ip_key(), Body::new(body)));
        };

        if let Some(limit) = self.max_body_size {
            let content_length = parts
                .headers
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok());
            if content_length.is_some_and(|length| length > limit) {
                return Err((self.error_response)(BarnacleError::PayloadTooLarge {
                    limit,
                }));
            }
        }
        let bytes = collect_body(body, self.max_body_size)
            .await
            .map_err(self.error_response)?;
        let key = payload_key(&bytes, parts).unwrap_or_else(|| {
            debug!("Payload key not found, using the client IP");
            ip_key()
        });
        Ok((key, Body::from(bytes)))
    }

    /// Counts the request in every bucket. Returns the state of each bucket, `None` when
    /// the store failed and the request goes through uncounted, or the response when
    /// the request is rejected.
    async fn count<S: BarnacleStore>(
        &self,
        store: &S,
        key: &BarnacleKey,
        limits: &[Limit],
        buckets: &[Bucket],
    ) -> Result<Option<Vec<BucketState>>, Response<Body>> {
        let states = call_store(self.store_timeout, store.increment_all(buckets))
            .await
            .and_then(|states| {
                if states.len() == buckets.len() {
                    Ok(states)
                } else {
                    Err(BarnacleError::store_error(
                        "The store returned a state per bucket count different from the buckets",
                    ))
                }
            });
        let states = match states {
            Ok(states) => states,
            Err(error) => {
                debug!("Rate limit not checked for key {:?}: {}", key, error);
                self.report(key, DecisionOutcome::StoreFailure, Vec::new);
                return match self.store_failure(error) {
                    Some(response) => Err(response),
                    None => Ok(None),
                };
            }
        };

        let outcome = self.decision_outcome(states.iter().any(|state| state.exceeded));
        self.report(key, outcome, || {
            limits
                .iter()
                .zip(buckets)
                .zip(&states)
                .map(|((limit, bucket), state)| LimitOutcome {
                    scope: self.scope_of(limit).clone(),
                    bucket: bucket.context.path.clone(),
                    max_requests: bucket.max_requests,
                    window: bucket.window,
                    remaining: state.remaining,
                    reset_after: state.reset_after,
                    exceeded: state.exceeded,
                })
                .collect()
        });

        match (outcome, strictest(&states)) {
            (DecisionOutcome::Rejected, Some(index)) => {
                debug!("Rate limit exceeded for key {:?}", key);
                let error = BarnacleError::rate_limit_exceeded(
                    0,
                    states[index].reset_after.as_secs(),
                    buckets[index].max_requests,
                );
                Err(rate_limited_response(self.error_response, error))
            }
            (DecisionOutcome::WouldReject, _) => {
                info!(
                    "Shadow mode: rate limit exceeded for {} key {}, letting the request through",
                    key.kind(),
                    key.hashed()
                );
                Ok(Some(states))
            }
            _ => Ok(Some(states)),
        }
    }

    /// Resets the counted buckets (and the extra contexts of
    /// [`ResetOnSuccess::Multiple`]) after a successful response
    async fn reset_counters<S: BarnacleStore>(
        &self,
        store: &S,
        key: &BarnacleKey,
        buckets: &[Bucket],
        status_code: u16,
    ) {
        if !self.reset_on_success.is_success_status(status_code) {
            return;
        }
        let extra_contexts = match &self.reset_on_success {
            ResetOnSuccess::Multiple(_, contexts) => contexts.as_slice(),
            _ => &[],
        };
        let contexts = buckets.iter().map(|bucket| bucket.context.clone()).chain(
            extra_contexts.iter().cloned().map(|mut context| {
                if context.key == BarnacleKey::Custom(NO_KEY.to_string()) {
                    context.key = key.clone();
                }
                context
            }),
        );
        for context in contexts {
            match call_store(self.store_timeout, store.reset(&context)).await {
                Ok(_) => debug!(
                    "Rate limit reset for key {:?} after successful request (status: {}) path: {}",
                    context.key, status_code, context.path
                ),
                Err(e) => warn!(
                    "Failed to reset rate limit for key {:?}: {} path: {}",
                    context.key, e, context.path
                ),
            }
        }
    }

    async fn handle<S, Inner, B>(
        &self,
        store: S,
        mut inner: Inner,
        req: Request<B>,
    ) -> Result<Response<Body>, Inner::Error>
    where
        S: BarnacleStore + 'static,
        Inner: Service<Request<Body>, Response = Response<Body>>,
        B: axum::body::HttpBody<Data = Bytes> + Send + 'static,
        B::Error: Into<axum::BoxError>,
    {
        let (mut parts, body) = req.into_parts();
        let current_path = request_path(&parts).to_owned();
        parts
            .extensions
            .insert(ClientIpStrategyExtension(self.client_ip_strategy.clone()));

        let mut api_key = None;
        let mut identity = None;
        if let Some(hooks) = &self.hooks {
            if let Some(validator) = &hooks.api_key_validator {
                match self
                    .validate_api_key(&store, validator, &hooks.state, &parts)
                    .await
                {
                    Ok(validated) => api_key = validated,
                    Err(response) => return Ok(response),
                }
            }
            if let Some(modifier) = &hooks.request_modifier {
                parts = match modifier(parts, hooks.state.clone()).await {
                    Ok(modified) => modified,
                    Err(response) => {
                        debug!("Request modifier returned an error");
                        return Ok(response);
                    }
                };
                // A modifier that rebuilds the parts may have dropped the extension the
                // public `client_ip` helpers read, in the key extractor or in the handler
                parts
                    .extensions
                    .insert(ClientIpStrategyExtension(self.client_ip_strategy.clone()));
            }
            if let Some(identifier) = &hooks.identifier {
                identity = identifier.identify(&parts, &hooks.state).await;
            }
        }

        let (key, limits, body) = match identity {
            Some(Identity { key, limits }) => (
                key,
                limits.map_or(Cow::Borrowed(self.limits.as_slice()), Cow::Owned),
                Body::new(body),
            ),
            None => match self.request_key(&parts, body, api_key, &current_path).await {
                Ok((key, body)) => (key, Cow::Borrowed(self.limits.as_slice()), body),
                Err(response) => return Ok(response),
            },
        };

        let buckets = match self.buckets(&key, &limits, &parts, &current_path) {
            Ok(buckets) => buckets,
            // Shadow mode never rejects: the request goes through uncounted
            Err(error) if self.mode == Mode::Shadow => {
                warn!("{}, letting the request through uncounted", error);
                Vec::new()
            }
            Err(error) => {
                warn!("{}", error);
                return Ok((self.error_response)(error));
            }
        };
        // An identity with no limits is not rate limited
        let states = if buckets.is_empty() {
            None
        } else {
            match self.count(&store, &key, &limits, &buckets).await {
                Ok(states) => states,
                Err(response) => return Ok(response),
            }
        };

        let mut response = inner.call(Request::from_parts(parts, body)).await?;

        // Without states nothing was counted: no counter to report or reset
        let Some(states) = states else {
            return Ok(response);
        };
        if let Some(index) = strictest(&states) {
            insert_rate_limit_headers(
                response.headers_mut(),
                buckets[index].max_requests,
                &states[index],
            );
        }
        // A request over a limit only gets here in shadow mode: enforcing would have
        // rejected it before the handler, so it must not reset the counters either
        if !states.iter().any(|state| state.exceeded) {
            self.reset_counters(&store, &key, &buckets, response.status().as_u16())
                .await;
        }
        Ok(response)
    }
}

/// The service built by [`BarnacleLayer`]
pub struct BarnacleMiddleware<Inner, S = RedisBarnacleStore, State = ()> {
    inner: Inner,
    store: S,
    settings: Arc<Settings<State>>,
}

impl<Inner: Clone, S: Clone, State> Clone for BarnacleMiddleware<Inner, S, State> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            store: self.store.clone(),
            settings: self.settings.clone(),
        }
    }
}

impl<Inner, B, S, State> Service<Request<B>> for BarnacleMiddleware<Inner, S, State>
where
    Inner: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
    B: axum::body::HttpBody<Data = Bytes> + Send + 'static,
    B::Error: Into<axum::BoxError>,
    S: BarnacleStore + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = Inner::Response;
    type Error = Inner::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let inner = self.inner.clone();
        let store = self.store.clone();
        let settings = self.settings.clone();
        Box::pin(async move { settings.handle(store, inner, req).await })
    }
}
