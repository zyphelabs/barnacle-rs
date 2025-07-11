use axum::body::Body;
use axum::extract::{OriginalUri, Request};
use axum::http::{HeaderMap, Response};
use axum::response::IntoResponse;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use crate::api_key_store::ApiKeyStore;
use crate::error::BarnacleError;
use crate::types::{ApiKeyMiddlewareConfig, BarnacleContext, BarnacleKey};
use crate::{BarnacleConfig, BarnacleStore, ResetOnSuccess};

/// Layer for API key validation and rate limiting
pub struct ApiKeyLayer<A, S, C = ()> {
    api_key_store: Arc<A>,
    rate_limit_store: Arc<S>,
    custom_validator: Option<Arc<C>>,
    config: ApiKeyMiddlewareConfig,
}

impl<A, S, C> Clone for ApiKeyLayer<A, S, C> {
    fn clone(&self) -> Self {
        Self {
            api_key_store: self.api_key_store.clone(),
            rate_limit_store: self.rate_limit_store.clone(),
            custom_validator: self.custom_validator.clone(),
            config: self.config.clone(),
        }
    }
}

impl<A, S> ApiKeyLayer<A, S, ()>
where
    A: ApiKeyStore + 'static,
    S: BarnacleStore + 'static,
{
    pub fn new(
        api_key_store: Arc<A>,
        rate_limit_store: Arc<S>,
        config: ApiKeyMiddlewareConfig,
    ) -> Self {
        Self {
            api_key_store,
            rate_limit_store,
            custom_validator: None,
            config,
        }
    }
}

impl<A, S, C> ApiKeyLayer<A, S, C>
where
    A: ApiKeyStore + 'static,
    S: BarnacleStore + 'static,
    C: ApiKeyStore + 'static,
{
    /// Add a custom validator that will be used as fallback when the main api_key_store fails
    /// The custom validator will be called if the main store returns invalid, and if it returns
    /// valid, the key will be automatically cached in the main store for future requests
    pub fn new_with_custom_validator<NewC>(
        api_key_store: Arc<A>,
        rate_limit_store: Arc<S>,
        config: ApiKeyMiddlewareConfig,
        custom_validator: Arc<NewC>,
    ) -> ApiKeyLayer<A, S, NewC>
    where
        NewC: ApiKeyStore + 'static,
    {
        ApiKeyLayer {
            api_key_store,
            rate_limit_store,
            custom_validator: Some(custom_validator),
            config,
        }
    }
}

// Implementation for the case without custom validator (C = ())
impl<Inner, A, S> Layer<Inner> for ApiKeyLayer<A, S, ()>
where
    A: ApiKeyStore + 'static,
    S: BarnacleStore + 'static,
{
    type Service = ApiKeyMiddleware<Inner, A, S, ()>;

    fn layer(&self, inner: Inner) -> Self::Service {
        ApiKeyMiddleware {
            inner,
            api_key_store: self.api_key_store.clone(),
            rate_limit_store: self.rate_limit_store.clone(),
            custom_validator: self.custom_validator.clone(),
            config: self.config.clone(),
        }
    }
}

// Implementation for the case with custom validator (C: ApiKeyStore)
impl<Inner, A, S, C> Layer<Inner> for ApiKeyLayer<A, S, C>
where
    A: ApiKeyStore + 'static,
    S: BarnacleStore + 'static,
    C: ApiKeyStore + 'static,
{
    type Service = ApiKeyMiddleware<Inner, A, S, C>;

    fn layer(&self, inner: Inner) -> Self::Service {
        ApiKeyMiddleware {
            inner,
            api_key_store: self.api_key_store.clone(),
            rate_limit_store: self.rate_limit_store.clone(),
            custom_validator: self.custom_validator.clone(),
            config: self.config.clone(),
        }
    }
}

/// The actual API key validation middleware
pub struct ApiKeyMiddleware<Inner, A, S, C = ()> {
    inner: Inner,
    api_key_store: Arc<A>,
    rate_limit_store: Arc<S>,
    custom_validator: Option<Arc<C>>,
    config: ApiKeyMiddlewareConfig,
}

impl<Inner, A, S, C> Clone for ApiKeyMiddleware<Inner, A, S, C>
where
    Inner: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            api_key_store: self.api_key_store.clone(),
            rate_limit_store: self.rate_limit_store.clone(),
            custom_validator: self.custom_validator.clone(),
            config: self.config.clone(),
        }
    }
}

// Implementation for the case without custom validator (C = ())
impl<Inner, B, A, S> Service<Request<B>> for ApiKeyMiddleware<Inner, A, S, ()>
where
    Inner: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
    B: Send + 'static,
    A: ApiKeyStore + 'static,
    S: BarnacleStore + 'static,
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
        let api_key_store = self.api_key_store.clone();
        let rate_limit_store = self.rate_limit_store.clone();
        let config = self.config.clone();

        Box::pin(async move {
            let current_path = {
                let original_path = req
                    .extensions()
                    .get::<OriginalUri>()
                    .map(|original_url| original_url.path().to_owned());

                original_path.unwrap_or_else(|| req.uri().path().to_owned())
            };

            let headers = req.headers();

            let api_key = extract_api_key(headers, &config.header_name);

            if api_key.is_none() && config.require_api_key {
                tracing::warn!("API key missing in header: {}", config.header_name);
                let error = BarnacleError::ApiKeyMissing;
                return Ok(error.into_response());
            }

            if let Some(api_key) = api_key {
                // Validate the API key
                let validation_result = api_key_store.validate_key(&api_key).await;

                if !validation_result.valid {
                    tracing::warn!("Invalid API key: {}", api_key);
                    let error = BarnacleError::invalid_api_key(&api_key);
                    return Ok(error.into_response());
                }

                // Get rate limit configuration for this key
                let rate_limit_config = validation_result
                    .rate_limit_config
                    .unwrap_or_else(|| config.barnacle_config.clone());

                // Create rate limiting key
                let rate_limit_key = BarnacleKey::ApiKey(api_key.clone());

                // Create context with route information
                let context = BarnacleContext {
                    key: rate_limit_key,
                    path: current_path,
                    method: req.method().as_str().to_string(),
                };

                // Check rate limit
                let rate_limit_result = match rate_limit_store
                    .increment(&context, &rate_limit_config)
                    .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::debug!("Rate limit store error: {}", e);
                        return Ok(e.into_response());
                    }
                };

                tracing::debug!(
                    "API key validation and rate limit check passed for: {}, path: {}, remaining: {}",
                    api_key,
                    context.path,
                    rate_limit_result.remaining
                );

                let mut response = inner.call(req).await?;

                let headers = response.headers_mut();
                if let Ok(remaining_header) = rate_limit_result.remaining.to_string().parse() {
                    headers.insert("X-RateLimit-Remaining", remaining_header);
                }
                if let Ok(limit_header) = rate_limit_config.max_requests.to_string().parse() {
                    headers.insert("X-RateLimit-Limit", limit_header);
                }
                if let Some(retry_after) = rate_limit_result.retry_after {
                    if let Ok(reset_header) = retry_after.as_secs().to_string().parse() {
                        headers.insert("X-RateLimit-Reset", reset_header);
                    }
                }

                let status_code = response.status().as_u16();
                tracing::trace!(
                    "Checking rate limit reset for key: {}, status_code: {}, reset_on_success: {:?}",
                    api_key,
                    status_code,
                    rate_limit_config.reset_on_success
                );

                handle_rate_limit_reset(
                    &rate_limit_store,
                    &rate_limit_config,
                    &context,
                    status_code,
                )
                .await;

                Ok(response)
            } else {
                // No API key required, continue without validation
                inner.call(req).await
            }
        })
    }
}

// Implementation for the case with custom validator (C: ApiKeyStore)
impl<Inner, B, A, S, C> Service<Request<B>> for ApiKeyMiddleware<Inner, A, S, C>
where
    Inner: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
    B: Send + 'static,
    A: ApiKeyStore + 'static,
    S: BarnacleStore + 'static,
    C: ApiKeyStore + 'static,
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
        let api_key_store = self.api_key_store.clone();
        let rate_limit_store = self.rate_limit_store.clone();
        let custom_validator = self.custom_validator.clone();
        let config = self.config.clone();

        Box::pin(async move {
            let current_path = {
                let original_path = req
                    .extensions()
                    .get::<OriginalUri>()
                    .map(|original_url| original_url.path().to_owned());

                original_path.unwrap_or_else(|| req.uri().path().to_owned())
            };
            let headers = req.headers();

            let api_key = extract_api_key(headers, &config.header_name);

            if api_key.is_none() && config.require_api_key {
                tracing::warn!("API key missing in header: {}", config.header_name);
                let error = BarnacleError::ApiKeyMissing;
                return Ok(error.into_response());
            }

            if let Some(api_key) = api_key {
                // 1. Try the main API key store first (usually Redis cache)
                let mut validation_result = api_key_store.validate_key(&api_key).await;

                // 2. If validation failed and we have a custom validator, try it
                if !validation_result.valid {
                    if let Some(custom_validator) = &custom_validator {
                        tracing::debug!(
                            "API key not found in main store, trying custom validator: {}",
                            api_key
                        );
                        let custom_result = custom_validator.validate_key(&api_key).await;
                        if custom_result.valid {
                            tracing::debug!(
                                "API key validated successfully by custom validator: {}",
                                api_key
                            );

                            // 3. Try to save to main store for future requests
                            // Use the specific rate limit config from the custom validator result
                            let cache_config = custom_result
                                .rate_limit_config
                                .as_ref()
                                .unwrap_or(&config.barnacle_config);

                            // Cache with configurable TTL for keys validated by custom validator
                            let cache_ttl_seconds = Some(config.cache_ttl_seconds);
                            if let Err(e) = api_key_store
                                .try_cache_key(&api_key, cache_config, cache_ttl_seconds)
                                .await
                            {
                                tracing::warn!("Failed to cache API key {}: {}", api_key, e);
                            }

                            validation_result = custom_result;
                        } else {
                            tracing::warn!("API key validation failed in both main store and custom validator: {}", api_key);
                        }
                    }
                }

                if !validation_result.valid {
                    tracing::warn!("Invalid API key: {}", api_key);
                    let error = BarnacleError::invalid_api_key(&api_key);
                    return Ok(error.into_response());
                }

                // Get rate limit configuration for this key
                let rate_limit_config = validation_result
                    .rate_limit_config
                    .unwrap_or_else(|| config.barnacle_config.clone());

                // Create rate limiting key
                let rate_limit_key = BarnacleKey::ApiKey(api_key.clone());

                // Create context with route information
                let context = BarnacleContext {
                    key: rate_limit_key,
                    path: current_path,
                    method: req.method().as_str().to_string(),
                };

                // Check rate limit
                let rate_limit_result = match rate_limit_store
                    .increment(&context, &rate_limit_config)
                    .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::debug!("Rate limit store error: {}", e);
                        return Ok(e.into_response());
                    }
                };

                tracing::debug!(
                    "API key validation and rate limit check passed for: {}, path: {}, remaining: {}",
                    api_key,
                    context.path,
                    rate_limit_result.remaining
                );

                let mut response = inner.call(req).await?;

                let headers = response.headers_mut();
                if let Ok(remaining_header) = rate_limit_result.remaining.to_string().parse() {
                    headers.insert("X-RateLimit-Remaining", remaining_header);
                }
                if let Ok(limit_header) = rate_limit_config.max_requests.to_string().parse() {
                    headers.insert("X-RateLimit-Limit", limit_header);
                }
                if let Some(retry_after) = rate_limit_result.retry_after {
                    if let Ok(reset_header) = retry_after.as_secs().to_string().parse() {
                        headers.insert("X-RateLimit-Reset", reset_header);
                    }
                }

                let status_code = response.status().as_u16();
                tracing::trace!(
                    "Checking rate limit reset for key: {}, status_code: {}, reset_on_success: {:?}",
                    api_key,
                    status_code,
                    rate_limit_config.reset_on_success
                );

                handle_rate_limit_reset(
                    &rate_limit_store,
                    &rate_limit_config,
                    &context,
                    status_code,
                )
                .await;

                Ok(response)
            } else {
                // No API key required, continue without validation
                inner.call(req).await
            }
        })
    }
}

fn extract_api_key(headers: &HeaderMap, header_name: &str) -> Option<String> {
    for (name, value) in headers.iter() {
        if name.as_str().eq_ignore_ascii_case(header_name) {
            return value.to_str().ok().map(|s| s.to_string());
        }
    }
    None
}

async fn handle_rate_limit_reset<S>(
    store: &Arc<S>,
    config: &BarnacleConfig,
    context: &BarnacleContext,
    status_code: u16,
) where
    S: BarnacleStore + 'static,
{
    if config.reset_on_success == ResetOnSuccess::Not {
        return;
    }

    if config.is_success_status(status_code) {
        if let Err(e) = store.reset(context).await {
            tracing::warn!(
                "Failed to reset rate limit for key {:?}: {}",
                context.key,
                e
            );
        } else {
            tracing::debug!(
                "Reset rate limit for key {:?} after successful response",
                context.key
            );
        }
    }
}

pub fn create_api_key_layer<A, S>(api_key_store: A, rate_limit_store: S) -> ApiKeyLayer<A, S>
where
    A: ApiKeyStore + 'static,
    S: BarnacleStore + 'static,
{
    ApiKeyLayer::new(
        Arc::new(api_key_store),
        Arc::new(rate_limit_store),
        ApiKeyMiddlewareConfig::default(),
    )
}

pub fn create_api_key_layer_with_config<A, S>(
    api_key_store: A,
    rate_limit_store: S,
    config: ApiKeyMiddlewareConfig,
) -> ApiKeyLayer<A, S>
where
    A: ApiKeyStore + 'static,
    S: BarnacleStore + 'static,
{
    ApiKeyLayer::new(Arc::new(api_key_store), Arc::new(rate_limit_store), config)
}

pub fn create_api_key_layer_with_custom_validator<A, S, C>(
    api_key_store: A,
    rate_limit_store: S,
    custom_validator: C,
    config: ApiKeyMiddlewareConfig,
) -> ApiKeyLayer<A, S, C>
where
    A: ApiKeyStore + 'static,
    S: BarnacleStore + 'static,
    C: ApiKeyStore + 'static,
{
    ApiKeyLayer {
        api_key_store: Arc::new(api_key_store),
        rate_limit_store: Arc::new(rate_limit_store),
        custom_validator: Some(Arc::new(custom_validator)),
        config,
    }
}
