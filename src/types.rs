use std::collections::HashMap;
use std::time::Duration;

/// Special constant to indicate a placeholder key that should be replaced
pub const NO_KEY: &str = "__BARNACLE_NO_KEY_PLACEHOLDER__";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ResetOnSuccess {
    Not,
    Yes(Option<Vec<u16>>),
    Multiple(Option<Vec<u16>>, Vec<BarnacleContext>),
}

/// Rate limiter configuration
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BarnacleConfig {
    pub max_requests: u32,
    pub window: Duration,
    pub reset_on_success: ResetOnSuccess,
}

impl Default for BarnacleConfig {
    fn default() -> Self {
        Self {
            max_requests: 20,
            window: Duration::from_secs(60), // 1 minute
            reset_on_success: ResetOnSuccess::Not,
        }
    }
}

impl BarnacleConfig {
    /// Check if a status code should be considered successful for rate limit reset
    pub fn is_success_status(&self, status_code: u16) -> bool {
        match &self.reset_on_success {
            ResetOnSuccess::Not => false,
            ResetOnSuccess::Yes(success_codes) | ResetOnSuccess::Multiple(success_codes, _) => {
                if let Some(codes) = success_codes {
                    codes.contains(&status_code)
                } else {
                    // Default to 2xx status codes
                    (200..300).contains(&status_code)
                }
            }
        }
    }
}

/// Identification key for rate limiting (e.g., email, api-key, IP)
///
/// The `Debug` output of [`BarnacleKey::ApiKey`] is redacted so that API keys
/// never end up in logs in clear text.
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BarnacleKey {
    Email(String),
    ApiKey(String),
    Ip(String),
    Custom(String),
}

impl std::fmt::Debug for BarnacleKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BarnacleKey::Email(email) => f.debug_tuple("Email").field(email).finish(),
            BarnacleKey::ApiKey(api_key) => f
                .debug_tuple("ApiKey")
                .field(&redact_api_key(api_key))
                .finish(),
            BarnacleKey::Ip(ip) => f.debug_tuple("Ip").field(ip).finish(),
            BarnacleKey::Custom(custom) => f.debug_tuple("Custom").field(custom).finish(),
        }
    }
}

/// SHA-256 hex digest of an API key.
///
/// Used to build store keys, so that API keys are never persisted in clear text.
pub fn hash_api_key(api_key: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(api_key.as_bytes()))
}

/// Log-safe representation of an API key: a short prefix of its hash.
pub fn redact_api_key(api_key: &str) -> String {
    format!("sha256:{}", &hash_api_key(api_key)[..12])
}

/// Which part of the request identifies the rate limit bucket, besides the key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RateLimitScope {
    /// One bucket per concrete request path and method (`/users/42` and `/users/43`
    /// are counted separately). This is the pre-0.4 behaviour.
    #[default]
    Path,
    /// One bucket per route template and method (`/users/{id}`), read from axum's
    /// `MatchedPath`. Falls back to the concrete path when no route matched.
    Route,
    /// One bucket per key shared by every route and method the layer wraps.
    /// Layers configured with the same name share the same bucket.
    Named(String),
}

/// What to do when the store (e.g. Redis) fails or times out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StoreFailurePolicy {
    /// Reject the request with the store error (503). This is the pre-0.4 behaviour.
    #[default]
    FailClosed,
    /// Let the request through without rate limiting and log a warning.
    FailOpen,
}

/// How the client IP is resolved for IP-based keys.
#[derive(Clone, Debug, Default)]
pub enum ClientIpStrategy {
    /// Socket peer address (`ConnectInfo`), then the first `X-Forwarded-For` entry,
    /// then `X-Real-IP`. This is the pre-0.4 behaviour: behind a load balancer every
    /// client shares the balancer's IP, and without `ConnectInfo` the headers can be
    /// spoofed by the client.
    #[default]
    Legacy,
    /// Only the socket peer address (`ConnectInfo`). Use when not behind a proxy.
    PeerOnly,
    /// The application runs behind the given proxies (e.g. the load balancer subnets).
    ///
    /// If the peer address is not a trusted proxy it is the client. Otherwise
    /// `X-Forwarded-For` is walked right to left and the first address that is not a
    /// trusted proxy is the client, so entries forged by the client are ignored.
    TrustedProxies(Vec<ipnet::IpNet>),
}

impl ClientIpStrategy {
    /// Build a [`ClientIpStrategy::TrustedProxies`] from CIDR strings
    /// (e.g. `"10.0.0.0/8"`); bare addresses are treated as single hosts.
    pub fn trusted_proxies<I, S>(proxies: I) -> Result<Self, ipnet::AddrParseError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        proxies
            .into_iter()
            .map(|proxy| {
                let proxy = proxy.as_ref().trim();
                proxy
                    .parse::<ipnet::IpNet>()
                    .or_else(|err| proxy.parse::<std::net::IpAddr>().map(ipnet::IpNet::from).map_err(|_| err))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(ClientIpStrategy::TrustedProxies)
    }
}

/// Rate limiting context that includes route information
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BarnacleContext {
    pub key: BarnacleKey,
    pub path: String,
    pub method: String,
}

impl BarnacleContext {
    /// This will be used to reset the rate limit for a specific path and method
    ///
    /// The key will be replaced with the current request's key
    pub fn with_path_and_method(path: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            key: BarnacleKey::Custom(NO_KEY.to_string()),
            path: path.into(),
            method: method.into(),
        }
    }
}

/// Result of an increment attempt
#[derive(Clone, Debug)]
pub struct BarnacleResult {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after: Option<Duration>,
}

/// API key validation result
#[derive(Clone, Debug)]
pub struct ApiKeyValidationResult {
    pub valid: bool,
    pub key_id: Option<String>,
    pub rate_limit_config: Option<BarnacleConfig>,
}

impl ApiKeyValidationResult {
    pub fn valid_with_config(key_id: String, config: BarnacleConfig) -> Self {
        Self {
            valid: true,
            key_id: Some(key_id),
            rate_limit_config: Some(config),
        }
    }

    pub fn valid_with_default_config(key_id: String) -> Self {
        Self {
            valid: true,
            key_id: Some(key_id),
            rate_limit_config: Some(BarnacleConfig::default()),
        }
    }

    pub fn invalid() -> Self {
        Self {
            valid: false,
            key_id: None,
            rate_limit_config: None,
        }
    }
}

/// Configuration for API key middleware
#[derive(Clone, Debug)]
pub struct ApiKeyConfig {
    pub header_name: String,
    /// TTL for caching API keys validated by custom validator (in seconds)
    pub cache_ttl_seconds: u64,
}

impl ApiKeyConfig {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn custom(
        header_name: String,
        cache_ttl_seconds: u64,
    ) -> Self {
        Self {
            header_name,
            cache_ttl_seconds, // 1 hour default
        }
    }
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            header_name: "x-api-key".to_string(),
            cache_ttl_seconds: 60 * 60, // 1 hour default
        }
    }
}

/// Per-key rate limiting configuration for static configurations
#[derive(Clone, Debug)]
pub struct StaticApiKeyConfig {
    pub key_configs: HashMap<String, BarnacleConfig>,
    pub default_config: BarnacleConfig,
}

impl StaticApiKeyConfig {
    pub fn new(default_config: BarnacleConfig) -> Self {
        Self {
            key_configs: HashMap::new(),
            default_config,
        }
    }

    pub fn with_key_config(mut self, api_key: String, config: BarnacleConfig) -> Self {
        self.key_configs.insert(api_key, config);
        self
    }

    pub fn get_config_for_key(&self, api_key: &str) -> &BarnacleConfig {
        self.key_configs
            .get(api_key)
            .unwrap_or(&self.default_config)
    }
}
