## 0.5.0 (2026-09-27)

### Breaking Changes

#### Identify requests by principal, check several limits atomically, and add a shadow mode.

An identifier (`with_identifier`, `with_identity_resolver`) reads the principal the
application's authentication middleware stored in the request, and returns its key and
the limits of its tier. `with_limits` checks several `Limit`s per request (burst and
sustained, global and per route) in a single Lua script, all or nothing: a rejected
request consumes no counter. The rate limit headers report the strictest limit.
`with_mode(Mode::Shadow)` counts and reports without ever rejecting, and `on_decision`
reports every decision with a hash of the key, for metrics, including the failed
validation limit's counts, rejections and store failures.

**Breaking**: `BarnacleLayer` takes `<Store, State>` instead of six type parameters: use
`with_payload_key::<T>()` and `with_error::<E>()` for the payload and error types. A
missing validator state is a build error, `ApiKeyConfig.cache_ttl_seconds` is removed,
and `RequestModifier` is no longer exported. See "Upgrading from 0.4" in the README.

## 0.4.0 (2026-09-22)

### Breaking Changes

#### Harden rate limiting against key spoofing, stuck counters, and Redis outages.

Hash API keys in Redis keys and move 0.3 entries on first lookup. Count requests with a
single atomic Lua script and repair counters left without expiry. Apply pool timeouts to
every Redis constructor, and let `StoreFailurePolicy` decide whether a store outage fails
open or closed. Parse `X-Forwarded-For` and `X-Real-IP` as addresses, and ignore the
`x-api-key` header unless a validator is configured.

**Breaking**: `ApiKeyStore::validate_key` returns `Result<ApiKeyValidationResult, BarnacleError>`,
and custom `BarnacleStore` implementations must implement `peek` to use
`with_failed_validation_limit`. See "Upgrading from 0.3" in the README.
