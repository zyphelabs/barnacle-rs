---
default: major
---

Harden rate limiting against key spoofing, stuck counters, and Redis outages.

Hash API keys in Redis keys and move 0.3 entries on first lookup. Count requests with a
single atomic Lua script and repair counters left without expiry. Apply pool timeouts to
every Redis constructor, and let `StoreFailurePolicy` decide whether a store outage fails
open or closed. Parse `X-Forwarded-For` and `X-Real-IP` as addresses, and ignore the
`x-api-key` header unless a validator is configured.

**Breaking**: `ApiKeyStore::validate_key` returns `Result<ApiKeyValidationResult, BarnacleError>`,
and custom `BarnacleStore` implementations must implement `peek` to use
`with_failed_validation_limit`. See "Upgrading from 0.3" in the README.
