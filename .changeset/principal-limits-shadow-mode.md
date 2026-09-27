---
default: major
---

Identify requests by principal, check several limits atomically, and add a shadow mode.

An identifier (`with_identifier`, `with_identity_resolver`) reads the principal the
application's authentication middleware stored in the request, and returns its key and
the limits of its tier. `with_limits` checks several `Limit`s per request (burst and
sustained, global and per route) in a single Lua script, all or nothing: a rejected
request consumes no counter. The rate limit headers report the strictest limit.
`with_mode(Mode::Shadow)` counts and reports without ever rejecting, and `on_decision`
reports every decision with a hash of the key, for metrics.

**Breaking**: `BarnacleLayer` takes `<Store, State>` instead of six type parameters: use
`with_payload_key::<T>()` and `with_error::<E>()` for the payload and error types. A
missing validator state is a build error, `ApiKeyConfig.cache_ttl_seconds` is removed,
and `RequestModifier` is no longer exported. See "Upgrading from 0.4" in the README.
