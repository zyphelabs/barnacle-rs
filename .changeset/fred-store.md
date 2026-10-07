---
default: minor
---

Add `FredBarnacleStore`, a rate limit store on the fred Redis client

Behind the new `fred` feature, `FredBarnacleStore` counts on a `fred::clients::Pool` with the same
keys and Lua scripts as `RedisBarnacleStore`, so an application already on fred can share its pool
instead of opening a deadpool-redis one, and switching store keeps the counters.
`FredBarnacleStore::new(pool)` shares a connected pool; `from_url` / `from_url_with_options` open
one with `FredPoolOptions`. A script Redis no longer knows (restart, failover, `SCRIPT FLUSH`) is
run with `EVAL`, which caches it again.

Building with `default-features = false` no longer fails: `BarnacleLayer` defaults to the fred store
without the `redis` feature.
