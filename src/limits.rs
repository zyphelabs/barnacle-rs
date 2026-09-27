use std::time::Duration;

use crate::types::{BarnacleConfig, BarnacleContext, BarnacleKey, RateLimitScope};

/// One rate limit applied to a request: at most `max_requests` every `window`, counted
/// in the bucket selected by `scope`.
///
/// A request can be subject to several limits (e.g. a burst and a sustained limit, or
/// a global limit per credential and a stricter one per route). They are checked
/// together, all or nothing: when one of them rejects the request, none of the
/// counters is incremented.
///
/// Every limit of a request must count a different bucket, i.e. have a different scope:
/// two limits on the same scope would share one counter. To combine a burst and a
/// sustained limit on the same routes, name them differently, e.g.
/// `Named("api:burst")` and `Named("api")`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    pub max_requests: u32,
    pub window: Duration,
    /// Bucket the limit is counted in; `None` uses the layer's scope
    /// (see `BarnacleLayerBuilder::with_scope`).
    pub scope: Option<RateLimitScope>,
}

impl Limit {
    /// Allow `max_requests` per `window`, in the layer's scope.
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            scope: None,
        }
    }

    /// Count this limit in `scope` instead of the layer's scope.
    pub fn with_scope(mut self, scope: RateLimitScope) -> Self {
        self.scope = Some(scope);
        self
    }
}

impl From<&BarnacleConfig> for Limit {
    fn from(config: &BarnacleConfig) -> Self {
        Self::new(config.max_requests, config.window)
    }
}

impl From<BarnacleConfig> for Limit {
    fn from(config: BarnacleConfig) -> Self {
        Self::from(&config)
    }
}

/// Who a request is counted for, as resolved by an identifier
/// (see `BarnacleLayerBuilder::with_identifier`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Key of the buckets the request is counted in
    pub key: BarnacleKey,
    /// Limits for this identity (e.g. those of its tier); `None` applies the layer's
    /// limits. An empty list counts nothing: the request is not rate limited.
    pub limits: Option<Vec<Limit>>,
}

impl Identity {
    /// Identity counted with the layer's limits.
    pub fn new(key: BarnacleKey) -> Self {
        Self { key, limits: None }
    }

    /// Apply `limits` to this identity instead of the layer's limits.
    pub fn with_limits(mut self, limits: impl IntoIterator<Item = Limit>) -> Self {
        self.limits = Some(limits.into_iter().collect());
        self
    }
}

/// Whether the layer enforces its limits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// Requests over a limit are rejected with 429.
    #[default]
    Enforce,
    /// Requests are counted, get the rate limit headers and are reported to the decision
    /// hook, but are never rejected: neither over a limit nor when the store fails.
    ///
    /// Counters behave exactly as in [`Mode::Enforce`] (a request that would be rejected
    /// is not counted), so the decisions reported are the ones enforcing would take.
    Shadow,
}

/// A counter checked by [`crate::BarnacleStore::increment_all`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bucket {
    pub context: BarnacleContext,
    pub max_requests: u32,
    pub window: Duration,
}

/// State of a [`Bucket`] after [`crate::BarnacleStore::increment_all`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BucketState {
    /// The bucket was already full: it is the reason the request is rejected.
    pub exceeded: bool,
    /// Requests left in the window, after this one when it was counted.
    pub remaining: u32,
    /// Time until the window resets.
    pub reset_after: Duration,
}

/// What happened to a rate limited request, reported to the hook set with
/// `BarnacleLayerBuilder::on_decision`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitDecision {
    /// Kind of key the request was counted for: `email`, `api_key`, `ip` or `custom`.
    pub key_kind: &'static str,
    /// Hash of the key (see [`BarnacleKey::hashed`]), safe for logs and metrics.
    pub key_hash: String,
    pub mode: Mode,
    pub outcome: DecisionOutcome,
    /// One entry per limit, in the order they were configured.
    /// Empty when the outcome is [`DecisionOutcome::StoreFailure`].
    pub limits: Vec<LimitOutcome>,
}

/// Outcome of a [`RateLimitDecision`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionOutcome {
    /// Every limit had room: the request was counted.
    Allowed,
    /// A limit was exceeded and the request was rejected with 429.
    Rejected,
    /// A limit was exceeded but the layer is in [`Mode::Shadow`]: the request went through.
    WouldReject,
    /// The store failed or timed out. Whether the request went through depends on the
    /// `StoreFailurePolicy` (and is always the case in [`Mode::Shadow`]).
    StoreFailure,
}

/// State of one limit in a [`RateLimitDecision`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitOutcome {
    /// Scope the limit is counted in, useful as a low-cardinality metric label
    pub scope: RateLimitScope,
    /// Bucket the limit was counted in: the path, route template or scope name
    pub bucket: String,
    pub max_requests: u32,
    pub window: Duration,
    pub remaining: u32,
    pub reset_after: Duration,
    /// This limit is the one (or one of those) rejecting the request
    pub exceeded: bool,
}

/// Index of the limit the rate limit headers report: the one that decides when the
/// client can send again.
///
/// Over the limit, that is the exceeded limit that resets last. Otherwise it is the one
/// with the fewest requests left, the one resetting last on a tie.
pub(crate) fn strictest(states: &[BucketState]) -> Option<usize> {
    let exceeded = states
        .iter()
        .enumerate()
        .filter(|(_, state)| state.exceeded)
        .max_by_key(|(_, state)| state.reset_after);
    if let Some((index, _)) = exceeded {
        return Some(index);
    }
    states
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| {
            a.remaining
                .cmp(&b.remaining)
                .then(b.reset_after.cmp(&a.reset_after))
        })
        .map(|(index, _)| index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(exceeded: bool, remaining: u32, reset_after: u64) -> BucketState {
        BucketState {
            exceeded,
            remaining,
            reset_after: Duration::from_secs(reset_after),
        }
    }

    #[test]
    fn strictest_is_the_exceeded_limit_resetting_last() {
        let states = [state(true, 0, 1), state(false, 3, 60), state(true, 0, 30)];
        assert_eq!(strictest(&states), Some(2));
    }

    #[test]
    fn strictest_is_the_limit_with_fewest_requests_left() {
        let states = [
            state(false, 10, 1),
            state(false, 2, 60),
            state(false, 5, 30),
        ];
        assert_eq!(strictest(&states), Some(1));
        // On a tie, the one the client has to wait longer for
        let states = [state(false, 2, 1), state(false, 2, 60)];
        assert_eq!(strictest(&states), Some(1));
        assert_eq!(strictest(&[]), None);
    }
}
