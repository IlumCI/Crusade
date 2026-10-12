//! Rate limiting: a token bucket for connections-per-second plus a semaphore
//! for concurrency.
//!
//! The two limits are orthogonal. The token bucket paces *how often* a new
//! connection may start; the semaphore caps *how many* connections are open at
//! once. Defaults are deliberately gentle ([`RateLimiterParams::default`]).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

/// Tuning for a [`RateLimiter`].
#[derive(Debug, Clone, Copy)]
pub struct RateLimiterParams {
    /// Sustained new connections per second.
    pub conn_per_sec: f64,
    /// Maximum burst (token-bucket capacity). Clamped to at least 1.
    pub burst: f64,
    /// Maximum simultaneously in-flight connections.
    pub concurrency: usize,
}

impl Default for RateLimiterParams {
    fn default() -> Self {
        // Conservative: 100 conn/s sustained, small burst, 50 concurrent.
        RateLimiterParams {
            conn_per_sec: 100.0,
            burst: 100.0,
            concurrency: 50,
        }
    }
}

/// A pure token bucket. Kept free of clocks so the refill/drain arithmetic can
/// be unit-tested deterministically.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    /// Tokens added per second.
    rate: f64,
}

impl TokenBucket {
    fn new(rate: f64, capacity: f64) -> Self {
        let rate = rate.max(f64::MIN_POSITIVE);
        let capacity = capacity.max(1.0);
        TokenBucket {
            tokens: capacity,
            capacity,
            rate,
        }
    }

    /// Credit tokens for `elapsed`, saturating at capacity.
    fn refill(&mut self, elapsed: Duration) {
        self.tokens = (self.tokens + elapsed.as_secs_f64() * self.rate).min(self.capacity);
    }

    /// Take a single token if one is available.
    fn try_take(&mut self) -> bool {
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// How long until a full token is available (zero if one already is).
    fn wait_for_token(&self) -> Duration {
        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64((1.0 - self.tokens) / self.rate)
        }
    }
}

/// Paces and bounds outgoing connection attempts.
///
/// Call [`RateLimiter::acquire`] immediately before each connection; it blocks
/// until a rate token is free, then returns a concurrency permit to hold for the
/// lifetime of the connection.
#[derive(Debug)]
pub struct RateLimiter {
    bucket: Mutex<(TokenBucket, Instant)>,
    sem: Arc<Semaphore>,
}

impl RateLimiter {
    /// Build a limiter from `params`.
    pub fn new(params: RateLimiterParams) -> Self {
        let bucket = TokenBucket::new(params.conn_per_sec, params.burst);
        RateLimiter {
            bucket: Mutex::new((bucket, Instant::now())),
            sem: Arc::new(Semaphore::new(params.concurrency.max(1))),
        }
    }

    /// Wait for a rate token, then acquire a concurrency permit. The permit is
    /// released when dropped, so hold it for the duration of the connection.
    pub async fn acquire(&self) -> OwnedSemaphorePermit {
        loop {
            let wait = {
                let mut guard = self.bucket.lock().await;
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(guard.1);
                guard.1 = now;
                guard.0.refill(elapsed);
                if guard.0.try_take() {
                    Duration::ZERO
                } else {
                    guard.0.wait_for_token()
                }
            };
            if wait.is_zero() {
                break;
            }
            tokio::time::sleep(wait).await;
        }
        // Concurrency permit; `max(1)` in the constructor means this never
        // panics on a closed semaphore (we never close it).
        self.sem
            .clone()
            .acquire_owned()
            .await
            .expect("scan semaphore is never closed")
    }

    /// Number of concurrency permits currently available (for diagnostics).
    pub fn available_permits(&self) -> usize {
        self.sem.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_starts_full_and_drains() {
        let mut b = TokenBucket::new(10.0, 4.0);
        assert!(b.try_take());
        assert!(b.try_take());
        assert!(b.try_take());
        assert!(b.try_take());
        // Capacity exhausted.
        assert!(!b.try_take());
    }

    #[test]
    fn bucket_refills_at_rate_and_caps_at_capacity() {
        let mut b = TokenBucket::new(10.0, 4.0);
        for _ in 0..4 {
            assert!(b.try_take());
        }
        // 10 tokens/s for 0.25s == 2.5 tokens.
        b.refill(Duration::from_millis(250));
        assert!(b.try_take());
        assert!(b.try_take());
        assert!(!b.try_take());

        // A long idle refills but never exceeds capacity.
        b.refill(Duration::from_secs(100));
        for _ in 0..4 {
            assert!(b.try_take());
        }
        assert!(!b.try_take());
    }

    #[test]
    fn wait_for_token_matches_deficit() {
        let mut b = TokenBucket::new(10.0, 4.0);
        for _ in 0..4 {
            assert!(b.try_take());
        }
        // Empty bucket at 10 tokens/s -> ~100ms for one token.
        let w = b.wait_for_token();
        assert!(
            w >= Duration::from_millis(99) && w <= Duration::from_millis(101),
            "{w:?}"
        );

        b.refill(Duration::from_millis(50)); // 0.5 token
        let w = b.wait_for_token();
        assert!(
            w >= Duration::from_millis(49) && w <= Duration::from_millis(51),
            "{w:?}"
        );
    }

    #[test]
    fn full_bucket_waits_zero() {
        let b = TokenBucket::new(10.0, 4.0);
        assert_eq!(b.wait_for_token(), Duration::ZERO);
    }

    #[test]
    fn degenerate_params_do_not_panic() {
        // Zero rate / zero capacity must be clamped, not produce NaN/inf.
        let b = TokenBucket::new(0.0, 0.0);
        assert!(b.capacity >= 1.0);
        assert!(b.rate > 0.0);
    }

    #[tokio::test]
    async fn acquire_hands_out_and_releases_permits() {
        let rl = RateLimiter::new(RateLimiterParams {
            conn_per_sec: 1000.0,
            burst: 1000.0,
            concurrency: 2,
        });
        let p1 = rl.acquire().await;
        let _p2 = rl.acquire().await;
        assert_eq!(rl.available_permits(), 0);
        drop(p1);
        assert_eq!(rl.available_permits(), 1);
    }
}
