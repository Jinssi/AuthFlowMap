// In-memory limits for run starts. No dependencies; state is per server process.

/** Sliding-window limiter: at most `max` events in any `windowMs`. */
export class RateLimiter {
  constructor({ max = 30, windowMs = 60 * 1000, now = () => Date.now() } = {}) {
    this.max = max;
    this.windowMs = windowMs;
    this.now = now;
    this.hits = [];
  }

  _prune() {
    const cutoff = this.now() - this.windowMs;
    while (this.hits.length > 0 && this.hits[0] <= cutoff) this.hits.shift();
  }

  /** Seconds until the next slot frees up, or 0 when a slot is free now. */
  retryAfter() {
    this._prune();
    if (this.hits.length < this.max) return 0;
    return Math.max(1, Math.ceil((this.hits[0] + this.windowMs - this.now()) / 1000));
  }

  /** Take a slot. Returns 0 on success, otherwise the Retry-After seconds. */
  take() {
    const wait = this.retryAfter();
    if (wait === 0) this.hits.push(this.now());
    return wait;
  }
}

export const DEFAULT_LIMITS = Object.freeze({
  runsPerMinute: 30,
  maxConcurrentFlows: 4,
  concurrentRetryAfterSec: 5,
});
