//! Idle-lock and clipboard timing that counts sleep (security review 2026-11-26 L-13).
//!
//! `Instant` (monotonic) does not advance while the Mac sleeps, so with "Lock on sleep"
//! off a Mac asleep for hours would wake still unlocked, with a copied secret still on
//! the pasteboard. Every timestamp here is taken twice, monotonic and wall clock, and
//! elapsed time is the larger of the two deltas. A wall clock that went backwards counts
//! as zero for that comparison, so moving the clock back can never lock (the monotonic
//! delta still runs). Moving it forward reads like sleep and can lock early, which is
//! the safe direction.

use std::time::{Duration, Instant, SystemTime};

/// Wall-clock jump beyond the monotonic delta between two ticks that counts as sleep.
/// Ticks are 1 s apart; scheduling jitter stays far below this.
const SLEEP_SLACK: Duration = Duration::from_secs(2);

/// One moment on both clocks.
#[derive(Debug, Clone, Copy)]
pub struct Stamp {
    mono: Instant,
    wall: SystemTime,
}

impl Stamp {
    /// Time from `self` to `now`: the larger of the monotonic and wall-clock deltas. A
    /// wall clock that went backwards contributes zero.
    pub fn elapsed(&self, now: Stamp) -> Duration {
        let mono = now.mono.saturating_duration_since(self.mono);
        let wall = now.wall.duration_since(self.wall).unwrap_or_default();
        mono.max(wall)
    }

    /// True when the wall clock moved at least [`SLEEP_SLACK`] more than the monotonic
    /// clock from `self` to `now`: the Mac slept (or the clock was set forward).
    pub fn slept_until(&self, now: Stamp) -> bool {
        let mono = now.mono.saturating_duration_since(self.mono);
        let wall = now.wall.duration_since(self.wall).unwrap_or_default();
        wall > mono + SLEEP_SLACK
    }
}

/// Time since the last user input, sleep included, accumulated step by step.
///
/// Each step adds [`Stamp::elapsed`] since the previous step, so a wall clock set back
/// cancels only the step it happened in: setting the clock back by X and then sleeping
/// up to X still counts the sleep (measured from one stamp, the two would cancel out).
#[derive(Debug, Clone, Copy)]
pub struct IdleClock {
    /// Idle time accumulated up to `mark`.
    total: Duration,
    /// The last step.
    mark: Stamp,
    /// When the last known input happened, on the monotonic clock: the clock the system
    /// idle time runs on, so an idle time that did not count a sleep never reads as new
    /// input.
    input_mono: Instant,
}

impl IdleClock {
    pub fn new(now: Stamp) -> Self {
        Self {
            total: Duration::ZERO,
            mark: now,
            input_mono: now.mono,
        }
    }

    /// Adds the time since the last step and returns the idle total.
    pub fn advance(&mut self, now: Stamp) -> Duration {
        self.total += self.mark.elapsed(now);
        self.mark = now;
        self.total
    }

    /// Input happened at `now`.
    pub fn reset(&mut self, now: Stamp) {
        *self = Self::new(now);
    }

    /// System-wide input happened `ago` before `now`. Taken in only if it is newer than
    /// the last known input; the idle total becomes `ago`. Call after [`Self::advance`].
    pub fn input(&mut self, now: Stamp, ago: Duration) {
        if let Some(at) = now.mono.checked_sub(ago)
            && at > self.input_mono
        {
            self.total = ago;
            self.mark = now;
            self.input_mono = at;
        }
    }

    /// Tests: the last input was `d` ago and nothing slept since.
    #[cfg(test)]
    pub fn idle_for(&mut self, now: Stamp, d: Duration) {
        self.total = d;
        self.mark = now;
        self.input_mono = now.mono.checked_sub(d).unwrap();
    }
}

/// Source of [`Stamp`]s. Real clocks in the app; tests shift the wall clock alone to
/// simulate sleep or a clock set backwards.
#[derive(Debug, Default)]
pub struct Clock {
    #[cfg(test)]
    wall_ahead: Duration,
    #[cfg(test)]
    wall_behind: Duration,
}

impl Clock {
    pub fn now(&self) -> Stamp {
        let wall = SystemTime::now();
        #[cfg(test)]
        let wall = (wall + self.wall_ahead)
            .checked_sub(self.wall_behind)
            .unwrap_or(wall);
        Stamp {
            mono: Instant::now(),
            wall,
        }
    }

    /// Tests: the Mac sleeps for `d` (the wall clock moves, the monotonic one does not).
    #[cfg(test)]
    pub fn sleep(&mut self, d: Duration) {
        self.wall_ahead += d;
    }

    /// Tests: the wall clock is set back by `d`.
    #[cfg(test)]
    pub fn set_back(&mut self, d: Duration) {
        self.wall_behind += d;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock set back by an hour, then a sleep of up to an hour: each step counts on
    /// its own, so the sleep is not cancelled by the earlier set-back.
    #[test]
    fn set_back_then_sleep_still_counts_the_sleep() {
        let mut clock = Clock::default();
        let mut idle = IdleClock::new(clock.now());
        clock.set_back(Duration::from_secs(3600));
        assert!(idle.advance(clock.now()) < Duration::from_secs(1));
        clock.sleep(Duration::from_secs(1800));
        assert!(idle.advance(clock.now()) >= Duration::from_secs(1800));
    }

    #[test]
    fn elapsed_is_the_larger_delta_and_ignores_a_clock_set_back() {
        let mut clock = Clock::default();
        let start = clock.now();
        clock.sleep(Duration::from_secs(3600));
        let woke = clock.now();
        assert!(start.elapsed(woke) >= Duration::from_secs(3600));
        assert!(start.slept_until(woke));

        let mut clock = Clock::default();
        let start = clock.now();
        clock.set_back(Duration::from_secs(3600));
        let later = clock.now();
        assert!(
            start.elapsed(later) < Duration::from_secs(1),
            "monotonic only"
        );
        assert!(!start.slept_until(later));

        // System input 5 s ago is newer than input 10 s ago; input 20 s ago is not.
        let mut idle = IdleClock::new(later);
        idle.idle_for(later, Duration::from_secs(10));
        idle.input(later, Duration::from_secs(20));
        assert_eq!(idle.advance(later), Duration::from_secs(10));
        idle.input(later, Duration::from_secs(5));
        assert_eq!(idle.advance(later), Duration::from_secs(5));
    }
}
