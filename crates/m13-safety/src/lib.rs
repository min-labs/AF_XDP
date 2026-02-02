#![no_std]
#![forbid(unsafe_code)]

use m13_core::{M13Result};
use m13_hal::{SecurityModule, PlatformClock};
use m13_time::PhaseMonitor;

/// Safety Limits (ISO 26262 Derived)
/// 100Hz Control Loop = 10ms Period.
const WATCHDOG_TIMEOUT_US: u64 = 20_000; // 20ms (Missed 2 cycles)
const MAX_TEMP_CELSIUS: f32 = 85.0;      // Silicon damage risk
const MAX_BUFFER_DEPTH_US: u64 = 100_000;// >100ms Latency is unsafe for control

pub struct SafetyMonitor {
    last_tick_us: u64,
    phase_mon: PhaseMonitor,
    consecutive_violations: u8,
}

impl SafetyMonitor {
    pub fn new(clock: &dyn PlatformClock) -> Self {
        Self {
            last_tick_us: clock.now_us(),
            phase_mon: PhaseMonitor::new(),
            consecutive_violations: 0,
        }
    }

    /// Update Link Physics Stats (Called by RX Thread).
    pub fn record_rtt(&mut self, rtt_us: u64) {
        self.phase_mon.add_sample(rtt_us);
    }

    /// The "Heartbeat" function.
    /// Must be called at the end of every scheduler loop.
    ///
    /// # Arguments
    /// * `temp_c` - Current SoC temperature.
    /// * `hal` - Interface to trigger hardware STO if needed.
    /// * `clock` - Time source.
    ///
    /// # Returns
    /// * `Ok(bool)` - State of the Safety Pin (High/Low).
    ///    Caller (Runtime) must write this bool to the GPIO.
    pub fn tick(
        &mut self,
        temp_c: f32,
        hal: &mut dyn SecurityModule,
        clock: &dyn PlatformClock
    ) -> M13Result<bool> {
        let now = clock.now_us();
        let delta = now.saturating_sub(self.last_tick_us);

        // 1. WATCHDOG CHECK (Livelock/Hang)
        // If we haven't been kicked in >20ms, software is hanging.
        if delta > WATCHDOG_TIMEOUT_US {
            // "Software Hung" -> STO
            // Invariant V: Fail-Safe.
            hal.panic_and_sanitize();
        }

        // 2. THERMAL CHECK
        if temp_c > MAX_TEMP_CELSIUS {
             hal.panic_and_sanitize();
        }

        // 3. JITTER CHECK (Phase Stability)
        // We calculate the required buffer depth based on variance (4-Sigma).
        // If the network requires >100ms buffering, it is too unstable for the robot.
        let optimal_depth = self.phase_mon.calculate_depth();
        
        if optimal_depth > MAX_BUFFER_DEPTH_US {
            self.consecutive_violations += 1;
        } else {
            self.consecutive_violations = 0;
        }

        // 3 Strikes Rule for Jitter (Debounce)
        if self.consecutive_violations >= 3 {
             // "Link Unstable" -> STO
             hal.panic_and_sanitize();
        }

        // 4. GENERATE PULSE (100 Hz Square Wave)
        // Update tick only if we survived checks
        self.last_tick_us = now;
        
        // 100Hz = 10ms Period. High for 5ms, Low for 5ms.
        // (now / 5000) % 2 == 0 -> High
        let cycle_5ms = now / 5_000;
        let pin_state = (cycle_5ms % 2) == 0;
        
        Ok(pin_state)
    }
}