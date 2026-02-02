#![forbid(unsafe_code)]

/// Tracks the Maximum value over a time window.
/// Used for Bottleneck Bandwidth (BtlBw).
#[derive(Debug, Clone)]
pub struct WindowedMaxFilter {
    window_us: u64,
    /// Ring buffer storing (timestamp_us, value).
    samples: [Option<(u64, u64)>; 10], 
    idx: usize,
}

impl WindowedMaxFilter {
    pub fn new(window_us: u64) -> Self {
        Self {
            window_us,
            samples: [None; 10],
            idx: 0,
        }
    }

    pub fn update(&mut self, val: u64, now: u64) {
        // Overwrite oldest slot in ring buffer
        self.samples[self.idx] = Some((now, val));
        self.idx = (self.idx + 1) % self.samples.len();
    }

    pub fn get_best(&self, now: u64) -> u64 {
        let mut max_val = 0;
        for s in self.samples.iter().flatten() {
            // Check expiry
            if now.saturating_sub(s.0) <= self.window_us {
                if s.1 > max_val { max_val = s.1; }
            }
        }
        max_val
    }
}

/// Tracks the Minimum value over a time window.
/// Used for Round-Trip Propagation (RTprop).
#[allow(dead_code)] // Logic exists for future BDP calc, currently unused in Lite.
#[derive(Debug, Clone)]
pub struct WindowedMinFilter {
    window_us: u64,
    samples: [Option<(u64, u64)>; 10],
    idx: usize,
}

#[allow(dead_code)]
impl WindowedMinFilter {
    pub fn new(window_us: u64) -> Self {
        Self {
            window_us,
            samples: [None; 10],
            idx: 0,
        }
    }

    pub fn update(&mut self, val: u64, now: u64) {
        self.samples[self.idx] = Some((now, val));
        self.idx = (self.idx + 1) % self.samples.len();
    }

    pub fn get_best(&self, now: u64) -> u64 {
        let mut min_val = u64::MAX;
        for s in self.samples.iter().flatten() {
            if now.saturating_sub(s.0) <= self.window_us {
                if s.1 < min_val { min_val = s.1; }
            }
        }
        if min_val == u64::MAX { 100_000 } else { min_val } // Default 100ms
    }
}