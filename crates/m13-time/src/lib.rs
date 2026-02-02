#![no_std]

mod jitter;
pub use jitter::JitterBuffer;

/// Calculates safety margins for Control Loops.
/// Continuously samples RTT to determine the optimal buffer depth.
pub struct PhaseMonitor {
    rtt_samples: [u64; 16],
    idx: usize,
    count: usize,
}

impl PhaseMonitor {
    pub fn new() -> Self {
        Self {
            rtt_samples: [0; 16],
            idx: 0,
            count: 0,
        }
    }

    pub fn add_sample(&mut self, rtt_us: u64) {
        self.rtt_samples[self.idx] = rtt_us;
        self.idx = (self.idx + 1) % 16;
        if self.count < 16 { self.count += 1; }
    }

    /// Calculates the optimal Buffer Depth (D_buf).
    /// Formula: D = Mean + k * Sigma + Delta_Proc
    /// k = 4 (99.99% confidence interval)
    pub fn calculate_depth(&self) -> u64 {
        if self.count == 0 { return 100_000; } // Default 100ms safe start
        
        // 1. Mean
        let sum: u64 = self.rtt_samples.iter().take(self.count).sum();
        let mean = sum / self.count as u64;

        // 2. Variance -> StdDev
        let mut var_sum = 0;
        for &s in self.rtt_samples.iter().take(self.count) {
             let diff = if s > mean { s - mean } else { mean - s };
             var_sum += diff * diff;
        }
        let variance = var_sum / self.count as u64;
        
        // Integer Sqrt approximation (no_std)
        let std_dev = int_sqrt(variance);

        // 3. Safety Margin (4 Sigma)
        // Spec §7.2.1
        let safety_margin = 4 * std_dev;
        
        // 4. Proc Offset (Fixed Crypto overhead ~50us)
        let proc_offset = 50;

        mean + safety_margin + proc_offset
    }
}

/// Newton's method for integer sqrt
fn int_sqrt(n: u64) -> u64 {
    if n < 2 { return n; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (n / x + x) / 2;
    }
    x
}