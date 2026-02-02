
#![forbid(unsafe_code)]

use crate::bbr::RateEstimator;



/// The Token Bucket Traffic Shaper.

pub struct Pacer {

    estimator: RateEstimator,

    last_update_us: u64,

    tokens: i64, // Bytes allowed to send

    min_rate_floor: u64, // CBR Floor (Bytes/sec)

}



impl Pacer {

    pub fn new(min_cbr_bps: u64) -> Self {

        Self {

            estimator: RateEstimator::new(),

            last_update_us: 0,

            tokens: 0,

            min_rate_floor: min_cbr_bps / 8,

        }

    }



    pub fn tick(&mut self, now_us: u64) -> u64 {

        if self.last_update_us == 0 {

            self.last_update_us = now_us;

            return 0;

        }



        let delta = now_us.saturating_sub(self.last_update_us);

        self.last_update_us = now_us;



        // 1. GET TARGET RATE

        let target_rate = core::cmp::max(

            self.estimator.get_pacing_rate_bps(now_us) / 8,

            self.min_rate_floor

        );



        // 2. REFILL TOKENS

        let new_tokens = (target_rate as u128 * delta as u128) / 1_000_000;

        

        // [M13-PHYSICS-CALCULATION]

        // TARGET: Intel Xeon W-2145 + Intel I219 NIC

        // L3 Cache: 11 MB

        // NIC Ring: 256 * 1280B = 327 KB

        //

        // OPTIMIZATION:

        // We cap the burst at 150 KB (approx 120 packets).

        // This guarantees we NEVER overflow the hardware TX Ring.

        // Even if the Pacer falls behind, we must NOT dump > 150KB at once.

        const NIC_RING_SAFETY_LIMIT: i64 = 150 * 1024; // 150 KB



        self.tokens = core::cmp::min(

            self.tokens + new_tokens as i64, 

            NIC_RING_SAFETY_LIMIT

        );



        if self.tokens > 0 { self.tokens as u64 } else { 0 }

    }



    pub fn consume(&mut self, bytes: usize) {

        self.tokens -= bytes as i64;

    }



    pub fn chaff_needed(&self, packet_mtu: usize) -> bool {

        self.tokens >= (packet_mtu as i64)

    }

    

    pub fn on_ack(&mut self, delivered_bps: u64, rtt_us: u64, now: u64) {

        self.estimator.on_ack(delivered_bps, rtt_us, now);

    }

}

