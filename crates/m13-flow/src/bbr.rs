
#![forbid(unsafe_code)]



use crate::filter::{WindowedMaxFilter, WindowedMinFilter};



const BTL_BW_WINDOW: u64 = 10_000_000; 

const RT_PROP_WINDOW: u64 = 10_000_000;



#[derive(Debug, Clone, Copy, PartialEq)]

#[allow(dead_code)]

pub enum BbrState { Startup, Drain, ProbeBw, ProbeRtt }



pub struct RateEstimator {

    #[allow(dead_code)]

    state: BbrState,

    btl_bw_filter: WindowedMaxFilter,

    rt_prop_filter: WindowedMinFilter,

    #[allow(dead_code)]

    last_rtt_probe: u64,

    pacing_gain: u64, 

}



impl RateEstimator {

    pub fn new() -> Self {

        Self {

            state: BbrState::Startup,

            btl_bw_filter: WindowedMaxFilter::new(BTL_BW_WINDOW),

            rt_prop_filter: WindowedMinFilter::new(RT_PROP_WINDOW),

            last_rtt_probe: 0,

            pacing_gain: 289, 

        }

    }



    pub fn on_ack(&mut self, delivered_bps: u64, rtt_us: u64, now: u64) {

        self.btl_bw_filter.update(delivered_bps, now);

        self.rt_prop_filter.update(rtt_us, now);

    }



    pub fn get_pacing_rate_bps(&self, now: u64) -> u64 {

        let btl_bw = self.btl_bw_filter.get_best(now);

        

        // [M13-PHYSICS-CALCULATION]

        // Hardware Limit: 1 Gbps I219 NIC

        // Value: 1,000,000,000 bps

        // We set the floor exactly to wire speed to saturate immediately

        // without triggering a bufferbloat collapse.

        let bw = if btl_bw == 0 { 1_000_000_000 } else { btl_bw };

        

        (bw * self.pacing_gain) / 100

    }

}

