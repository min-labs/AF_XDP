// M13 HUB — NETWORK: BPF STEERSMAN
// Loads and attaches the eBPF XDP program that filters M13 traffic into AF_XDP UMEM.
// Detaches on Drop.

use libbpf_sys::{
    bpf_object, bpf_object__open_mem, bpf_object__load, bpf_object__find_program_by_name,
    bpf_program__fd, bpf_object__find_map_by_name, bpf_map__fd,
    bpf_set_link_xdp_fd,
    XDP_FLAGS_SKB_MODE, XDP_FLAGS_DRV_MODE, XDP_FLAGS_UPDATE_IF_NOEXIST,
};
use libc::{c_void, setrlimit, rlimit, RLIMIT_MEMLOCK, RLIM_INFINITY};
use std::mem;
use std::ffi::CString;

use crate::network::xdp::UMEM_SIZE;

const BPF_OBJ_BYTES: &[u8] = include_bytes!(env!("BPF_OBJECT_PATH"));

/// BPF XDP steersman. Loads and attaches the eBPF program that filters
/// EtherType 0x88B5 (M13) traffic into AF_XDP UMEM. Detaches on Drop.
pub struct BpfSteersman { #[allow(dead_code)] obj: *mut bpf_object, map_fd: i32, if_index: i32, pub attach_mode: &'static str }
unsafe impl Send for BpfSteersman {}
impl BpfSteersman {
    pub fn load_and_attach(if_name: &str) -> Option<Self> {
        // Scope RLIMIT_MEMLOCK to UMEM + 16MB for BPF maps/programs.
        // Least-privilege: only lock what AF_XDP + BPF actually need.
        // Fallback to RLIM_INFINITY for kernels <5.11 or restrictive limits.conf.
        // SAFETY: Caller ensures invariants documented at module level.
        unsafe {
            let needed = (UMEM_SIZE + 16 * 1024 * 1024) as u64;
            let rlim = rlimit { rlim_cur: needed, rlim_max: needed };
            if setrlimit(RLIMIT_MEMLOCK, &rlim) != 0 {
                let rlim = rlimit { rlim_cur: RLIM_INFINITY, rlim_max: RLIM_INFINITY };
                setrlimit(RLIMIT_MEMLOCK, &rlim);
            }
        }
        let c_ifname = match CString::new(if_name) {
            Ok(c) => c,
            Err(_) => return None,
        };
        // SAFETY: CString pointer is valid and null-terminated.
        let if_index = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) } as i32;
        if if_index == 0 { 
            eprintln!("[M13-BPF] Interface not found: {}", if_name);
            return None; 
        }
        // SAFETY: Type is repr(C) and all-zeroes is a valid bit pattern.
        unsafe {
            let mut opts: libbpf_sys::bpf_object_open_opts = mem::zeroed();
            opts.sz = mem::size_of::<libbpf_sys::bpf_object_open_opts>() as u64;
            let obj = bpf_object__open_mem(BPF_OBJ_BYTES.as_ptr() as *const c_void, BPF_OBJ_BYTES.len() as u64, &opts);
            if obj.is_null() { 
                eprintln!("[M13-BPF] BPF object open failed");
                return None; 
            }
            let ret = bpf_object__load(obj);
            if ret != 0 { 
                eprintln!("[M13-BPF] BPF object load failed (op not permitted?). Running in non-XDP mode.");
                return None; 
            }
            let prog_name = CString::new("m13_steersman").unwrap();
            let prog = bpf_object__find_program_by_name(obj, prog_name.as_ptr());
            let prog_fd = bpf_program__fd(prog);
            let map_name = CString::new("xsks_map").unwrap();
            let map = bpf_object__find_map_by_name(obj, map_name.as_ptr());
            let map_fd = bpf_map__fd(map);
            let is_sim = std::env::var("M13_SIMULATION").is_ok();
            let mut flags = if is_sim { XDP_FLAGS_SKB_MODE } else { XDP_FLAGS_DRV_MODE };
            flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
            let mut ret = bpf_set_link_xdp_fd(if_index, prog_fd, flags);
            if ret != 0 && !is_sim {
                flags = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
                ret = bpf_set_link_xdp_fd(if_index, prog_fd, flags);
            }
            if ret != 0 { 
                eprintln!("[M13-BPF] BPF XDP attach failed");
                return None; 
            }
            let attach_mode = if flags & XDP_FLAGS_DRV_MODE != 0 { "Native" } else { "Generic (SKB)" };
            Some(BpfSteersman { obj, map_fd, if_index, attach_mode })
        }
    }
    pub fn map_fd(&self) -> i32 { self.map_fd }
}
// SAFETY: FFI call; if_index and prog_fd are verified valid.
impl Drop for BpfSteersman { fn drop(&mut self) { unsafe { if self.if_index > 0 { bpf_set_link_xdp_fd(self.if_index, -1, 0); } } } }
