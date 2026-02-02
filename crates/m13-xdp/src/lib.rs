pub mod umem; pub mod socket; pub mod protocol;
use umem::Umem; use socket::{XdpSocket, XdpDesc}; use protocol::*;
use m13_tun::TunDevice; use aya::{Ebpf, include_bytes_aligned}; use aya::maps::XskMap;
use std::convert::TryInto; use aya::programs::{Xdp, XdpFlags};
use rlimit::{Resource, setrlimit, INFINITY}; use std::ptr; use std::fs;
use std::net::Ipv4Addr;
use std::thread;
use std::time::{Instant, Duration};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::process::Command; 
use std::os::unix::io::AsRawFd;
use crossbeam_queue::ArrayQueue;
use io_uring::{IoUring, opcode, types};

use m13_ulk::{M13Kernel, KernelConfig};
use m13_hal::{PhysicalInterface, SecurityModule, PlatformClock, PeerAddr, LinkProperties};
use m13_mem::SlabAllocator;
use m13_pqc::DsaKeypair; 
use m13_core::M13Error;

// [PHYSICS] TITAN CONFIGURATION
const BATCH_SIZE: usize = 4096; 
const QUEUE_SIZE: usize = 32768;
const IO_URING_DEPTH: u32 = 8192;
const SLOT_SIZE: usize = 2048;
const BUFFER_SLOTS: usize = 8192; // 16MB Total
const BATCH_TIMEOUT_US: u128 = 50; // Hysteresis Window

pub struct VirtualPhy {
    pub tx_queue: Arc<ArrayQueue<(Vec<u8>, Option<PeerAddr>)>>,
    pub rx_queue: Arc<ArrayQueue<(Vec<u8>, PeerAddr)>>,
}

impl PhysicalInterface for VirtualPhy {
    fn properties(&self) -> LinkProperties {
        LinkProperties { mtu: 1500, bandwidth_bps: 10_000_000_000, is_reliable: false }
    }

    fn send(&mut self, data: &[u8], target: Option<PeerAddr>) -> Result<usize, nb::Error<M13Error>> {
        match self.tx_queue.push((data.to_vec(), target)) {
            Ok(_) => Ok(data.len()),
            Err(_) => Err(nb::Error::WouldBlock),
        }
    }

    fn recv(&mut self, _buf: &mut [u8]) -> Result<(usize, PeerAddr), nb::Error<M13Error>> {
        Err(nb::Error::WouldBlock)
    }

    fn recv_batch(&mut self, ptrs: &mut [&mut [u8]], meta: &mut [(usize, PeerAddr)]) -> Result<usize, nb::Error<M13Error>> {
        let mut count = 0;
        for (_i, (buf, addr)) in ptrs.iter_mut().zip(meta.iter_mut()).enumerate() {
            if let Some((packet, src)) = self.rx_queue.pop() {
                let len = std::cmp::min(buf.len(), packet.len());
                buf[..len].copy_from_slice(&packet[..len]);
                *addr = (len, src);
                count += 1;
            } else {
                break;
            }
        }
        Ok(count)
    }

    fn send_gso(&mut self, data: &[u8], target: Option<PeerAddr>, _segment_size: u16) -> Result<usize, nb::Error<M13Error>> {
        let total_len = data.len();
        let mut offset = 0;
        while offset < total_len {
            if total_len - offset < 32 { break; }
            let magic_slice = &data[offset..offset+4];
            let magic = u32::from_be_bytes(magic_slice.try_into().unwrap());
            if magic != MAGIC { return Err(nb::Error::Other(M13Error::WireFormatError)); }
            let len_slice = &data[offset+12..offset+14];
            let payload_len = u16::from_be_bytes(len_slice.try_into().unwrap()) as usize;
            let packet_len = 32 + payload_len; 
            if offset + packet_len > total_len { return Err(nb::Error::Other(M13Error::WireFormatError)); }
            let slice = &data[offset..offset+packet_len];
            if self.tx_queue.push((slice.to_vec(), target)).is_err() { return Err(nb::Error::WouldBlock); }
            offset += packet_len;
        }
        Ok(total_len)
    }
}

struct SysClock;
impl PlatformClock for SysClock { 
    fn now_us(&self) -> u64 { 0 } 
    fn ptp_ns(&self) -> Option<u64> { None }
}

struct SysSec;
impl SecurityModule for SysSec { 
    fn get_random_bytes(&mut self, buf: &mut [u8]) -> Result<(), M13Error> { 
        getrandom::getrandom(buf).map_err(|_| M13Error::RngFailure) 
    }
    fn sign_digest(&mut self, _msg: &[u8], _sig: &mut [u8]) -> Result<usize, M13Error> {
        Err(M13Error::Generic)
    }
    fn panic_and_sanitize(&self) -> ! {
        std::process::exit(1);
    }
}

fn mac_to_u64(mac: [u8; 6]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[0..6].copy_from_slice(&mac);
    u64::from_be_bytes(bytes)
}

fn u64_to_mac(val: u64) -> [u8; 6] {
    let bytes = val.to_be_bytes();
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bytes[0..6]);
    mac
}

pub struct M13HubDriver {
    _bpf: Ebpf, 
    socket: XdpSocket, 
    tun: Option<TunDevice>, 
    local_mac: [u8;6], 
    local_ip: u32, 
    gateway_mac: Arc<AtomicU64>,
    kernel: Option<M13Kernel>, 
    kernel_tx_queue: Arc<ArrayQueue<(Vec<u8>, Option<PeerAddr>)>>,
    kernel_rx_queue: Arc<ArrayQueue<(Vec<u8>, PeerAddr)>>,
    vec_free_queue: Arc<ArrayQueue<Vec<u8>>>,
    frame_cache: Vec<u64>,
}

impl M13HubDriver {
    pub fn new(iface: &str, qid: u32, manual_ip: Option<String>) -> anyhow::Result<Self> {
        setrlimit(Resource::MEMLOCK, INFINITY, INFINITY).ok();
        
        eprintln!(">>> [DIAGNOSTIC] SYSTEM CHECK (TITAN v4.2 - ADAPTIVE BATCHING)...");
        
        let _ = Command::new("ethtool").args(&["-L", iface, "combined", "1"]).output();

        let mut bpf = Ebpf::load(include_bytes_aligned!("../bpf/xdp_redirect.o"))?;
        let prog: &mut Xdp = bpf.program_mut("xdp_sock_prog").unwrap().try_into()?;
        prog.load()?; prog.attach(iface, XdpFlags::default())?;

        let umem = Umem::new()?;
        let socket = unsafe { XdpSocket::new(iface, qid, umem)? };
        let mut map: XskMap<_> = bpf.map_mut("xsks_map").unwrap().try_into()?;
        map.set(qid, socket.fd, 0)?;

        // [PHYSICS] ENABLE KERNEL BUSY POLLING (100us)
        unsafe {
            let val: u32 = 100; 
            let _ = libc::setsockopt(
                socket.fd, 
                libc::SOL_SOCKET, 
                libc::SO_BUSY_POLL, 
                &val as *const _ as *const libc::c_void, 
                std::mem::size_of::<u32>() as u32
            );
        }

        eprintln!("    -> AF_XDP: SOCKET BOUND [ACTIVE]");

        let requested_name = "m13tun";
        let tun = TunDevice::new_hub(requested_name)?;
        let actual_tun_name = wait_for_interface(requested_name, "tun0");

        Self::setup_system_routing(iface, &actual_tun_name);

        let mac_s = fs::read_to_string(format!("/sys/class/net/{}/address", iface))?.trim().to_string();
        let mut local_mac = [0u8; 6];
        let v: Vec<u8> = mac_s.split(':').map(|x| u8::from_str_radix(x,16).unwrap_or(0)).collect();
        if v.len() == 6 { local_mac.copy_from_slice(&v); }

        let gw_mac_bytes = match resolve_gateway_mac_retry(iface) {
            Ok(m) => m,
            Err(_) => [0u8; 6]
        };
        let gateway_mac = Arc::new(AtomicU64::new(mac_to_u64(gw_mac_bytes)));
        
        let mut local_ip = 0;
        if let Some(ip_str) = manual_ip {
             if let Ok(addr) = ip_str.parse::<Ipv4Addr>() {
                 local_ip = u32::from(addr).to_be();
             }
        }

        let tx_queue = Arc::new(ArrayQueue::new(QUEUE_SIZE));
        let rx_queue = Arc::new(ArrayQueue::new(QUEUE_SIZE));
        let vec_free_queue = Arc::new(ArrayQueue::new(QUEUE_SIZE));
        for _ in 0..QUEUE_SIZE {
            let _ = vec_free_queue.push(Vec::with_capacity(2048));
        }
        
        let phy = Box::new(VirtualPhy { 
            tx_queue: tx_queue.clone(),
            rx_queue: rx_queue.clone(),
        });
        
        let sec = Box::new(SysSec);
        let clock = Box::new(SysClock);
        let mem = SlabAllocator::new(16384); 
        let config = KernelConfig { is_hub: true, enable_encryption: true };
        let identity = DsaKeypair::generate(&mut rand_core::OsRng).expect("Failed to gen identity");

        let kernel = M13Kernel::new(phy, sec, clock, mem, config, identity);

        let d = Self { 
            _bpf: bpf, socket, 
            tun: Some(tun), 
            local_mac, 
            gateway_mac,
            local_ip, 
            kernel: Some(kernel), 
            kernel_tx_queue: tx_queue,
            kernel_rx_queue: rx_queue,
            vec_free_queue,
            frame_cache: Vec::with_capacity(BATCH_SIZE),
        };
        unsafe { d.initial_fill(); }
        Ok(d)
    }

    fn setup_system_routing(wan_iface: &str, tun_iface: &str) {
        // [PHYSICS] KILL IPV6 & FORCE STATIC INTERRUPTS
        run_cmd("sysctl", &["-w", "net.ipv6.conf.all.disable_ipv6=1"]);
        run_cmd("sysctl", &["-w", "net.ipv6.conf.default.disable_ipv6=1"]);
        run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
        let _ = Command::new("ethtool").args(&["-C", wan_iface, "rx-usecs", "50"]).output();

        run_cmd("ip", &["addr", "flush", "dev", tun_iface]); 
        run_cmd("ip", &["addr", "add", "10.13.13.1/24", "dev", tun_iface]);
        run_cmd("ip", &["link", "set", "dev", tun_iface, "txqueuelen", "10000"]);
        run_cmd("ip", &["link", "set", "dev", tun_iface, "up"]);
        let _ = Command::new("iptables").args(&["-t", "nat", "-A", "POSTROUTING", "-o", wan_iface, "-j", "MASQUERADE"]).output();
        let _ = Command::new("iptables").args(&["-A", "FORWARD", "-i", tun_iface, "-o", wan_iface, "-j", "ACCEPT"]).output();
        let _ = Command::new("iptables").args(&["-A", "FORWARD", "-i", wan_iface, "-o", tun_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).output();
    }

    unsafe fn initial_fill(&self) {
        let f = &self.socket.fill_ring; let mut p = ptr::read_volatile(f.producer);
        let mut free = self.socket.umem.free_frames.lock().unwrap();
        let fill_ptr = f.desc as *mut u64;
        for _ in 0..8192 {
            if let Some(a) = free.pop_back() {
                *fill_ptr.add((p & f.mask) as usize) = a; 
                p = p.wrapping_add(1);
            }
        }
        ptr::write_volatile(f.producer, p);
    }

    // [PHYSICS] XDP TX BATCHER (No Flags Check)
    unsafe fn xdp_tx_batch(&mut self) -> usize {
        let tx = &mut self.socket.tx_ring; 
        let mut p = ptr::read_volatile(tx.producer);
        let c = ptr::read_volatile(tx.consumer);
        let size = tx.mask + 1;
        
        let available_slots = size - p.wrapping_sub(c);
        if available_slots == 0 { return 0; }

        let mut pkt_batch = Vec::with_capacity(BATCH_SIZE);
        let mut meta_batch = Vec::with_capacity(BATCH_SIZE);
        
        for _ in 0..std::cmp::min(available_slots as usize, BATCH_SIZE) {
            if let Some((pkt, target)) = self.kernel_tx_queue.pop() {
                pkt_batch.push(pkt);
                meta_batch.push(target);
            } else {
                break;
            }
        }
        let count = pkt_batch.len();
        if count == 0 { return 0; }

        {
            let mut free = self.socket.umem.free_frames.lock().unwrap();
            for _ in 0..count {
                if let Some(a) = free.pop_back() {
                    self.frame_cache.push(a);
                } else {
                    break; 
                }
            }
        }
        let alloc_count = self.frame_cache.len();
        let current_gw = u64_to_mac(self.gateway_mac.load(Ordering::Relaxed));
        let tx_ptr = tx.desc as *mut XdpDesc;

        for i in 0..alloc_count {
            let a = self.frame_cache[i];
            let data = &pkt_batch[i];
            let target = meta_batch[i];

            let (dst_ip, dst_port) = match target {
                Some(PeerAddr::V4(ip_bytes, port)) => (u32::from_be_bytes(ip_bytes), port),
                _ => (0,0), 
            };

            let ptr = self.socket.umem.as_ptr().offset(a as isize);
            let eth = ptr as *mut EthHeader; 
            (*eth).dst = current_gw; (*eth).src = self.local_mac; (*eth).etype = 0x0800u16.to_be(); 

            let n = data.len();
            let ip = ptr.add(14) as *mut Ipv4Header; 
            (*ip).ver_ihl = 0x45; (*ip).len = ((n + 20 + 8) as u16).to_be(); 
            (*ip).ttl = 64; (*ip).proto = 17; (*ip).src = self.local_ip; (*ip).dst = dst_ip.to_be(); 
            
            calc_ip_checksum(&mut *ip); 
            let udp = ptr.add(34) as *mut UdpHeader; 
            (*udp).src = M13_PORT.to_be(); (*udp).dst = dst_port.to_be(); (*udp).len = ((n + 8) as u16).to_be(); 
            (*udp).check = 0; 

            ptr.add(42).copy_from_nonoverlapping(data.as_ptr(), n);

            *tx_ptr.add((p & tx.mask) as usize) = XdpDesc{addr:a, len:(n as u32 + 42), options:0};
            p = p.wrapping_add(1);
        }

        self.frame_cache.clear();
        ptr::write_volatile(tx.producer, p);
        libc::sendto(self.socket.fd, ptr::null(), 0, libc::MSG_DONTWAIT, ptr::null(), 0);
        alloc_count
    }

    pub fn run_vpp(mut self) {
        let mut kernel = self.kernel.take().unwrap();
        let tun = self.tun.take().unwrap();
        let tun_fd = tun.as_raw_fd(); 
        
        unsafe {
            let mut flags = libc::fcntl(tun_fd, libc::F_GETFL, 0);
            flags |= libc::O_NONBLOCK;
            libc::fcntl(tun_fd, libc::F_SETFL, flags);
        }

        let gateway_mac_atomic = self.gateway_mac.clone();
        let vec_free_atomic = self.vec_free_queue.clone();

        thread::spawn(move || {
            if let Some(core) = core_affinity::get_core_ids().and_then(|v| v.get(2).copied()) {
                core_affinity::set_for_current(core);
            }
            
            eprintln!("    -> IO_URING: INIT ({} Entries, FIXED BUFFERS)", IO_URING_DEPTH);
            let mut ring = IoUring::new(IO_URING_DEPTH).expect("Failed to setup io_uring");
            let submitter = ring.submitter();

            let buffer_size = BUFFER_SLOTS * SLOT_SIZE;
            let mut fixed_buffer = vec![0u8; buffer_size]; 
            let iovec = libc::iovec {
                iov_base: fixed_buffer.as_mut_ptr() as *mut libc::c_void,
                iov_len: buffer_size,
            };
            unsafe {
                submitter.register_buffers(&[iovec]).expect("FAILED TO REGISTER BUFFERS");
            }
            eprintln!("    -> IO_URING: BUFFERS REGISTERED [LOCKED]");

            let mut free_slots: Vec<usize> = (0..BUFFER_SLOTS).collect();
            let mut active_reads = 0;
            let mut _once = false;

            const READ_TARGET: usize = 256; 
            
            loop {
                let mut worked = false;
                let mut needs_submit = false;
                
                // 1. MAINTAIN READ PRESSURE
                while active_reads < READ_TARGET {
                    if let Some(idx) = free_slots.pop() {
                        let offset = idx * SLOT_SIZE;
                        let buf_ptr = fixed_buffer.as_mut_ptr();
                        let op = opcode::ReadFixed::new(types::Fd(tun_fd), unsafe { buf_ptr.add(offset) }, SLOT_SIZE as u32, 0)
                            .build()
                            .user_data(idx as u64);
                        unsafe { let _ = ring.submission().push(&op); }
                        active_reads += 1;
                        needs_submit = true;
                    } else {
                        break;
                    }
                }

                // 2. REAP COMPLETIONS
                if ring.completion().len() > 0 {
                    let cq = ring.completion();
                    for cqe in cq {
                        let idx = cqe.user_data() as usize;
                        let res = cqe.result();
                        let is_write = (idx & (1<<63)) != 0;
                        let real_idx = idx & !(1<<63);

                        if is_write {
                            free_slots.push(real_idx);
                        } else {
                            if res > 0 {
                                let n = res as usize;
                                let offset = real_idx * SLOT_SIZE;
                                let data_slice = &fixed_buffer[offset..offset+n];
                                let gw = u64_to_mac(gateway_mac_atomic.load(Ordering::Relaxed));
                                if gw != [0u8; 6] { 
                                    let _ = kernel.send_payload(data_slice);
                                    worked = true;
                                }
                            }
                            active_reads -= 1; 
                            free_slots.push(real_idx); 
                        }
                    }
                }

                // 3. POLL KERNEL
                for _ in 0..64 {
                    if kernel.poll() { worked = true; } else { break; }
                }

                // 4. WRITE TUN + ADAPTIVE BATCHING (HYSTERESIS)
                // [PHYSICS] Stop Dribbling. Wait for 256 or 50us.
                let mut write_cnt = 0;
                let batch_start = Instant::now();
                let mut batch_started = false;

                loop {
                    // Try to fetch a packet
                    if let Some(pkt) = kernel.pop_ingress() {
                        batch_started = true;
                        if let Some(idx) = free_slots.pop() {
                            let offset = idx * SLOT_SIZE;
                            let len = std::cmp::min(pkt.len(), SLOT_SIZE);
                            let dst = &mut fixed_buffer[offset..offset+len];
                            let b0 = pkt[0];
                            let final_len;

                            if ! _once {
                                eprintln!("    -> PAYLOAD SAMPLE: First Byte = {:02X}", b0);
                                _once = true;
                            }

                            // Decapsulate
                            if (b0 & 0xF0) == 0x40 {
                                dst.copy_from_slice(&pkt[0..len]);
                                final_len = len;
                            } else if pkt.len() > 14 && (pkt[14] & 0xF0) == 0x40 {
                                final_len = len - 14;
                                dst[0..final_len].copy_from_slice(&pkt[14..14+final_len]);
                            } else {
                                free_slots.push(idx);
                                let _ = vec_free_atomic.push(pkt); 
                                continue;
                            }

                            let op = opcode::WriteFixed::new(types::Fd(tun_fd), unsafe { fixed_buffer.as_ptr().add(offset) }, final_len as u32, 0)
                                .build()
                                .user_data((idx as u64) | (1<<63));
                            
                            unsafe { let _ = ring.submission().push(&op); }
                            needs_submit = true;
                            
                            let mut p = pkt; p.clear();
                            let _ = vec_free_atomic.push(p);
                            
                            write_cnt += 1;
                        } else {
                            // No Slots? Break immediately
                            break; 
                        }
                    } else {
                        // QUEUE EMPTY. Do we wait?
                        if !batch_started {
                            // If we haven't started a batch, don't wait.
                            break; 
                        }
                        
                        // If we HAVE started, wait up to 50us to fill it.
                        if write_cnt >= 256 { break; }
                        if batch_start.elapsed().as_micros() > BATCH_TIMEOUT_US { break; }
                        
                        std::hint::spin_loop(); // BURN CYCLES TO WAIT FOR PACKETS
                    }
                }
                
                if write_cnt > 0 { worked = true; }

                if needs_submit {
                    let _ = ring.submit();
                }

                if !worked { std::hint::spin_loop(); }
            }
        });

        if let Some(core) = core_affinity::get_core_ids().and_then(|v| v.get(1).copied()) {
            core_affinity::set_for_current(core);
        }

        loop {
            let mut worked = false;

            unsafe {
                let cp = &self.socket.comp_ring; 
                let mut cc = ptr::read_volatile(cp.consumer);
                let comp_ptr = cp.desc as *const u64; 
                if cc != ptr::read_volatile(cp.producer) {
                    let mut batch_free = Vec::with_capacity(256);
                    while cc != ptr::read_volatile(cp.producer) && batch_free.len() < 256 {
                         batch_free.push(*comp_ptr.add((cc & cp.mask) as usize)); 
                         cc = cc.wrapping_add(1);
                    }
                    if !batch_free.is_empty() {
                        let mut free = self.socket.umem.free_frames.lock().unwrap();
                        for addr in batch_free {
                            free.push_back(addr);
                        }
                    }
                    ptr::write_volatile(cp.consumer, cc);
                }
            }

            unsafe {
                if self.xdp_tx_batch() > 0 {
                    worked = true;
                }
            }

            unsafe {
                let rx = &self.socket.rx_ring; 
                let mut c = ptr::read_volatile(rx.consumer);
                let p_head = ptr::read_volatile(rx.producer);
                let rx_ptr = rx.desc as *const XdpDesc;
                
                if c != p_head {
                    worked = true;
                    let f = &mut self.socket.fill_ring;
                    let fill_ptr = f.desc as *mut u64;
                    let mut fp = ptr::read_volatile(f.producer);

                    let mut rx_batch = 0;
                    while c != p_head && rx_batch < BATCH_SIZE {
                        let d = *rx_ptr.add((c & rx.mask) as usize);
                        let ptr = self.socket.umem.as_ptr().offset(d.addr as isize);
                        
                        let eth = ptr as *const EthHeader;
                        let mut cursor = 14; 
                        let mut etype = (*eth).etype;
                        if etype == 0x8100u16.to_be() { cursor += 4; etype = *(ptr.add(cursor-2) as *const u16); }

                        if etype == 0x0800u16.to_be() { 
                            let ip = ptr.add(cursor) as *const Ipv4Header;
                            let ip_len = (*ip).header_len();
                            cursor += ip_len;
                            if d.len as usize >= cursor + 8 + 32 {
                                let udp = ptr.add(cursor) as *const UdpHeader;
                                if (*udp).dst == M13_PORT.to_be() {
                                    cursor += 8;
                                    let m13 = ptr.add(cursor) as *const M13Header;
                                    if (*m13).magic == MAGIC.to_be() {
                                        let current_gw = u64_to_mac(self.gateway_mac.load(Ordering::Relaxed));
                                        if current_gw != (*eth).src {
                                            self.gateway_mac.store(mac_to_u64((*eth).src), Ordering::Relaxed);
                                        }
                                        let total_udp_len = u16::from_be((*udp).len) as usize;
                                        let m13_len = total_udp_len - 8;
                                        let _src_ip_bytes = (*ip).src.to_be_bytes(); 
                                        let src_ip_u32 = u32::from_be((*ip).src);
                                        let peer = PeerAddr::V4(src_ip_u32.to_be_bytes(), u16::from_be((*udp).src));
                                        
                                        let mut vec = if let Some(mut v) = self.vec_free_queue.pop() {
                                            v.clear();
                                            v.reserve(m13_len);
                                            v
                                        } else {
                                            Vec::with_capacity(m13_len)
                                        };
                                        
                                        let payload_ptr = ptr.add(cursor);
                                        vec.extend_from_slice(std::slice::from_raw_parts(payload_ptr, m13_len));
                                        
                                        let _ = self.kernel_rx_queue.push((vec, peer));
                                    }
                                }
                            }
                        }
                        
                        *fill_ptr.add((fp & f.mask) as usize) = d.addr;
                        fp = fp.wrapping_add(1);
                        c = c.wrapping_add(1);
                        rx_batch += 1;
                    }
                    ptr::write_volatile(rx.consumer, c);
                    ptr::write_volatile(f.producer, fp);
                }
            }
            if !worked { std::hint::spin_loop(); }
        }
    }
}

fn wait_for_interface(primary: &str, fallback: &str) -> String {
    for _ in 0..10 {
        if interface_exists(primary) { return primary.to_string(); }
        if interface_exists(fallback) { return fallback.to_string(); }
        thread::sleep(Duration::from_millis(500));
    }
    panic!("TUN Creation Timeout");
}

fn interface_exists(iface: &str) -> bool {
    let output = Command::new("ip").args(&["link", "show", iface]).output();
    output.map(|o| o.status.success()).unwrap_or(false)
}

fn run_cmd(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

fn resolve_gateway_mac_retry(iface: &str) -> anyhow::Result<[u8; 6]> {
    if let Ok(out) = std::process::Command::new("ip").args(&["route", "show", "default", "dev", iface]).output() {
        if let Ok(s) = String::from_utf8(out.stdout) {
            if let Some(gw_ip) = s.split_whitespace().nth(2) {
                for _ in 0..3 {
                    std::process::Command::new("ping").args(&["-c", "1", "-W", "1", "-I", iface, gw_ip]).output().ok();
                    if let Ok(n_out) = std::process::Command::new("ip").args(&["neigh", "show", gw_ip, "dev", iface]).output() {
                        let ns = String::from_utf8(n_out.stdout).unwrap_or_default();
                        if let Some(pos) = ns.find("lladdr") {
                            let remainder = &ns[pos + 7..];
                            let mac_s = remainder.split_whitespace().next().unwrap_or("");
                            if mac_s.len() == 17 {
                                let mut m = [0u8; 6];
                                let v: Vec<u8> = mac_s.split(':').map(|x| u8::from_str_radix(x,16).unwrap_or(0)).collect();
                                if v.len() == 6 {
                                    m.copy_from_slice(&v);
                                    return Ok(m);
                                }
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }
    Err(anyhow::anyhow!("Gateway Resolution Failed"))
}
