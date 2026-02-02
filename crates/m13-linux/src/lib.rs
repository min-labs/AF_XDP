#![allow(unused)]

use std::io::{self, Read, Write};
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process::Command;
use tun::Device;
use std::net::{SocketAddr, IpAddr};
use std::time::Instant;
use socket2::{Socket, Domain, Type, Protocol, SockAddr};

// [FIXED] Correct Import from HAL
use m13_hal::{PhysicalInterface, LinkProperties, SecurityModule, PlatformClock, PeerAddr};
use m13_core::{M13Error, M13Result};

#[cfg(target_os = "macos")]
const BSD_AF_INET: [u8; 4] = [0, 0, 0, 2];

#[cfg(target_os = "linux")]
const MAX_BATCH: usize = 64;

fn to_peer_addr(addr: SocketAddr) -> PeerAddr {
    match addr {
        SocketAddr::V4(v4) => PeerAddr::V4(v4.ip().octets(), v4.port()),
        SocketAddr::V6(v6) => PeerAddr::V6(v6.ip().octets(), v6.port()),
    }
}

fn to_socket_addr(peer: &PeerAddr) -> Option<SocketAddr> {
    match peer {
        PeerAddr::V4(ip, port) => Some(SocketAddr::new(IpAddr::from(*ip), *port)),
        PeerAddr::V6(ip, port) => Some(SocketAddr::new(IpAddr::from(*ip), *port)),
        PeerAddr::None => None,
    }
}

pub struct TunDevice {
    file: File,
    name: String,
    raw_fd: RawFd,
    local_ip: String,
    peer_ip: String,
}

impl TunDevice {
    pub fn new(name: &str, ip: &str, dest: &str) -> anyhow::Result<Self> {
        let mut config = tun::Configuration::default();
        config
            .name(name)
            .address(ip)
            .destination(dest)
            .netmask("255.255.255.0")
            .mtu(1280)
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|c| { c.packet_information(false); });

        let dev = tun::create(&config).map_err(|e| anyhow::anyhow!(e))?;
        let name = dev.name().to_string();
        
        let raw_fd = dev.as_raw_fd();
        let file = unsafe { File::from_raw_fd(raw_fd) };
        std::mem::forget(dev); 

        unsafe {
            let mut flags = libc::fcntl(raw_fd, libc::F_GETFL, 0);
            flags |= libc::O_NONBLOCK;
            libc::fcntl(raw_fd, libc::F_SETFL, flags);
        }

        Ok(Self { 
            file, name, raw_fd,
            local_ip: ip.to_string(),
            peer_ip: dest.to_string(),
        })
    }

    pub fn fd(&self) -> RawFd { self.raw_fd }
    pub fn name(&self) -> &str { &self.name }

    pub fn shutdown(&self) {
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("ifconfig")
                .args(&[&self.name, "delete", &self.local_ip, &self.peer_ip])
                .status();
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.file.read(buf) {
            Ok(n) => {
                #[cfg(target_os = "macos")]
                {
                    if n > 4 {
                        buf.copy_within(4..n, 0);
                        return Ok(n - 4);
                    }
                    Ok(0)
                }
                #[cfg(not(target_os = "macos"))]
                Ok(n)
            },
            Err(e) => Err(e),
        }
    }

    pub fn write(&mut self, packet: &[u8]) -> std::io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            let mut out = Vec::with_capacity(4 + packet.len());
            out.extend_from_slice(&BSD_AF_INET);
            out.extend_from_slice(packet);
            self.file.write_all(&out)
        }
        #[cfg(not(target_os = "macos"))]
        self.file.write_all(packet)
    }
}

pub struct LinuxUdp {
    socket: Socket,
    default_target: Option<PeerAddr>,
}

impl LinuxUdp {
    pub fn new(bind_addr: &str, target_addr: Option<&str>) -> anyhow::Result<Self> {
        let addr: SocketAddr = bind_addr.parse()?;
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        
        // PHYSICS FIX: 4MB Buffers
        let buf_size = 4 * 1024 * 1024;
        let _ = socket.set_recv_buffer_size(buf_size);
        let _ = socket.set_send_buffer_size(buf_size);
        
        socket.set_nonblocking(true)?;
        
        let sa: SockAddr = addr.into();
        socket.bind(&sa)?;
        
        let default_target = if let Some(t) = target_addr {
             let sa: SocketAddr = t.parse()?;
             Some(to_peer_addr(sa))
        } else {
             None
        };

        Ok(Self { socket, default_target })
    }
}

impl PhysicalInterface for LinuxUdp {
    fn properties(&self) -> LinkProperties {
        LinkProperties { mtu: 1400, bandwidth_bps: 1_000_000_000, is_reliable: false }
    }

    fn send(&mut self, frame: &[u8], target: Option<PeerAddr>) -> nb::Result<usize, M13Error> {
        let final_target = target.or(self.default_target);

        let dest_peer = match final_target {
            Some(t) => t,
            None => return Ok(0),
        };

        let dest_sock = to_socket_addr(&dest_peer).ok_or(nb::Error::Other(M13Error::HalError))?;
        let addr: SockAddr = dest_sock.into();

        match self.socket.send_to(frame, &addr) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Err(nb::Error::WouldBlock),
            Err(_) => Err(nb::Error::Other(M13Error::HalError)),
        }
    }

    // [PHYSICS] GSO Implementation OVERRIDE
    #[cfg(target_os = "linux")]
    fn send_gso(
        &mut self, 
        data: &[u8], 
        target: Option<PeerAddr>, 
        segment_size: u16
    ) -> nb::Result<usize, M13Error> {
        use libc::{iovec, msghdr, sendmsg, cmsghdr, CMSG_FIRSTHDR, CMSG_DATA, SOL_UDP, UDP_SEGMENT};
        use std::mem;

        // Resolve Target
        let final_target = target.or(self.default_target);
        let dest_peer = match final_target {
            Some(t) => t,
            None => return Ok(0),
        };
        let dest_sock = to_socket_addr(&dest_peer).ok_or(nb::Error::Other(M13Error::HalError))?;
        let socket_addr: SockAddr = dest_sock.into();

        let fd = self.socket.as_raw_fd();
        
        let mut iov = iovec {
            iov_base: data.as_ptr() as *mut _,
            iov_len: data.len(),
        };

        let mut ctrl_buf = [0u8; 64]; 
        let mut msg = unsafe { mem::zeroed::<msghdr>() };
        
        msg.msg_name = socket_addr.as_ptr() as *mut _;
        msg.msg_namelen = socket_addr.len();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = ctrl_buf.len() as usize;

        let res = unsafe {
            let cmsg = CMSG_FIRSTHDR(&mut msg);
            (*cmsg).cmsg_level = SOL_UDP;
            (*cmsg).cmsg_type = UDP_SEGMENT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(2) as usize;
            
            let data_ptr = CMSG_DATA(cmsg) as *mut u16;
            *data_ptr = segment_size;
            
            msg.msg_controllen = (*cmsg).cmsg_len;
            
            sendmsg(fd, &msg, 0)
        };

        if res < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Err(nb::Error::WouldBlock);
            }
            return Err(nb::Error::Other(M13Error::HalError));
        }
        Ok(res as usize)
    }

    fn recv<'a>(&mut self, buf: &'a mut [u8]) -> nb::Result<(usize, PeerAddr), M13Error> {
        let buf_uninit = unsafe { 
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>, buf.len()) 
        };

        match self.socket.recv_from(buf_uninit) {
            Ok((n, src)) => Ok((n, to_peer_addr(src.as_socket().unwrap()))),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Err(nb::Error::WouldBlock),
            Err(_) => Err(nb::Error::Other(M13Error::HalError)),
        }
    }

    #[cfg(target_os = "linux")]
    fn recv_batch(
        &mut self, 
        buffers: &mut [&mut [u8]], 
        meta: &mut [(usize, PeerAddr)]
    ) -> nb::Result<usize, M13Error> {
        use libc::{mmsghdr, iovec, sockaddr_storage, recvmmsg, MSG_DONTWAIT};
        use std::mem;

        let fd = self.socket.as_raw_fd();
        let count = buffers.len().min(meta.len()).min(MAX_BATCH);

        let mut msg_vec: [mmsghdr; MAX_BATCH] = unsafe { mem::zeroed() };
        let mut iov_vec: [iovec; MAX_BATCH] = unsafe { mem::zeroed() };
        let mut addr_vec: [sockaddr_storage; MAX_BATCH] = unsafe { mem::zeroed() };

        for i in 0..count {
            iov_vec[i].iov_base = buffers[i].as_mut_ptr() as *mut libc::c_void;
            iov_vec[i].iov_len = buffers[i].len();

            msg_vec[i].msg_hdr.msg_iov = &mut iov_vec[i];
            msg_vec[i].msg_hdr.msg_iovlen = 1;
            msg_vec[i].msg_hdr.msg_name = &mut addr_vec[i] as *mut _ as *mut libc::c_void;
            msg_vec[i].msg_hdr.msg_namelen = mem::size_of::<sockaddr_storage>() as u32;
        }

        let res = unsafe {
            recvmmsg(fd, msg_vec.as_mut_ptr(), count as u32, MSG_DONTWAIT, std::ptr::null_mut())
        };

        if res < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Err(nb::Error::WouldBlock);
            }
            return Err(nb::Error::Other(M13Error::HalError));
        }

        let pkts = res as usize;
        for i in 0..pkts {
            meta[i].0 = msg_vec[i].msg_len as usize;
            
            let addr = unsafe { 
                socket2::SockAddr::new(addr_vec[i], msg_vec[i].msg_hdr.msg_namelen) 
            };
            
            if let Some(sa) = addr.as_socket() {
                meta[i].1 = to_peer_addr(sa);
            }
        }
        Ok(pkts)
    }
}

pub type LinuxPhy = LinuxUdp; 

pub struct LinuxHsm;
impl SecurityModule for LinuxHsm {
    fn get_random_bytes(&mut self, buf: &mut [u8]) -> M13Result<()> {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buf);
        Ok(())
    }
    fn sign_digest(&mut self, _: &[u8], sig: &mut [u8]) -> M13Result<usize> {
        sig.fill(0xAA); Ok(64)
    }
    fn panic_and_sanitize(&self) -> ! { std::process::abort(); }
}

pub struct LinuxClock(Instant);
impl LinuxClock { pub fn new() -> Self { Self(Instant::now()) } }
impl PlatformClock for LinuxClock {
    fn now_us(&self) -> u64 { self.0.elapsed().as_micros() as u64 }
    fn ptp_ns(&self) -> Option<u64> { None }
}

pub mod setup;
