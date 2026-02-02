use std::os::unix::io::RawFd;
use std::ptr;
use libc::*;
use anyhow::{Result, Context};
use crate::umem::{Umem, UMEM_SIZE, FRAME_SIZE};

const SOL_XDP: c_int = 283;
const XDP_UMEM_REG: c_int = 4;

pub struct RingRef { pub producer: *mut u32, pub consumer: *mut u32, pub desc: *mut u8, pub mask: u32 }
unsafe impl Send for RingRef {} unsafe impl Sync for RingRef {}
#[repr(C)] #[derive(Clone, Copy)] pub struct XdpDesc { pub addr: u64, pub len: u32, pub options: u32 }

pub struct XdpSocket {
    pub fd: RawFd, pub umem: std::sync::Arc<Umem>, 
    pub fill_ring: RingRef, pub rx_ring: RingRef, 
    pub tx_ring: RingRef, pub comp_ring: RingRef
}

impl XdpSocket {
    pub unsafe fn new(iface: &str, qid: u32, umem: std::sync::Arc<Umem>) -> Result<Self> {
        let fd = socket(AF_XDP, SOCK_RAW, 0);
        if fd < 0 { return Err(anyhow::Error::from(std::io::Error::last_os_error())).context("Socket creation failed"); }

        let mut reg = [0u8; 32];
        let addr = umem.as_ptr() as u64; let len = UMEM_SIZE as u64; let chunk = FRAME_SIZE as u32;
        reg[0..8].copy_from_slice(&addr.to_ne_bytes());
        reg[8..16].copy_from_slice(&len.to_ne_bytes());
        reg[16..20].copy_from_slice(&chunk.to_ne_bytes());
        
        if setsockopt(fd, SOL_XDP, XDP_UMEM_REG, reg.as_ptr() as *const _, 32) < 0 { 
            let err = std::io::Error::last_os_error();
            close(fd);
            return Err(anyhow::Error::from(err)).context("UMEM Register failed"); 
        }

        let rs = 8192u32;
        for opt in [5, 2, 3, 6] { 
            if setsockopt(fd, SOL_XDP, opt, &rs as *const _ as *const _, 4) < 0 {
                let err = std::io::Error::last_os_error();
                close(fd);
                return Err(anyhow::Error::from(err)).context("Ring Size Set failed");
            }
        }

        let mut off: xdp_mmap_offsets = std::mem::zeroed();
        let mut ol = std::mem::size_of::<xdp_mmap_offsets>() as socklen_t;
        if getsockopt(fd, SOL_XDP, 1, &mut off as *mut _ as *mut _, &mut ol) < 0 {
            let err = std::io::Error::last_os_error();
            close(fd);
            return Err(anyhow::Error::from(err)).context("Get Offsets failed");
        }

        let map = |o: u64, d: u64, p: u64, c: u64, item_size: u64| -> Result<RingRef> {
            let len = (d + (rs as u64 * item_size)) as usize;
            let ptr = mmap(
                ptr::null_mut(), 
                len, 
                PROT_READ | PROT_WRITE, 
                MAP_SHARED | MAP_POPULATE, 
                fd, 
                o as off_t
            );
            if ptr == MAP_FAILED { 
                let err = std::io::Error::last_os_error();
                return Err(anyhow::Error::from(err)).context(format!("Mmap failed for offset 0x{:x}", o)); 
            }
            Ok(RingRef { 
                producer: ptr.offset(p as isize) as *mut u32, 
                consumer: ptr.offset(c as isize) as *mut u32, 
                desc: ptr.offset(d as isize) as *mut u8, 
                mask: rs - 1 
            })
        };

        let fill = map(0x100000000, off.fr.desc, off.fr.producer, off.fr.consumer, 8)?;
        let rx   = map(0,           off.rx.desc, off.rx.producer, off.rx.consumer, 16)?;
        let tx   = map(0x80000000,  off.tx.desc, off.tx.producer, off.tx.consumer, 16)?;
        let comp = map(0x180000000, off.cr.desc, off.cr.producer, off.cr.consumer, 8)?;

        let c_if = std::ffi::CString::new(iface)?;
        let idx = if_nametoindex(c_if.as_ptr());
        
        let mut sa = sockaddr_xdp { 
            sxdp_family: AF_XDP as u16, 
            sxdp_flags: 0, 
            sxdp_ifindex: idx, 
            sxdp_queue_id: qid, 
            sxdp_shared_umem_fd: 0 
        };
        
        // ZeroCopy or Bust (Silent)
        sa.sxdp_flags = (1<<2) | (1<<3);
        if bind(fd, &sa as *const _ as *const _, 16) < 0 {
             sa.sxdp_flags = (1<<1) | (1<<3);
             if bind(fd, &sa as *const _ as *const _, 16) < 0 {
                 let err = std::io::Error::last_os_error();
                 close(fd);
                 return Err(anyhow::Error::from(err)).context("Bind failed");
             }
        }
        
        Ok(Self { fd, umem, fill_ring: fill, rx_ring: rx, tx_ring: tx, comp_ring: comp })
    }
}
