use std::ffi::CStr;
use std::os::unix::io::{AsRawFd, RawFd};
use libc::*;
use anyhow::{Result, anyhow};
use std::process::Command;

const TUNSETIFF: c_ulong = 0x400454ca;

pub struct TunDevice {
    fd: RawFd,
    #[allow(dead_code)] // [FIX] Suppress warning for stored-but-unread field
    name: String,
}

impl TunDevice {
    pub fn new_hub(tun_name: &str) -> Result<Self> {
        let dev_path = CStr::from_bytes_with_nul(b"/dev/net/tun\0")?;
        
        // [PHYSICS] O_NONBLOCK is critical for VPP Loop
        let fd = unsafe { open(dev_path.as_ptr(), O_RDWR | O_NONBLOCK) };
        if fd < 0 { return Err(anyhow!("Failed to open /dev/net/tun (Root Required)")); }

        #[repr(C)] struct ifreq { ifr_name: [u8; IFNAMSIZ], ifr_flags: c_short }
        let mut ifr: ifreq = unsafe { std::mem::zeroed() };
        
        ifr.ifr_flags = (IFF_TUN | IFF_NO_PI) as c_short;
        
        let bytes = tun_name.as_bytes();
        if bytes.len() >= IFNAMSIZ { return Err(anyhow!("TUN name too long")); }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ifr.ifr_name.as_mut_ptr(), bytes.len()) };

        if unsafe { ioctl(fd, TUNSETIFF, &mut ifr) } < 0 {
            unsafe { close(fd) }; 
            return Err(anyhow!("ioctl(TUNSETIFF) failed. Is the name '{}' taken?", tun_name));
        }

        run_cmd("ip", &["link", "set", "dev", tun_name, "up"])?;
        run_cmd("ip", &["link", "set", "dev", tun_name, "mtu", "1500"])?; 

        Ok(Self { fd, name: tun_name.to_string() })
    }

    pub fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n < 0 { 
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock { return Ok(0); }
            return Err(err);
        }
        Ok(n as usize)
    }

    pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { write(self.fd, buf.as_ptr() as *const c_void, buf.len()) };
        if n < 0 { return Err(std::io::Error::last_os_error()); }
        Ok(n as usize)
    }
}

impl AsRawFd for TunDevice { fn as_raw_fd(&self) -> RawFd { self.fd } }

impl Drop for TunDevice { 
    fn drop(&mut self) { 
        unsafe { close(self.fd); } 
    } 
}

fn run_cmd(p: &str, a: &[&str]) -> Result<()> {
    if !Command::new(p).args(a).output()?.status.success() { 
        Err(anyhow!("Cmd failed: {} {:?}", p, a)) 
    } else { 
        Ok(()) 
    }
}
