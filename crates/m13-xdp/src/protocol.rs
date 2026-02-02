use std::mem::size_of;

pub const M13_PORT: u16 = 51820; 
// [FIX] Aligned Magic
pub const MAGIC: u32 = 0x4D313300; 

#[repr(C, packed)] #[derive(Clone, Copy, Debug)] 
pub struct EthHeader { pub dst:[u8;6], pub src:[u8;6], pub etype:u16 }

#[repr(C, packed)] #[derive(Clone, Copy, Debug)] 
pub struct Ipv4Header { 
    pub ver_ihl:u8, pub tos:u8, pub len:u16, pub id:u16, 
    pub frag:u16, pub ttl:u8, pub proto:u8, pub check:u16, 
    pub src:u32, pub dst:u32 
}

impl Ipv4Header {
    #[inline(always)]
    pub fn header_len(&self) -> usize { (self.ver_ihl & 0x0F) as usize * 4 }
}

#[repr(C, packed)] #[derive(Clone, Copy, Debug)] 
pub struct UdpHeader { pub src:u16, pub dst:u16, pub len:u16, pub check:u16 }

// [FIX] STRUCT ALIGNMENT
// Must match m13-core EXACTLY to prevent Length corruption
#[repr(C, packed)] #[derive(Clone, Copy, Debug)] 
pub struct M13Header { 
    pub magic: u32,       
    pub version: u8,      
    pub packet_type: u8, 
    pub gen_id: u16,      
    pub symbol_id: u32,   
    pub payload_len: u16, // <--- Correct 16-bit Length
    pub recoder_rank: u8, 
    pub reserved: u8,     
    pub auth_tag: [u8; 16], 
}

// 14 + 20 + 8 + 32 = 74
pub const HEADROOM: usize = size_of::<EthHeader>() + size_of::<Ipv4Header>() + size_of::<UdpHeader>() + size_of::<M13Header>();

pub fn calc_checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    let mut i = 0;
    while i < data.len() - 1 {
        let w = (u16::from(data[i]) << 8) + u16::from(data[i+1]);
        sum = sum.wrapping_add(w as u32);
        i += 2;
    }
    if i < data.len() { sum = sum.wrapping_add((u16::from(data[i]) << 8) as u32); }
    while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !sum as u16
}

pub fn calc_ip_checksum(h: &mut Ipv4Header) {
    h.check = 0;
    let slice = unsafe { std::slice::from_raw_parts(h as *const _ as *const u8, h.header_len()) };
    let c = calc_checksum(slice, 0);
    h.check = c.to_be();
}

pub fn calc_udp_checksum(ip: &Ipv4Header, udp: &mut UdpHeader) {
    udp.check = 0;
    let mut sum = 0u32;
    sum += (u32::from_be(ip.src) >> 16) + (u32::from_be(ip.src) & 0xFFFF);
    sum += (u32::from_be(ip.dst) >> 16) + (u32::from_be(ip.dst) & 0xFFFF);
    sum += 17 + u32::from(u16::from_be(udp.len));
    
    let total_len = u16::from_be(udp.len) as usize;
    let udp_slice = unsafe { std::slice::from_raw_parts(udp as *const _ as *const u8, total_len) };
    
    let c = calc_checksum(udp_slice, sum);
    udp.check = if c == 0 { 0xFFFF } else { c.to_be() };
}
