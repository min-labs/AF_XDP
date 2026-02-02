#![no_std]
extern crate alloc;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::collections::{VecDeque, BTreeMap};
use alloc::format;
// [FIX] Removed unused 'String' import (inferred by compiler)

use log::{info};

use m13_core::{M13Result, M13Header, PacketType, M13_MAGIC};
use m13_core::KYBER_PK_LEN_1024;
use m13_core::KYBER_CT_LEN_1024;

use m13_hal::{PhysicalInterface, SecurityModule, PlatformClock, PeerAddr};
use m13_mem::{SlabAllocator, FrameLease};
use m13_cipher::{M13Cipher, SessionKey};
use m13_pqc::{KyberKeypair, kyber_encapsulate, kyber_decapsulate, dsa_sign, DsaKeypair};
use m13_raptor::{FountainEncoder, FountainDecoder};
use m13_flow::Pacer;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub mod fragment;
pub mod session;
use session::Session;

const BATCH_SIZE: usize = 64;
const MAX_PAYLOAD_SIZE: usize = 1280;

fn is_allowed(addr: &PeerAddr) -> bool {
    match addr {
        PeerAddr::V4(_, _) => true, 
        _ => false,
    }
}

fn parse_ipv4_headers(packet: &[u8]) -> Option<(u32, u32)> {
    if packet.len() < 20 { return None; }
    if packet[0] >> 4 != 4 { return None; }
    let src = u32::from_be_bytes(packet[12..16].try_into().ok()?);
    let dst = u32::from_be_bytes(packet[16..20].try_into().ok()?);
    Some((src, dst))
}

// [DEBUG] Logging Function
fn log_packet_debug(direction: &str, peer: Option<PeerAddr>, data: &[u8]) {
    let len = data.len();
    let type_str = if let Ok(h) = M13Header::from_bytes(data) {
        let pt = h.packet_type;
        let sid = h.symbol_id;
        format!("{:?} ID:{:x}", pt, sid)
    } else {
        "RAW".into()
    };

    // [DEBUG] Only log control packets or small data to avoid spamming
    if len < 200 { 
         info!(">>> [{}] Peer: {:?} | Type: {} | Len: {}", direction, peer, type_str, len);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KernelConfig {
    pub is_hub: bool,
    pub enable_encryption: bool,
}

pub struct M13Kernel {
    phy: Box<dyn PhysicalInterface>,
    #[allow(dead_code)]
    sec: Box<dyn SecurityModule>,
    clock: Box<dyn PlatformClock>,
    mem: Arc<SlabAllocator>,
    
    config: KernelConfig,
    rng: ChaCha20Rng,
    identity: DsaKeypair,

    sessions: BTreeMap<PeerAddr, Session>,
    routes: BTreeMap<u32, PeerAddr>,

    node_target: Option<PeerAddr>,
    pending_kyber: Option<KyberKeypair>,

    rx_batch_cache: Vec<FrameLease>, 

    pub tun_tx_queue: VecDeque<Vec<u8>>, 
    pub tun_rx_queue: VecDeque<Vec<u8>>,
    
    last_handshake_tx: u64,

    pacer: Pacer,
    
    // [FIX] Suppress Dead Code warnings for RaptorQ (Future Sprints)
    #[allow(dead_code)]
    data_encoder: Option<(FountainEncoder, u32, Option<PeerAddr>)>, 
    #[allow(dead_code)]
    data_decoders: BTreeMap<u16, FountainDecoder>,
    #[allow(dead_code)]
    next_data_gen_id: u16,
}

impl M13Kernel {
    pub fn new(
        phy: Box<dyn PhysicalInterface>,
        mut sec: Box<dyn SecurityModule>,
        clock: Box<dyn PlatformClock>,
        mem: Arc<SlabAllocator>,
        config: KernelConfig,
        identity: DsaKeypair,
    ) -> Self {
        let mut seed = [0u8; 32];
        let _ = sec.get_random_bytes(&mut seed);
        let rng = ChaCha20Rng::from_seed(seed);

        info!(">>> [KERNEL] v0.3.5: DEBUG MODE ENABLED <<<");

        Self {
            phy, sec, clock, mem, config, identity,
            rng,
            sessions: BTreeMap::new(),
            routes: BTreeMap::new(),
            node_target: None,
            pending_kyber: None,
            rx_batch_cache: Vec::with_capacity(BATCH_SIZE),
            tun_tx_queue: VecDeque::new(),
            tun_rx_queue: VecDeque::new(),
            last_handshake_tx: 0,
            
            pacer: Pacer::new(1_000_000_000), 
            data_encoder: None,
            data_decoders: BTreeMap::new(),
            next_data_gen_id: 1,
        }
    }

    pub fn send_payload(&mut self, data: &[u8]) -> M13Result<()> {
        if self.tun_tx_queue.len() < 2048 {
            self.tun_tx_queue.push_back(data.to_vec());
            Ok(())
        } else {
            self.tun_tx_queue.pop_front();
            self.tun_tx_queue.push_back(data.to_vec());
            Ok(())
        }
    }

    pub fn pop_ingress(&mut self) -> Option<Vec<u8>> {
        self.tun_rx_queue.pop_front()
    }

    pub fn poll(&mut self) -> bool {
        let now = self.clock.now_us();
        let mut work_done = false;

        if !self.config.is_hub {
            let mut session_alive = false;
            for (_, session) in self.sessions.iter() {
                if session.cipher.is_some() {
                    session_alive = true;
                }
            }
            if !session_alive {
                if now.saturating_sub(self.last_handshake_tx) > 2_000_000 {
                    info!("Client: Initiating Handshake (Cold Start)...");
                    self.initiate_handshake(self.node_target);
                    self.last_handshake_tx = now;
                    work_done = true;
                }
            }
        }

        let mut batch = core::mem::take(&mut self.rx_batch_cache);
        while batch.len() < BATCH_SIZE {
            if let Some(lease) = self.mem.alloc() { batch.push(lease); }
            else { break; }
        }

        if !batch.is_empty() {
            let mut ptrs: Vec<&mut [u8]> = batch.iter_mut()
                .map(|lease| &mut lease.data[..])
                .collect();
            
            let mut meta = alloc::vec![(0, PeerAddr::None); ptrs.len()];

            if let Ok(n) = self.phy.recv_batch(&mut ptrs, &mut meta) {
                if n > 0 {
                    work_done = true;
                    for (i, mut lease) in batch.drain(0..n).enumerate() {
                        let (len, src) = meta[i];
                        lease.len = len;
                        
                        // [DEBUG] LOGGING ENABLED
                        log_packet_debug("RX", Some(src), &lease.data[..len]);

                        if self.config.is_hub && !is_allowed(&src) {
                             // Blocked
                        } else {
                             self.handle_packet(lease, src, now); 
                        }
                    }
                }
            }
        }
        self.rx_batch_cache = batch;
        self.pacer.tick(now);

        if self.config.is_hub || !self.sessions.is_empty() {
            if self.data_encoder.is_some() {
                self.pump_liquid_data();
                work_done = true;
            } 
            else {
                let segment_size = 1350u16; 
                let mut gso_buffer = Vec::with_capacity(64000);
                let mut current_target: Option<PeerAddr> = None;
                
                let mut count = 0;
                while count < 64 {
                    if let Some(payload) = self.tun_tx_queue.pop_front() {
                        let target_peer = if self.config.is_hub {
                             if let Some((_, dest_vip)) = parse_ipv4_headers(&payload) {
                                self.routes.get(&dest_vip).cloned()
                             } else { None }
                        } else {
                             self.node_target
                        };

                        if let Some(target) = target_peer {
                            if let Some(curr) = current_target {
                                if curr != target {
                                    self.phy.send_gso(&gso_buffer, Some(curr), segment_size).ok();
                                    gso_buffer.clear();
                                    current_target = Some(target);
                                }
                            } else {
                                current_target = Some(target);
                            }
                            
                            if let Some(session) = self.sessions.get(&target) {
                                if let Some(cipher) = &session.cipher {
                                    let mut offset = 0;
                                    let total = payload.len();

                                    while offset < total {
                                        let end = core::cmp::min(offset + MAX_PAYLOAD_SIZE, total);
                                        let slice = &payload[offset..end];
                                        let slice_len = slice.len();

                                        let mut packet_buf = alloc::vec![0u8; 32 + slice_len];
                                        let mut header = M13Header {
                                            magic: M13_MAGIC, version: 1, packet_type: PacketType::Data,
                                            gen_id: 0, symbol_id: 0, payload_len: slice_len as u16,
                                            recoder_rank: 0, reserved: 0, auth_tag: [0; 16]
                                        };
                                        
                                        packet_buf[32..].copy_from_slice(slice);
                                        
                                        if let Ok(tag) = cipher.encrypt_detached(&header, &mut packet_buf[32..]) {
                                            header.auth_tag = tag;
                                            header.to_bytes(&mut packet_buf[0..32]).ok();
                                            gso_buffer.extend_from_slice(&packet_buf);
                                        }
                                        offset += MAX_PAYLOAD_SIZE;
                                    }
                                }
                            }
                        }
                    } else { break; }
                    count += 1;
                }
                
                if !gso_buffer.is_empty() {
                    if let Some(curr) = current_target {
                        // [DEBUG] Log Outgoing GSO
                        // log_packet_debug("TX-GSO", Some(curr), &gso_buffer);
                        self.phy.send_gso(&gso_buffer, Some(curr), segment_size).ok();
                        work_done = true;
                    }
                }
            }
        }
        work_done
    }

    fn pump_liquid_data(&mut self) {
    }

    fn handle_packet(&mut self, mut frame: FrameLease, peer: PeerAddr, now: u64) {
        if let Ok(header) = M13Header::from_bytes(&frame.data[0..32]) {
            let payload_len = header.payload_len as usize;
            if frame.len < 32 + payload_len { return; }
            let payload = &mut frame.data[32..32+payload_len];

            if !self.sessions.contains_key(&peer) {
                if self.config.is_hub && header.packet_type == PacketType::ClientHello {
                    info!("New Peer Detected: {:?}", peer);
                    self.sessions.insert(peer, Session::new(now));
                } else if !self.config.is_hub {
                    if self.sessions.is_empty() {
                        self.sessions.insert(peer, Session::new(now));
                        self.node_target = Some(peer);
                    }
                } else { return; }
            }

            let session = self.sessions.get_mut(&peer).unwrap();
            let rng = &mut self.rng;
            let identity = &self.identity;
            let mem = &self.mem;
            let phy = &mut *self.phy;
            let pending_kyber = &mut self.pending_kyber;
            let routes = &mut self.routes;
            let is_hub = self.config.is_hub;

            match header.packet_type {
                PacketType::ClientHello => {
                    if is_hub {
                        if let Ok(Some(full_data)) = session.assembler.ingest(payload) {
                            session.last_valid_rx_us = now;
                            Self::process_client_hello(rng, identity, mem, phy, session, &full_data, peer);
                        }
                    }
                },
                PacketType::HandshakeInit => {
                    if !is_hub {
                        if let Ok(Some(full_data)) = session.assembler.ingest(payload) {
                            session.last_valid_rx_us = now;
                            Self::process_server_hello(session, &full_data, pending_kyber);
                        }
                    }
                },
                PacketType::Coded | PacketType::Data => {
                    if let Some(cipher) = &session.cipher {
                        if cipher.decrypt_detached(&header, payload).is_ok() {
                            session.last_valid_rx_us = now;
                            if is_hub {
                                if let Some((src_vip, _)) = parse_ipv4_headers(payload) {
                                    routes.insert(src_vip, peer);
                                }
                            }
                            self.tun_rx_queue.push_back(payload.to_vec());
                        }
                    }
                },
                _ => {}
            }
        }
    }

    fn initiate_handshake(&mut self, target: Option<PeerAddr>) {
        if let Ok(kp) = KyberKeypair::generate(&mut self.rng) {
            let mut payload = Vec::new();
            payload.extend_from_slice(&kp.public);
            
            if let Some(t) = target {
                let mut s = Session::new(0);
                s.ephemeral_key = Some(kp);
                self.sessions.insert(t, s);
            } else {
                self.pending_kyber = Some(kp);
            }
            Self::send_fragmented(&self.mem, &mut *self.phy, PacketType::ClientHello, &payload, target);
        }
    }

    fn process_client_hello(
        rng: &mut ChaCha20Rng,
        identity: &DsaKeypair,
        mem: &Arc<SlabAllocator>,
        phy: &mut dyn PhysicalInterface,
        session: &mut Session,
        payload: &[u8], 
        peer: PeerAddr
    ) {
        if payload.len() < KYBER_PK_LEN_1024 { return; }
        let pk = &payload[0..KYBER_PK_LEN_1024];
        info!("Handshaking with {:?}", peer);
        
        if let Ok((ct, ss)) = kyber_encapsulate(pk, rng) {
            let sig = dsa_sign(&ct, &identity.secret);
            let mut resp = Vec::new();
            resp.extend_from_slice(&ct);
            resp.extend_from_slice(&sig);
            session.cipher = Some(M13Cipher::new(&SessionKey(ss)));
            info!("Session Established with {:?}", peer);
            Self::send_fragmented(mem, phy, PacketType::HandshakeInit, &resp, Some(peer));
        }
    }

    fn process_server_hello(session: &mut Session, payload: &[u8], pending_key: &mut Option<KyberKeypair>) {
        if let Some(kp) = pending_key.take() {
            if payload.len() < KYBER_CT_LEN_1024 { return; }
            let ct = &payload[0..KYBER_CT_LEN_1024];
            if let Ok(ss) = kyber_decapsulate(&kp, ct) {
                session.cipher = Some(M13Cipher::new(&SessionKey(ss)));
                info!(">>> [NODE] v0.3.0: SECURE LINK ESTABLISHED (PQC+FEC Active).");
            }
        }
    }

    fn send_fragmented(
        mem: &Arc<SlabAllocator>, 
        phy: &mut dyn PhysicalInterface, 
        ptype: PacketType, 
        payload: &[u8], 
        target: Option<PeerAddr>
    ) {
        const CHUNK_SIZE: usize = 1000;
        let total_len = payload.len();
        let mut offset = 0;

        while offset < total_len {
            let end = core::cmp::min(offset + CHUNK_SIZE, total_len);
            let chunk = &payload[offset..end];
            let chunk_len = chunk.len();

            if let Some(mut lease) = mem.alloc() {
                let mut frag_payload = Vec::with_capacity(4 + chunk_len);
                frag_payload.extend_from_slice(&(total_len as u16).to_be_bytes());
                frag_payload.extend_from_slice(&(offset as u16).to_be_bytes());
                frag_payload.extend_from_slice(chunk);

                let header = M13Header {
                    magic: M13_MAGIC, version: 1, packet_type: ptype,
                    gen_id: 0, symbol_id: 0, payload_len: frag_payload.len() as u16,
                    recoder_rank: 0, reserved: 0, auth_tag: [0; 16]
                };
                
                lease.data[32..32+frag_payload.len()].copy_from_slice(&frag_payload);
                if header.to_bytes(&mut lease.data).is_ok() {
                    let packet_data = &lease.data[..32+frag_payload.len()];
                    // log_packet_debug("TX-FRAG", target, packet_data);
                    let _ = phy.send(packet_data, target);
                }
            }
            offset += chunk_len;
        }
    }
}
