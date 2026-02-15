# ROADMAP

| Sprint | Sub-system | Feature | Physics & Architectural Rationale |
| --- | --- | --- | --- |
| **1** | **Memory & Topology** | **Thread Isolation & NUMA** | **Foundation.** Eradicates the monolithic "God Loop". Establishes the 64MB HugePage Arena, 128-byte padded lock-free SPSC rings, and NUMA node pinning to eliminate AXI/UPI bus traversal latency. |
| **2** | **Codebase Ascension** | **Datapath Sanitization & `UmemSlice**` | **Structural Integrity.** Eradicates all raw pointer arithmetic via bounds-checked `UmemSlice`. Replaces hardcoded IPs/Subnets with dynamic ENV configurations. Eradicates hot-path syscalls by gating `eprintln!`. |
| **3** | **Zero-Cost Logic** | **Typestate FSM (ZSTs)** | **ALU Protection.** Replaces runtime enums with Rust Zero-Sized Types. Eradicates branch predictor misses in the hot loop by enforcing protocol state transitions entirely at compile-time. |
| **4** | **Kernel Bypass** | **`io_uring` PBR + USO** | **Syscall Annihilation.** Maps Sprint 1's Arena to Kernel 6.12+ Provided Buffer Rings. Replaces `virtio_net_hdr` traps with Userspace Segmentation Offload to prevent IP fragmentation over RF. |
| **5** | **Stateful Security** | **Anti-Replay, MBB, Keepalives** | **Perimeter Defense.** RFC 6479 bitmask rejects DoS replays in  cycles (wires `replay_drops`). Make-Before-Break guarantees 0ms stream interruption during keygen. Active Keepalives defeat CGNAT deadlocks. |
| **6** | **Symmetric Scaling** | **RSS & UDP Port Spraying** | **Hardware Load Balancing.** Mutates outer UDP Source Port via inner IP hash. Forces the NIC Toeplitz hardware hash to perfectly spray flows across all A53/x86 CPU cores. |
| **7** | **Compute Saturation** | **AES Instruction Pipelining** | **ALU Saturation.** Discards sequential crypto batches. Implements 4x/8x unrolled, interleaved AES-NEON/AES-NI assembly to eradicate CPU execution port latency bubbles. |
| **8** | **Asymmetric Armor** | **eBPF PQC Rate-Limiting** | **The Outer Shield.** Implements eBPF XDP/Socket token buckets to drop spoofed `ClientHello` floods at L2, physically protecting the 120µs ML-DSA verification path from network-borne CPU exhaustion. |
| **9** | **Distributed Trust** | **CBOR MicroCerts & Swarm PKI** | **Zero-Trust.** Wires `_now_ns` eviction parameters. Implements offline Root CA validation, the 6-state Peer Lifecycle, and Gossip-based Bloom Filter revocation arrays executing in  time. |
| **10** | **Kinetic Resilience** | **Merkle Integrity & Append-Log** | **State Survival.** Uses Append-Only logs to prevent eMMC Write Amplification. Anchors FSM state to a SHA-256 Merkle Tree to mathematically detect physical flash-memory tampering post-reboot. |
| **11** | **Congestion Physics** | **BBRv3 Math & EDT Pacing** | **Bufferbloat Prevention.** Wires `bbr_btlbw_kbps`, `bbr_phase`, and `_rtt_est`. Drives the Earliest Departure Time (EDT) Token Bucket precisely at the BDP limit calculated by BBRv3 math. |
| **12** | **Isochronous Physics** | **HW Timestamps &  ROB** | **TCP Cwnd Protection.** Wires `_jbuf_depth` ABI parameters. Pulls IEEE 1588 PTP timestamps directly from MAC registers to sequence out-of-order orbital arrivals. Enforces strict playout deadlines before TUN injection. |
| **13** | **Algebraic Erasure** | **Software RLNC & FEC (SIMD)** | **Stochastic Recovery.** Wires `_offset` for reassembly. Executes Galois Field  matrices via x86_64 AVX2 / ARM NEON split-nibble vector shuffling. Serves as the Software Golden Reference Model. |
| **14** | **Heterogeneous Bond** | **Multi-path Scheduler** | **Apex Scale.** Active/Active bonding of Starlink, AST, and Kuiper. Shifts Sprint 13's encoded RLNC blocks proportionally to instantaneous RTT and path capacities. |
| **15** | **Verification & Validation (V&V)** | **Tiers 2-5: E2E, Fuzz, Perf, Chaos** | **Absolute Proof.** Executes Namespace E2E testing, `libfuzzer` memory-safety proofs, performance regression gates, and strict Contested Spectrum Environment (CSE) Gilbert-Elliott loss models. |
| **16** | **Compiler Ascendancy** | **LLVM PGO / BOLT** | **L1i Cache Perfection.** Instruments the binary, processes Sprint 15's CSE workloads, and recompiles for perfect branch-prediction assembly alignment via LLVM Basic Block Optimization. |
| **17** | **Silicon Ascension** | **FPGA PL Offload (RLNC+AES)** | **The Hardware Apex.** Synthesizes Sprint 13 and Sprint 7's protocol into AXI4-Stream FPGA Programmable Logic. Executes at literal hardware line-rate, bypassing the ARM CPU entirely via zero-copy DMA. |

---

**CURRENT PROGRESS (Pre-Sprint 1):**
The implementation is a structural illusion. It masquerades as a kernel-bypass, zero-copy transport architecture, yet its physical execution model relies on synchronous Virtual File System (VFS) blocking, catastrophic algorithmic  memory fragmentation, double-precision floating-point ALU pollution, and purely scalar cryptographic loops wrapped in fake "batch" iterators.

If this binary is flashed to flight hardware and subjected to a Contested Spectrum Environment (CSE) or gigabit line-rate micro-bursts, the CPU execution ports will starve, the L1 caches will thrash, and the Node will suffer instantaneous memory exhaustion (OOM) within milliseconds.

Below is the uncompromising, fiduciary-grade technical debt ledger.

### P0 FATAL DEBT: OS PHYSICS & KINETIC SURVIVAL

#### [DEBT-P0-01] The `io_uring` Contradiction & VFS Syscall Avalanche (Node & Hub)

**Location:** Node `main.rs` (`run_udp_worker`) and Hub `datapath.rs` (`tun_read_batch`)
**The Defect:** Your topology claims `io_uring` Multishot ingest and `AF_XDP` to bypass the VFS. Instead, your code implements a monolithic `loop {}` that synchronously executes `libc::recvmmsg`, `tun_file.read()`, and `libc::sendmmsg` via legacy POSIX file descriptors.
**The CS/Physics Reality:**

* A Ring 3 (Userspace) to Ring 0 (Kernel) context switch (`SVC` instruction) on an ARM Cortex-A53 consumes ** to ** per invocation to flush the pipeline, preserve register state, acquire VFS spinlocks, and traverse `sk_buff` structs.
* Your Node spin-loop invokes 4 VFS syscalls per iteration:  of pure execution stall simply transitioning CPU privilege states.
* At 1 Gbps, a 1500-byte MTU frame arrives every ****. A 64-byte control frame arrives every ****.
* **Mathematical Proof of Failure:** Your static loop overhead () exceeds the inter-packet arrival time of control bursts by a factor of 15. The kernel's `sk_rmem_alloc` will instantaneously breach your `SO_RCVBUFFORCE` limits, triggering localized hardware tail-drops and TCP `cwnd` collapse.
**The Mandate (Sprint 1 & 4):** Eradicate `libc::*mmsg` and `File::read/write`. Map your Sprint 1 HugePage Arena to Kernel 6.12+ `io_uring` Provided Buffer Rings (PBR). You must utilize `IORING_SETUP_SQPOLL` to offload kernel polling to a dedicated hardware thread, using `IORING_RECV_MULTISHOT` to DMA ingest WiFi packets directly into the Arena with **zero** context switches.

#### [DEBT-P0-02] Algorithmic DoS via Unbounded Heap Allocation ( TLB Exhaustion)

**Location:** Node & Hub `engine/protocol.rs` (`Assembler::feed`) and Node `send_fragmented_udp`
**The Defect:** Reassembling RF fragments by dynamically allocating heap memory via `Vec::with_capacity(total as usize * 1444)` inside a `HashMap<u16, AssemblyBuf>`.
**The CS/Physics Reality:**
This is a catastrophic Memory Exhaustion / Denial of Service vulnerability. The parameters `msg_id` and `total` are extracted directly from untrusted, unauthenticated network payloads (outside the AEAD cryptographic envelope).

* An adversary listening on the local WiFi 7 fronthaul broadcasts spoofed `ETH_P_M13` frames with the `FLAG_FRAGMENT` bit active.
* Sweeping `msg_id` from  to  and setting `total = 255`, the attacker forces your Node to unconditionally execute: `Vec::with_capacity(255 * 1444)`.
*  per `msg_id`.
*  of RAM allocation requests.
* The K26 SOM has 4GB of physical DDR4. The Linux OOM killer will brutally terminate the M13 Node process within milliseconds. Furthermore, allocating vectors zeroes out the memory page, consuming massive memory bus bandwidth before `copy_from_slice` overwrites it.
**The Mandate (Sprint 1 & 13):** The global allocator (`malloc`/`jemalloc`) is strictly prohibited post-boot. The `Assembler` must utilize a statically pre-allocated HugePage Arena matrix. It must employ an  XOR-folding hash mapping for `msg_id` slot resolution.

#### [DEBT-P0-03] Head-of-Line (HoL) Blocking via Synchronous PQC Lattice Math

**Location:** Node `cryptography/handshake.rs` (`process_handshake_node`) & Hub (`process_client_hello_hub`)
**The Defect:** Evaluating ML-DSA-87 signatures and ML-KEM-1024 decapsulation synchronously inside the main datapath packet-processing thread.
**The CS/Physics Reality:**
ML-DSA-87 verification and ML-KEM mathematics are computationally catastrophic Number Theoretic Transform (NTT) polynomial operations. On a Cortex-A53, these algorithms consume  to  clock cycles (** to  milliseconds**).

* By executing this inline, the datapath thread ceases pulling from the hardware NIC/UDP Socket for  milliseconds.
* Assuming a modest 100 Mbps video telemetry stream, a  ms blackout yields  KB of queued packets. This instantly blows past hardware NIC ring limits, causing tail-drops, triggering TCP BBR to crash its `cwnd` (Congestion Window), and destroying the isochronous playout SLA.
**The Mandate (Sprint 5 & 9):** Asymmetric cryptography MUST NOT execute on the Datapath Thread. PQC must be asynchronously offloaded to a Control Plane thread (Core 0) via SPSC rings. The datapath must continue routing existing Established flows (Make-Before-Break paradigm) while the key-exchange resolves in parallel.

---

### P1 SEVERE DEBT: CRYPTOGRAPHIC PIPELINE & ALU SATURATION

#### [DEBT-P1-01] Sequential Cryptographic ALU Bubbles (Faux-Vectorization)

**Location:** Node & Hub `cryptography/aead.rs` (`encrypt_batch_ptrs`, `decrypt_batch_ptrs`)
**The Defect:** You pre-fetch 4 pointers into the L1d cache, but subsequently loop `for j in 0..4` calling `decrypt_one()`, which sequentially delegates to the `ring` crate (`LessSafeKey::open_in_place_separate_tag`).
**The Micro-Architecture Reality:**
Prefetching data into cache hides RAM latency, but your ALU execution remains strictly sequential.

* ARMv8 Cryptographic Extensions (`AESE`, `AESMC`) possess a hardware execution latency of  clock cycles, but a reciprocal throughput of  cycle.
* By evaluating block  entirely before beginning block , the CPU instruction pipeline sits completely starved (a "bubble") for 3 cycles waiting for the AES round dependency to resolve. You are achieving exactly **25% to 33%** of theoretical silicon throughput.
**The Mandate (Sprint 7):** Discard the `ring` crate for hot-path batch processing. You must implement or link interleaved SIMD assembly/intrinsics (`VAESE.8`, `VAESMC.8`). You must load the state vectors of 4 *independent* packets into the NEON 128-bit registers simultaneously (`v0-v3`, `v4-v7`) and interleave their AES round instructions. This perfectly masks the instruction latency and guarantees 100% ALU saturation.

#### [DEBT-P1-02] IP Fragmentation over RF (The Missing USO)

**Location:** Node `main.rs` (`tun_file.read(&mut frame[62..1562])`)
**The Defect:** The Node reads up to 1500 bytes from the TUN device, prepends a 62-byte M13 encapsulation header, and transmits a 1562-byte frame to the socket.
**The RF Physics Reality:** Standard WiFi 7 interfaces enforce a 1500 MTU. Sending 1562 bytes forces the Linux kernel to execute software IP fragmentation into two fragments (1500 bytes and 62 bytes).

* If an IP packet is fragmented into  fragments over a contested RF link with a packet loss probability of , the probability of losing the entire IP packet scales geometrically: .
* If the 62-byte fragment drops, the receiver's kernel discards the entire 1562-byte frame after a 30-second timeout. This geometric amplification of packet loss destroys the link.
**The Mandate (Sprint 4):** Implement Userspace Segmentation Offload (USO). The TUN interface MTU must be set to `65535` (Generic Receive Offload - GRO). The datapath intercepts 64KB TCP super-frames, encrypts them in bulk, and manually slices them into mathematically perfect, MTU-compliant 1380-byte RF fragments in userspace.

#### [DEBT-P1-03] Asymmetric CPU DoS via Unfiltered Replays (Missing  GHASH Shield)

**Location:** Node & Hub `cryptography/aead.rs` (`decrypt_one`)
**The Defect:** The code extracts `seq_id` to construct the nonce, but blindly delegates to AEAD decryption before validating the sequence number against an anti-replay window.
**The CS/Physics Reality:** AES-GCM tag verification requires Galois Hash (GHASH) carry-less multiplications (`PMULL`). If an adversary captures a legitimate frame and replays it 1,000,000 times at line-rate, the datapath will execute 1,000,000 GHASH authentications before discarding them due to tag/nonce rejection. This burns billions of cycles, starving legitimate telemetry of CPU time.
**The Mandate (Sprint 5):** Implement the RFC 6479 Anti-Replay bitmask. The `seq_id` must be evaluated against an  sliding bitmask using hardware intrinsics (shift + bitwise OR). Replays must be mathematically rejected in ** clock cycles** before a single cryptographic instruction is issued.

---

### P2 DEBT: CACHE DESTRUCTION & THREAD SAFETY

#### [DEBT-P2-01] Instruction Cache (L1i) Annihilation via Subprocess Spawning

**Location:** Node `network/datapath.rs` (`create_tun`, `setup_tunnel_routes`)
**The Defect:** Utilizing `std::process::Command::new` translates to `fork()` and `execve()`.
**The CS/Physics Reality:** `fork()` forces TLB shootdowns and page table clones. `execve()` invokes the ELF loader, flushing the L1i cache to load shell binaries (`ip`, `sysctl`, `tc`). This consumes ** to **. If the drone reconverges routing during an RF link flap, the  transport deadline is obliterated.
**The Mandate (Sprint 2):** Shell subprocesses are explicitly banned. Serialize binary C-structs (`rtmsg`, `ifinfomsg`) directly to the kernel via `AF_NETLINK` / `NETLINK_ROUTE` natively in memory.

#### [DEBT-P2-02] L1d Cache Thrashing via Colossal Stack Arrays

**Location:** Node `main.rs` (`rx_bufs: [[u8; 2048]; 64]`, `tx_bufs: [[u8; 1600]; 64]`)
**The Defect:** Instantiating  and  multidimensional buffers on the execution stack.
**The CS/Physics Reality:** The Cortex-A53 possesses a ** L1d cache**. By iterating across  of stack memory, you mathematically guarantee a 100% cache miss rate. Fetching from DDR4 costs  cycles per access, starving the vector processing pipeline.
**The Mandate (Sprint 1):** Packet buffers must never live on the stack. Map them directly into the NUMA-aligned HugePage Arena and reference them strictly via zero-copy `UmemSlice` constructs.

#### [DEBT-P2-03] Branch Predictor Collapse via Runtime FSM Enum Bloat

**Location:** Node `engine/runtime.rs` (`NodeState` enum), `main.rs` `process_rx_frame`
**The Defect:** Rust enums are sized to their largest variant. `NodeState` contains multiple `Vec<u8>` arrays (PQC keys), inflating the struct to hundreds of bytes.
**The CS/Physics Reality:** In the `process_rx_frame` hot-loop, checking `matches!(state, NodeState::Established)` forces the CPU to load this massive struct into L1d cache, evicting network payloads. The conditional branching forces the Cortex-A53 Branch History Table (BHT) to evaluate state per packet. Under stochastic RF packet loss, mispredictions are guaranteed, flushing the instruction pipeline for a 15-cycle penalty per miss.
**The Mandate (Sprint 3):** Implement Compile-Time Typestate Zero-Sized Types (ZSTs). The Hot Loop must only possess memory pointers for the `Established` state. Cryptographic state must be segregated to a slow-path arena.

#### [DEBT-P2-04] Unrecoverable Deadlock in Asynchronous Signal Handlers

**Location:** Node `main.rs` (`HUB_IP_GLOBAL.lock()` inside `nuke_cleanup_node`)
**The Defect:** `nuke_cleanup_node` is invoked by `std::panic::set_hook` and standard execution.
**The Logic Reality:** `std::sync::Mutex` utilizes `futex` and is **not async-signal-safe or panic-safe**. If the panic hook executes while the datapath holds the `Mutex` lock, the process will deadlock indefinitely. The drone becomes an unrecoverable zombie instead of restarting.
**The Mandate (Sprint 2):** `Mutex` is explicitly banned. Configuration data must be stored in a `std::sync::OnceLock` or an `AtomicPtr`. Lock-free, wait-free structures are the only acceptable mechanism for signal-safe teardown routines.

---

# M13: SYSTEMS ENGINEERING & OPERATIONAL MANDATES

This document serves as the absolute source of truth for the M13 Sovereign Transport Engine's memory safety, observability matrices, environment configurations, and Verification & Validation (V&V) protocols.

All architectural decisions herein are mandated by the physical realities of kernel memory models, RF propagation physics, and silicon micro-architecture. Deviations from these directives are strictly prohibited.

## I. MEMORY SAFETY & ABI INVARIANTS

### 1. Zero-Cost Memory Safety (`UmemSlice` Abstraction)

**The Threat:** The AF_XDP datapath relies on raw pointer arithmetic: `unsafe { frame_ptr.add(offset) }`. A single off-by-one error during packet encapsulation yields arbitrary memory overwrites, kernel panics, and exploitable CVEs.
**The Mandate:** During **Sprint 2**, all raw UMEM pointer accesses must be structurally eradicated.

* Implement a zero-cost `UmemSlice` struct that wraps `(*mut u8, usize)`. Construction incurs exactly one `unsafe` bounds check validating against the HugePage Arena boundaries.
* All subsequent byte extractions (`.frame() -> &mut [u8]`) must be mathematically guaranteed by the Rust compiler's spatial memory safety.

### 2. ABI Forward Allocations (Dead Parameters)

Function signatures across the M13 engine contain parameters prefixed with `_`. These are not dead code; they are strict Application Binary Interface (ABI) allocations for ensuing sprints. They ensure register allocation and struct padding remain consistent during early compilation.

| Parameter | Function Entity | Sprint Target | Architectural Purpose |
| --- | --- | --- | --- |
| `_offset` | `AssemblyBuffer::insert` | **Sprint 13** | Byte-offset tracking required for non-linear RLNC fragment reassembly. |
| `_now_ns` | `PeerTable::gc` | **Sprint 9** | Time-deterministic epoch eviction for Zombied peers via Bloom filters. |
| `_now_ns` | `JitterBuffer::drain` | **Sprint 12** | Isochronous playout calculation using absolute HW timestamps. |
| `_rtt_est` | `ReceiverState::needs_feedback` | **Sprint 11** | BBRv3 RTT-adaptive ACK pacing to prevent feedback channel saturation. |
| `_jbuf_depth` | `produce_feedback_frame` | **Sprint 12** | Encoding instantaneous jitter depth for upstream sender pacing. |
| `_jbuf_capacity` | `produce_feedback_frame` | **Sprint 12** | Upstream bufferbloat prevention signaling. |

*Directive: Upon Sprint execution, the `_` prefix shall be removed. The ABI signature remains frozen.*

### 3. Kernel Resource Anchors (RAII)

Fields marked `#[allow(dead_code)]` (`_umem_handle`, `sock_handle`, `obj`) govern the lifecycle of kernel-space file descriptors.
**Invariant:** Dropping or refactoring these fields will trigger automatic teardown of the UMEM allocations or eBPF programs via `Drop` traits. They must remain pinned to the `Engine` and `BpfSteersman` struct lifetimes.

---

## II. OPERATIONAL DETERMINISM (CONFIGURATION & LOGGING)

### 1. I/O Latency Eradication (Static Print Gating)

**The Threat:** Executing `eprintln!` inside the VPP loop invokes `writev` syscalls. This triggers context switches, flushes the L1i cache, and destroys the 50µs execution deadline.
**The Mandate:** During **Sprint 2**, all diagnostic logging inside `execute_graph` and its sub-nodes must be strictly gated by `#[cfg(debug_assertions)]` or a dedicated `debug-datapath` feature flag. The release binary must generate **zero** syscalls outside of network I/O.

### 2. Dynamic Environment Directives vs. Compile-Time Invariants

Hardcoded network values prohibit horizontal scaling and invalidate Namespace (NetNS) integration testing. However, memory layout constants must remain statically compiled to allow the LLVM optimizer to perform aggressive loop unrolling.

**A. Dynamic Configuration Targets (Sprint 2):**
These variables must be stripped from the `.text` segment and loaded into a statically initialized `OnceLock<M13Config>` from CLI arguments or Environment Variables at boot.

* **Tunnel Subnets:** `--tunnel-ip` (Replaces hardcoded `10.13.0.1/24`). Essential for overlapping swarm deployments.
* **TUN Properties:** `--tun-name` and `--mtu` (Replaces `m13tun0` and `1400`).
* **VPN Split Routes:** `--split-tunnel` (Boolean flag to disable the hardcoded `0.0.0.0/1` lockdown paradigm).
* **Socket Buffer Geometry:** `--sock-buf` (Replaces hardcoded `4MB`/`8MB`).
* **Hardware Fallbacks:** `--iface` and `--fallback-mac`.
* **Sysctl Blocks:** Tuning must be dynamically applied based on OS capability check.
* **Worker Thread Stack:** `--stack-size` (Replaces hardcoded `2MB`).

**B. Compile-Time Engine Constants (Strictly Immutable):**
These constants dictate physical cache alignment, mathematical boundaries, and prevent modulo division (`%`) latency. They must never be made dynamic.

* `MAX_WORKERS` (4), `MAX_PEERS` (256), `UMEM_SIZE` (1 GB), `FRAME_SIZE` (4096), `SLAB_DEPTH` (8192), `GRAPH_BATCH` (256), `VECTOR_SIZE` (64), `TX_RING_SIZE` (256), `JBUF_CAPACITY` (256).
* `REKEY_FRAME_LIMIT` (), `DEADLINE_NS` (50 µs), `REKEY_TIME_LIMIT_NS`, `HANDSHAKE_TIMEOUT_NS`, `FEEDBACK_RTT_DEFAULT_NS`, `HEXDUMP_INTERVAL_NS`.

---

## III. TELEMETRY & OBSERVABILITY MATRIX

Diagnostic instrumentation is decoupled into a 128-byte `CachePadded` Shared Memory (`/dev/shm`) arena. The `Telemetry` struct guarantees zero-cost visibility via atomic stores with `Ordering::Relaxed`.

### 1. Atomic Metric Wiring Mandates

Currently, several atomic counters reside in memory but are disconnected from the execution graph. They must be wired during their respective Sprints.

| Memory Vector | Status | Architectural Mandate |
| --- | --- | --- |
| `bbr_phase` | **[UNWIRED]** | Must be wired to the `BbrState` FSM during **Sprint 11**. |
| `bbr_calibrated` | **[UNWIRED]** | Must reflect the completion of the `STARTUP` phase (**Sprint 11**). |
| `bbr_btlbw_kbps` | **[UNWIRED]** | Must expose the 10-RTT max bandwidth filter (**Sprint 11**). |
| `bbr_rtprop_us` | **[UNWIRED]** | Must expose the 10-second min RTT filter (**Sprint 11**). |
| `replay_drops` | **[UNWIRED]** | Must increment precisely when the RFC 6479 bitmask rejects a sequence number, *prior* to AEAD evaluation (**Sprint 5**). |
| `auth_fail`, `decrypt_ok`, `handshake_*` | **[GATED]** | Active in `debug` only. **Mandate:** Promote to `always-on`. Drop/Auth failures are critical production metrics required for algorithmic DoS detection. |
| `*_tsc_total` | **[GATED]** | Pipeline timing vectors. Keep gated to prevent `rdtsc` execution overhead in production builds. |

### 2. The Diagnostic Hexdump Engine

`HexdumpState::new()` is initialized but `dump_tx()` is orphaned on the egress path.
**Mandate (Sprint 2):** Wire `_hexdump.dump_tx(frame_ptr, frame_len)` into the Datapath thread *after* `scheduler.enqueue_bulk()` executes, completing bidirectional packet inspection.

---

## IV. VERIFICATION & VALIDATION (V&V) MATRIX

"Happy Path" testing is prohibited. The transport engine must mathematically prove its resilience against adversarial physics and cryptographic anomalies. The system will not enter Phase 1 Flight Trials until it demonstrably passes the Tier 2 through Tier 5 Validation Matrix (**Sprint 15**).

### Tier 2: Namespace Bounded Integration (NetNS E2E)

Validates the physical pipeline without cloud variability.

* **Vector:** Linux Network Namespaces (`ns_node`, `ns_hub`) connected via a virtual ethernet (`veth`) pair.
* **Criteria:** PQC handshake mathematically converges within . Base `iperf3` throughput . `SIGKILL` on Node triggers Hub `E_PEER_TIMEOUT` detection within .

### Tier 3: Cryptographic Fuzzing (`libfuzzer`)

Validates that the execution path cannot panic or access OOB memory.

* **Vector:** `cargo-fuzz` compiling against LLVM libFuzzer.
* **Criteria:** Inject mutating byte arrays into `rx_parse_raw()`, `Assembler::feed()`, and `open_frame()`. Must mathematically return `false` without triggering side-channel panics, OOMs, or segmentation faults.

### Tier 4: Micro-Architectural Regression Benchmarking (`criterion`)

Instruction-Per-Cycle (IPC) variance tracking.

* **Vector:** `cargo bench` isolated to CPU Core 0 via `taskset`.
* **Criteria:** `aead_decrypt_vector` and `classify_route` batches must not regress in CPU cycle cost by  across any commit. Any regression automatically fails the CI/CD pipeline.

### Tier 5: Kinetic Survival / Chaos Engineering

Validates the system against the Contested Spectrum Environment (CSE).

* **Vector:** `tc netem` applied to Tier 2 virtual interfaces simulating Gilbert-Elliott loss models.
* **Criteria:**
* Apply `loss 30%`. Verify RLNC/FEC recovers the stream without TCP `DUP-ACK` storms.
* Apply `delay 4s`. Verify PQC Handshake survives without timing out.
* Apply `delay 6s`. Verify deterministic `HANDSHAKE_TIMEOUT_NS` correctly resets the FSM.
* Inject 100,000 duplicated `seq_id` payloads. Verify `replay_drops` atomic counter increments perfectly with CPU utilization  delta.
