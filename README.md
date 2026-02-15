# M13 

**Classification:** Aerospace / High-Frequency Transport (HFT) Grade  
**Target Hardware:** AMD/Xilinx Kria K26 SOM + Zynq UltraScale+ FPGA + Custom PCB  
**Testbench Architecture:** x86_64 (AVX2/AES-NI) for CI/CD and fixed ground-station Hubs  
**Operating System:** AMD Embedded Development Framework (EDF) Yocto Project (Scarthgap 5.0 LTS) / **Linux Kernel 6.12 LTS+**  
> **ARCHITECTURAL MANDATE:** Legacy PetaLinux distributions are explicitly End-of-Life (EOL) and physically incompatible with the M13 datapath. Kernel 6.12+ is a hard architectural requirement to enable `io_uring` Provided Buffer Rings (PBR), `IORING_RECV_MULTISHOT`, and advanced `XDP_REDIRECT` primitives.



## I. System Topology

M13 is a hardware-accelerated control and transport architecture engineered specifically for Beyond Visual Line of Sight (BVLOS) drone operations. It establishes a contiguous, end-to-end datapath between WAN-deprived tactical drone swarms and remote command centers by tightly coupling a localized WiFi 7 fronthaul with a bonded, multipath SATCOM backhaul. 

M13 executes entirely via kernel-bypass (`AF_XDP` and `io_uring`) on isolated CPU cores to strip all Virtual File System (VFS) overhead and provide a deterministic, line-rate transport pipeline. By enforcing zero-trust physical isolation and Post-Quantum Cryptographic (PQC) payload encapsulation, the system guarantees bounded-latency command execution and isochronous telemetry survival in heavily contested RF environments.

* **Hub (LALE Drone):** This module aggregates heterogeneous, asymmetric satellite uplinks (e.g., Starlink, Amazon Kuiper, Eutelsat) into a bonded, multipath-scheduled backhaul. It functions as a “flying telco” that broadcasts a WiFi 7 Access Point (AP) for the localized daughter drones. The Hub executes `AF_XDP` zero-copy packet processing, BBRv3 congestion pacing, and eBPF token buckets at hardware line-rate.
* **Nodes (WAN-deprived Daughter Drone Swarm):** This module comprises of tactical drone swarm lacking inherent Wide Area Network (WAN) hardware interfaces. The Nodes associate with the Hub's WiFi 7 AP, achieving end-to-end connectivity to the User exclusively via the M13 L3 encrypted tunnel over the local WLAN. To bypass VFS overhead in the absence of `AF_XDP` support over `mac80211`, the Node utilizes an `IORING_SETUP_SQPOLL`-configured `io_uring` Multishot ingest, mapping the buffer to a HugePage Arena.
* **User (Command Center):** This constitutes the remote infrastructure connected via a standard Internet Service Provider (ISP). M13 operates strictly at the transport layer, acting as a transparent, opaque IP tunnel that remains entirely agnostic to the L7 application protocols (MAVLink/Video) executing above it.

### Data Flow Physics

**Commands (Downstream - Low Latency, Strict Priority):**
```text
User PC ──Fiber──→ ISP ──Fiber──→ Satellite Constellation ──→ Hub (AF_XDP) ──WiFi 7──→ Node (io_uring)

```

**Telemetry/Video (Upstream - High Throughput, Isochronous):**

```text
Node (FPGA DMA/RLNC) ──WiFi 7──→ Hub (O(1) Re-Order Buffer) ──Multi-Path LEO/MEO──→ Satellite Constellation ──Fiber──→ ISP ──→ User PC

```

---

## II. Source Tree Architecture

The repository enforces strict boundary isolation between the Satellite Aggregator logic (Hub) and the Edge Endpoint logic (Node).

```text
m13/
├── Cargo.toml          ← workspace: [hub, node], release profile (LTO, panic=abort, codegen-units=1)
├── hub/                ← THE HUB (AF_XDP / Satellite Aggregator)
│   ├── build.rs        ← eBPF object compilation & kernel bindgen
│   └── src/
│       ├── main.rs     ← Orchestrator, thread pinning, NUMA alignment
│       ├── engine/
│       │   ├── protocol.rs  → BBRv3 EDT Pacing, O(1) Re-Order Buffer, RLNC Matrix Solvers
│       │   └── runtime.rs   → IEEE 1588 HW Timestamps, CachePadded Telemetry, SPSC Rings
│       ├── network/
│       │   ├── xdp.rs       → AF_XDP engine (1GB UMEM, ZeroCopyTx)
│       │   ├── bpf.rs       → BPF Steersman (XDP_REDIRECT, PQC L2 Rate Limiting)
│       │   └── datapath.rs  → VPP Graph Nodes, Multi-path Scheduler
│       └── cryptography/
│           ├── aead.rs      → AES-256-GCM (AVX2/NEON SIMD Pipelining & FPGA AXI4 DMA)
│           └── handshake.rs → PQC Handshake (ML-KEM-1024, ML-DSA-87, CBOR MicroCerts)
└── node/               ← THE NODE (io_uring / Edge Endpoint)
    ├── build.rs        ← Kernel bindgen
    └── src/
        ├── main.rs     ← Orchestrator, bifurcated thread pinning, HugePage Arena init
        ├── engine/
        │   ├── protocol.rs  → Typestate FSM (ZSTs), Fragment Assembler
        │   └── runtime.rs   → SPSC Rings, UmemSlice memory safety, Merkle Append-Log
        ├── network/
        │   └── datapath.rs  → io_uring Multishot PBR integration, Userspace Segmentation Offload (USO)
        └── cryptography/
            ├── fpga_dma.rs  → AXI4-Stream zero-copy DMA to Zynq UltraScale+ Programmable Logic
            ├── aead.rs      → RFC 6479 Anti-Replay Mask, AES-256-GCM (NEON SIMD Pipelining)
            ├── rlnc.rs      → Algebraic Erasure: GF(2^8) NEON split-nibble shuffle
            └── handshake.rs → PQC Handshake & Active Keepalives

```

> **Why does the Node have no AF_XDP or BPF?**
> The Node connects to the Hub over WiFi 7 — a managed wireless link operating at L3 (IP/UDP). `AF_XDP` requires a raw L2 Ethernet interface with direct NIC queue access, which WiFi does not provide. The Node therefore uses `io_uring` multishot sockets for zero-syscall transport, while the Hub retains `AF_XDP` for wire-speed packet processing on its wired satellite NICs.

---

## III. Phase 0: Silicon Provisioning & Micro-Architecture Isolation

To guarantee zero-context-switch execution, target CPU cores must be mathematically amputated from the Linux Completely Fair Scheduler (CFS), RCU callbacks, and hardware timer interrupts (`nohz_full`).

### Target Flight Hardware: AMD/Xilinx K26 SOM (Hub & Node)

**Silicon Geometry:** The Zynq UltraScale+ MPSoC possesses a **Quad-Core ARM Cortex-A53**.

* **Core 0:** Reserved for Linux Housekeeping (SMMU, VFS locks, SSH, unpinned hardIRQs).
* **Cores 1, 2, 3:** Physically isolated for M13's Net I/O, Datapath, and Crypto threads.
* **Memory:** 4GB total DDR4. We lock 512MB (`hugepages=256`) for the zero-copy Arenas.

**Implementation (Yocto EDF / U-Boot):**
Do not attempt to use `update-grub`. Append the kernel parameters via your Yocto `machine.conf`, Device Tree (`system-user.dtsi`), or dynamically at runtime via `extlinux.conf`.

```bash
# 1. Modify the U-Boot extlinux configuration on the K26 SOM
sudo sed -i '/^[[:space:]]*append/ s/$/ isolcpus=1,2,3 rcu_nocbs=1,2,3 nohz_full=1,2,3 irqaffinity=0 hugepagesz=2M hugepages=256/' /boot/extlinux/extlinux.conf

# 2. Sync filesystem and reboot to apply silicon isolation
sync && sudo reboot

```

> **Verification Post-Reboot:**
> 1. Verify CPU Isolation: `cat /sys/devices/system/cpu/isolated` → Must output exactly `1-3`.
> 2. Verify HugePage allocation: `cat /proc/sys/vm/nr_hugepages` → Must output `256`.
> *If either check fails, the pipeline will fall back to the CFS scheduler and the mission MUST be aborted.*
> 
> 

### Build Dependencies (Run on K26 or Cross-Compile Host)

```bash
# Install Rust HFT Toolchain & Kernel 6.12+ Headers
sudo apt update && sudo apt install -y curl build-essential clang llvm libbpf-dev pkg-config libelf-dev make linux-headers-$(uname -r)
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
rustup default stable && rustup update

```

---

## IV. Phase 1: Build & Execution Chains

M13 abandons monolithic event loops. Both Hub and Node utilize **Vertical Pipelining** via lock-free 128-byte padded SPSC rings to eradicate Head-of-Line (HoL) blocking and isolate the Virtual File System (VFS) from network ingest.

### 1. Hub Execution: AF_XDP + Multi-Path Satellite

```bash
# Build with target-cpu optimizations (AVX2 / ARMv8-CE) and PGO/BOLT profiling
RUSTFLAGS="-C target-cpu=native -C profile-use=merged.profdata" cargo build --release --manifest-path hub/Cargo.toml

# Execute (NUMA-aware, AF_XDP active)
sudo RUST_LOG=info ./target/release/m13-hub --iface enp1s0f0 --tunnel-ip 10.13.0.1/24

```

**The Hub Runtime Graph:**

```text
main()
├── Parse CLI & Dynamic Config → Initialize OnceLock<M13Config>
├── Pre-Flight: NUMA verification (libnuma), HugePage Alloc, IRQ fencing, PMU Lock
├── BPF Steersman: Attach eBPF XDP Object → Load L2 Token Buckets (Drop PQC Floods)
└── Spawn Bifurcated Workers (Pinned to isolated cores 1, 2, 3)
    │
    ├── NET I/O THREAD (Core 1)
    │   ├── Owns AF_XDP UMEM and RX/TX Completion Rings.
    │   └── 100% Spin-Loop: Drains XDP RX → Packs Meta → Pushes to `ingress_ring`.
    │
    └── DATAPATH THREAD (Core 2)
        └── 100% Spin-Loop (Zero VFS Locks):
            ├── 1. Pop `ingress_ring` (Vector Batch)
            ├── 2. Anti-Replay: O(1) RFC 6479 Bitmask evaluation
            ├── 3. FPGA AXI4-Stream DMA: Zero-copy AES-256-GCM Decrypt
            ├── 4. O(1) Re-Order Buffer (ROB): Sequence out-of-order orbital arrivals
            ├── 5. BBRv3 State Machine: Calculate instantaneous BDP & RTProp
            ├── 6. Multi-Path Scheduler: Distribute encoded RLNC blocks across Satellite uplinks
            └── 7. Push to `egress_ring` → Net I/O Thread transmits at line-rate.

```

### 2. Node Execution: `io_uring` + WiFi 7

```bash
# Cross-compile for K26 SOM / aarch64
RUSTFLAGS="-C target-cpu=native -C profile-use=merged.profdata" cargo build --release --target aarch64-unknown-linux-gnu --manifest-path node/Cargo.toml

# Execute (io_uring PBR active)
sudo RUST_LOG=info ./target/release/m13-node --hub-ip 67.213.122.151:443 --tunnel-ip 10.13.0.2/24

```

**The Node Runtime Graph:**

```text
main()
├── Initialize 64MB HugePage Arena (MAP_POPULATE | MAP_LOCKED | MAP_HUGETLB)
├── Initialize `io_uring`: IORING_SETUP_DEFER_TASKRUN
├── Register Provided Buffer Rings (PBR): Map HugePage Arena directly to kernel SoftIRQ
└── Spawn Bifurcated Workers
    │
    ├── NET I/O THREAD (Core 1)
    │   ├── Submits ONE `IORING_RECV_MULTISHOT` SQE for the lifetime of the socket.
    │   ├── 100% Spin-Loop over CQE Ring:
    │   │   ├── Read CQE → Packet DMA'd to Arena by Kernel → Push `udp_rx_ring` (C2 cmds)
    │   │   └── Read TUN `io_uring` CQE → Push `tun_rx_ring` (Bulk Video)
    │   └── Submit `sendmsg` SQEs from `egress_ring`
    │
    └── DATAPATH THREAD (Core 2)
        └── Strict Priority Scheduling (Defeats HoL Blocking):
            ├── Priority 1: Drain `udp_rx_ring` (C2). Decrypt → Typestate FSM → Write to TUN.
            ├── Priority 2: If UDP is empty, drain `tun_rx_ring` (Video). 
            │   ├── Userspace Segmentation Offload (USO): Slice 64KB GRO frames to MTU.
            │   ├── Galois Field Matrix: SIMD/FPGA RLNC Encoding.
            │   └── AES-GCM Encrypt → UDP Port Spraying → Push to `egress_ring`.
            └── Priority 3: State Persistence. Active Keepalives injected if starved for 15s.

```

---

## V. Dependencies & Security Posture

M13 relies on an absolute minimum of external crates to reduce the supply chain attack surface.

### Hub & Node Shared Dependencies

| Crate | Subsystem | Hot Path? | Justification |
| --- | --- | --- | --- |
| `libc` | Core I/O | ✅ | Essential for `mmap`, `sched_setaffinity`, `io_uring`. |
| `ring` | Crypto | ✅ | Used strictly as software fallback for FPGA AES-GCM offload. |
| `bytemuck` | Parsing | ✅ | Zero-copy header casting. |
| `ml-kem` | PQC | ❌ | FIPS 203 Key Encapsulation (Handshake only). |
| `ml-dsa` | PQC | ❌ | FIPS 204 Digital Signatures (Handshake only). |
| `sha2` | PQC | ❌ | SHA-512 for HKDF (Handshake only). |
| `hkdf` | PQC | ❌ | HKDF-SHA-512 key derivation (Handshake only). |
| `rand` | PQC | ❌ | OsRng CSPRNG (Handshake only). |
| `bindgen` | Build | ❌ | Build-time kernel header bindings. |

### Hub-Specific Dependencies

| Crate | Subsystem | Hot Path? | Justification |
| --- | --- | --- | --- |
| `libbpf-sys` | Network | ❌ (Init) | Loads XDP/eBPF anti-DoS perimeters. |

### Node-Specific Dependencies

| Crate | Subsystem | Hot Path? | Justification |
| --- | --- | --- | --- |
| `io-uring` | Network | ✅ | Kernel 6.12+ MULTISHOT PBR bindings. |

---

## VI. Zero-Waste Determinism (Static Liveness Protocol)

M13 enforces a strict, zero-waste binary footprint. The architecture mandates that any code failing to mathematically prove its liveness in the compiler's Mid-Level Intermediate Representation (MIR) is inherently adversarial and must be automatically incinerated.

Lexical analysis (`grep`/Bash) is explicitly banned due to macro-expansion blindness. M13 achieves proof of liveness via a custom `rustc` driver and strict compiler lints (`#![deny(dead_code)]`, `#![deny(unused_variables)]`) that traverse the intermediate compiler graphs. This guarantees a pristine topological blueprint for all future hardware migrations.

### 1. MIR Call-Graph Reachability

M13 models function execution as a directed graph $G = (V, E)$, where $V$ represents all functions and $E$ represents invocation edges in the MIR. The protocol computes the transitive closure originating strictly from hardware entry points (e.g., `main`, interrupt vectors, eBPF hooks).

Let $R$ be the set of root execution nodes. A function node $v$ is mathematically live if and only if:
$$v \in Closure(R) \iff \exists \text{ path from } R \text{ to } v$$

Any function $v \notin Closure(R)$ is proven dead by the compiler. The build pipeline automatically aborts, demanding manual developer removal of the phantom execution path.

### 2. HIR Field-Level Memory Validation

Bloated struct definitions waste L1d cache and memory bandwidth. The M13 compiler driver traverses the High-Level Intermediate Representation (HIR) to enforce bidirectional memory liveness.

For every field $f$ within a struct $S$, the compiler must verify two distinct state transitions across the codebase:
* **Write State:** $\exists$ an assignment to $S.f$
* **Read State:** $\exists$ a subsequent load from $S.f$

If $S.f$ is written to but never read, or read but statically initialized without modification, the field is classified as a phantom payload and the compilation panics.

### 3. MIR Semantic Liveness (Def-Use Chains)

M13 executes strict Dataflow Analysis on the MIR control-flow graph to eradicate dead stores and discarded error codes. A variable assignment (Definition) is only mathematically valid if it reaches a subsequent consumer (Use) that influences hardware state (e.g., an `io_uring` submission, an `AF_XDP` ring update, or a hardware DMA register write).

The compiler evaluates the `LiveOut` state for every basic block $n$:
$$LiveOut(n) = \bigcup_{s \in succ(n)} LiveIn(s)$$

If a variable is defined but its state transitions to `StorageDead` before reaching a valid `LiveIn` state of a successor block, the allocation is flagged as a semantic leak.

### 4. Zero-Tolerance Dependency Pruning

The supply chain attack surface is minimized by continuously auditing the AST for phantom external crates. M13 utilizes strict `cargo-udeps` integration at the CI/CD level.

If a crate is declared in `Cargo.toml` but lacks a resolved invocation edge in the lowered AST, the build fails. There are zero waivers for unused dependencies.

---

## VII. Verification & Validation (V&V) Matrix

"Happy Path" testing is structurally prohibited. M13 must mathematically prove its logical correctness, memory safety, and physical resilience against adversarial physics, cryptographic anomalies, and silicon bottlenecks before Tier-1 flight trials.

Execution of this matrix guarantees the state machine is perfectly deterministic. The V&V Matrix strictly separates logical software proofs from physical silicon validation.

### Tier 1: Core Mathematical Integration

Validates the foundational mathematics and deterministic memory boundaries of the architecture in absolute isolation.

* **Vector:** 30+ strict deterministic tests executed via `cargo test`.
* **Criteria:** Verifies VPP pipeline scatter/gather logic, Galois Field matrix inversions, AES-256-GCM AEAD bit-exactness, wire format parity, and Compile-Time Typestate transitions. Zero allocations permitted in the hot path during execution.

### Tier 2: Namespace Bounded Integration (NetNS E2E)

Validates the **logical packet-processing graph (VPP)** and typestate transitions without RF/cloud variability, utilizing strict Linux Network Namespaces bridged via a synthetic `veth` pair.

* **Vector:** Kernel-isolated Linux `netns` (`ns_node`, `ns_hub`).
* **Criteria:** PQC handshake mathematically converges within **250ms**. Base logical throughput achieves theoretical maximums limited only by DDR4 memory bandwidth. `SIGKILL` on the Node triggers Hub `E_PEER_TIMEOUT` detection within **500ms**, verifying state machine timeout enforcement.

### Tier 3: Cryptographic Fuzzing (`libfuzzer`)

Mathematical proofs of spatial memory safety and algorithmic stability under adversarial mutation.

* **Vector:** `cargo-fuzz` compiling against LLVM libFuzzer.
* **Criteria:** Millions of mutating, adversarial byte arrays injected into `rx_parse_raw()`, `Assembler::feed()`, and `open_frame()`. The AST must mathematically guarantee a `false` or `Drop` return type without triggering timing side-channels, Out-Of-Memory (OOM) conditions, arithmetic panics, or segmentation faults.

### Tier 4: Micro-Architectural Benchmarking (`criterion`)

Instruction-Per-Cycle (IPC) variance tracking and ALU saturation bounds.

* **Vector:** `cargo bench` isolated to CPU Core 0 via `taskset` and CPU affinity pinning.
* **Criteria:** `aead_decrypt_vector` and `classify_route` batches must not regress in CPU cycle cost by **> 2%** across any commit. Any latency regression automatically halts the CI/CD pipeline, enforcing strict cycle-budget invariant bounds.

### Tier 5: Kinetic Survival & Chaos Engineering (CSE)

Validates the logical VPP state machines against Contested Spectrum Environment (CSE) realities.

* **Vector:** `tc netem` applied to Tier 2 virtual interfaces, injecting rigorous Gilbert-Elliott burst-loss models.
* **Criteria:**
* Inject `loss 30%`. Verify Software RLNC/FEC recovers the stream mathematically without triggering TCP `DUP-ACK` storms at the TUN boundary.
* Inject `delay 4s`. Verify MBB Epoch continuity and PQC Handshake survival.
* Inject `delay 6s`. Verify deterministic `HANDSHAKE_TIMEOUT_NS` correctly resets the FSM to `Disconnected`.
* Inject 100,000 duplicated `seq_id` payloads. Verify `replay_drops` atomic counter increments perfectly via the RFC 6479 bitmask with CPU utilization delta **< 1%**, proving algorithmic DoS immunity.



### Tier 6: Hardware-In-The-Loop (HITL) Silicon Proof

Validates the **true physical pipeline** (PCIe, DMA, AXI Bus, SMMU) against physical RF degradation and hardware exhaustion.

* **Vector:** Physical K26 SOM connected via physical Gigabit Ethernet/WiFi to an RF channel emulator.
* **Criteria:** Validates BBRv3 EDT pacing against real hardware queue backpressure. Validates IEEE 1588 hardware timestamping accuracy from the physical Gigabit Ethernet MAC (GEM). Proves zero CPU thermal throttling and zero dropped packets at the physical NIC ring buffers under sustained 50 Mbps Bandwidth-Delay Product (BDP) micro-bursts.
