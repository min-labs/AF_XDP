use m13_xdp::M13HubDriver; 
use clap::Parser;
use std::process::Command;
use std::io::Write;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use log::{info, warn};

#[derive(Parser)] 
struct Args { 
    #[arg(long, default_value="eno2")] 
    iface: String,
    
    #[arg(long)] 
    ip: Option<String>,
}

// [SPRINT 41] TITAN GATEWAY PROTOCOL
const TITAN_SCRIPT: &str = r#"#!/bin/bash
# -----------------------------------------------------------------------------
# M13 HUB "TITAN GATEWAY" - PHYSICS ENGINE v0.4.1
# TARGET: Linux Servers (x86_64 / ARM64)
# FIXES: Adaptive RX (True), NAPI, IRQ Pinning, Buffers, Firewall, BBR
# -----------------------------------------------------------------------------

if [ "$(uname)" != "Linux" ]; then
    echo ">>> FATAL: This script requires Linux. Aborting."
    exit 1
fi

# Detect active interface (Gateway Route) or use provided arg
INTERFACE=$1
if [ -z "$INTERFACE" ]; then
    INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
fi

echo ">>> ENGAGING TITAN GATEWAY PROTOCOLS FOR $INTERFACE..."

# ==============================================================================
# 1. HARDWARE PHYSICS (ADAPTIVE COALESCING)
# ==============================================================================
echo "[+] NEGOTIATING INTERRUPTS..."
if ethtool -C $INTERFACE adaptive-rx on adaptive-tx on 2>/dev/null; then
    echo "    -> SUCCESS: Adaptive Coalescing ENGAGED."
else
    echo "    -> FAILURE: Hardware rejected Adaptive Mode."
    # Fallback to static
    ethtool -C $INTERFACE rx-usecs 30 2>/dev/null
fi

echo "[+] EXPANDING RINGS..."
ethtool -G $INTERFACE rx 4096 tx 4096 2>/dev/null || echo "    -> Rings already maxed."

# ==============================================================================
# 2. SOFTWARE COMPENSATION (NAPI BUDGET)
# ==============================================================================
echo "[+] TUNING NAPI BUDGET..."
sysctl -w net.core.netdev_budget=600 > /dev/null
sysctl -w net.core.netdev_budget_usecs=4000 2>/dev/null || true

# ==============================================================================
# 3. IRQ ISOLATION (CORE 0 ONLY)
# ==============================================================================
echo "[+] ISOLATING IRQS TO CORE 0..."
service irqbalance stop 2>/dev/null
systemctl stop irqbalance 2>/dev/null

IRQS=$(grep "$INTERFACE" /proc/interrupts | awk '{print $1}' | tr -d :)
if [ -n "$IRQS" ]; then
    for IRQ in $IRQS; do
        # Affinity Mask 1 = Core 0
        echo 1 > /proc/irq/$IRQ/smp_affinity 2>/dev/null
        echo "    -> Locked IRQ $IRQ to Core 0"
    done
fi

# ==============================================================================
# 4. KERNEL BUFFERS & LATENCY
# ==============================================================================
echo "[+] MAXIMIZING KERNEL BUFFERS..."
sysctl -w net.core.netdev_max_backlog=10000 > /dev/null
sysctl -w net.core.rmem_max=16777216 > /dev/null
sysctl -w net.core.wmem_max=16777216 > /dev/null
sysctl -w net.core.busy_read=50 > /dev/null
sysctl -w net.core.busy_poll=50 > /dev/null

# ==============================================================================
# 5. FIREWALL BYPASS
# ==============================================================================
echo "[+] DISABLING CONNTRACK FOR UDP..."
iptables -t raw -I OUTPUT -p udp -j NOTRACK 2>/dev/null
iptables -t raw -I PREROUTING -p udp -j NOTRACK 2>/dev/null

# ==============================================================================
# 6. MEMORY PHYSICS (HUGE PAGES)
# ==============================================================================
echo "[+] ACTIVATING HUGE PAGES..."
sysctl -w vm.nr_hugepages=64 > /dev/null
echo always > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
echo always > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null

# ==============================================================================
# 7. THERMAL PHYSICS (LATENCY LOCK)
# ==============================================================================
echo "[+] DISABLING SLEEP STATES..."
# We assume the binary handles CPU affinity, but we prevent C-States here if possible
# (Requires python3 or specialized tools, skipping complicated python invocation to avoid deps)
# Direct C-State limit via sysctl if available
sysctl -w kernel.nmi_watchdog=0 2>/dev/null

# ==============================================================================
# 8. CONGESTION PHYSICS (BBR ALGORITHM)
# ==============================================================================
echo "[+] ENGAGING BBR ALGORITHM..."
modprobe tcp_bbr 2>/dev/null
sysctl -w net.core.default_qdisc=fq > /dev/null
sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null

echo ">>> OPTIMIZATION COMPLETE."
"#;

fn engage_physics(iface: &str) -> std::io::Result<()> {
    info!(">>> [AUTO] WRITING TITAN GATEWAY SCRIPT...");
    let path = "/tmp/m13_titan_gateway.sh";
    
    let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
    file.write_all(TITAN_SCRIPT.as_bytes())?;
    
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(0o755);
    file.set_permissions(perms)?;
    drop(file);

    info!(">>> [AUTO] EXECUTING TITAN GATEWAY PROTOCOLS...");
    let status = Command::new(path).arg(iface).status()?;
    
    if status.success() {
        info!("    -> PHYSICS OPTIMIZED.");
    } else {
        warn!("    -> PHYSICS SCRIPT RETURNED ERROR CODE.");
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() { std::env::set_var("RUST_LOG", "info"); }
    env_logger::init();
    
    let args = Args::parse();
    
    // [PHYSICS] RUN THE SCRIPT
    if let Err(e) = engage_physics(&args.iface) {
        warn!("Failed to engage physics: {}", e);
    }
    
    // VPP: Blocks Forever
    let driver = M13HubDriver::new(&args.iface, 0, args.ip)?;
    driver.run_vpp();
    Ok(())
}
