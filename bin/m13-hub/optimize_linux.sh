#!/bin/bash
# -----------------------------------------------------------------------------
# M13 HUB "TITAN GATEWAY" - PHYSICS ENGINE v0.4.1
# TARGET: Linux Servers (x86_64 / ARM64)
# FIXES: Adaptive RX (True), NAPI, IRQ Pinning, Buffers, Firewall, BBR
# -----------------------------------------------------------------------------

if [ "$(uname)" != "Linux" ]; then
    echo ">>> FATAL: This script requires Linux. Aborting."
    exit 1
fi

# Detect active interface (Gateway Route)
INTERFACE=$(ip -o -4 route show to default | awk '{print $5}')
echo ">>> ENGAGING TITAN GATEWAY PROTOCOLS FOR $INTERFACE..."

# ==============================================================================
# 1. HARDWARE PHYSICS (ADAPTIVE COALESCING)
# ==============================================================================
echo "[+] NEGOTIATING INTERRUPTS..."

if ethtool -C $INTERFACE adaptive-rx on adaptive-tx on 2>/dev/null; then
    echo "    -> SUCCESS: Adaptive Coalescing ENGAGED."
else
    echo "    -> FAILURE: Hardware rejected Adaptive Mode."
    exit 1
fi

echo "[+] EXPANDING RINGS..."
ethtool -G $INTERFACE rx 4096 tx 4096 2>/dev/null || echo "    -> Rings already maxed."

# ==============================================================================
# 1.1 RADIO PHYSICS (POWER MANAGEMENT)
# ==============================================================================
echo "[+] OPTIMIZING RADIO PHYSICS..."
# Relevant for Hubs running on bare metal with WiFi backhaul or specific NICs
if command -v iw >/dev/null 2>&1; then
    if [[ "$INTERFACE" == wlp* ]] || [[ "$INTERFACE" == wl* ]]; then
        iw dev $INTERFACE set power_save off 2>/dev/null
        CURRENT_STATE=$(iw dev $INTERFACE get power_save | awk '{print $3}')
        echo "    -> WiFi Power Save: $CURRENT_STATE (Target: off)"
    fi
else
    echo "    -> WARNING: 'iw' binary missing or interface is wired. Skipping."
fi

# Persistence (NetworkManager Override)
NM_CONF="/etc/NetworkManager/conf.d/default-wifi-powersave-on.conf"
if [ -d "/etc/NetworkManager/conf.d" ]; then
    echo -e "[connection]\nwifi.powersave=2" > $NM_CONF
    echo "    -> Persistence Applied: NetworkManager Config Updated."
fi

# ==============================================================================
# 2. SOFTWARE COMPENSATION (NAPI BUDGET)
# ==============================================================================
echo "[+] TUNING NAPI BUDGET..."
sysctl -w net.core.netdev_budget=600 > /dev/null
sysctl -w net.core.netdev_budget_usecs=4000 2>/dev/null || true

# ==============================================================================
# 3. IRQ ISOLATION
# ==============================================================================
echo "[+] ISOLATING IRQS TO CORE 0..."
service irqbalance stop 2>/dev/null

IRQS=$(grep "$INTERFACE" /proc/interrupts | awk '{print $1}' | tr -d :)
if [ -n "$IRQS" ]; then
    for IRQ in $IRQS; do
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
echo "[+] DISABLING CONNTRACK..."
iptables -t raw -I OUTPUT -p udp -j NOTRACK 2>/dev/null
iptables -t raw -I PREROUTING -p udp -j NOTRACK 2>/dev/null

# ==============================================================================
# 6. MEMORY PHYSICS (HUGE PAGES)
# ==============================================================================
echo "[+] ACTIVATING HUGE PAGES..."
echo always > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
echo always > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null

# ==============================================================================
# 7. THERMAL PHYSICS (LATENCY LOCK)
# ==============================================================================
echo "[+] DISABLING SLEEP STATES..."
if [ ! -f /tmp/latency_lock ]; then
    nohup python3 -c "import os; f=os.open('/dev/cpu_dma_latency', os.O_RDWR); os.write(f, b'\x00\x00\x00\x00'); import time; time.sleep(99999999)" >/dev/null 2>&1 &
    touch /tmp/latency_lock
fi

# ==============================================================================
# 8. CONGESTION PHYSICS (BBR ALGORITHM)
# ==============================================================================
echo "[+] ENGAGING BBR ALGORITHM..."
modprobe tcp_bbr 2>/dev/null
sysctl -w net.core.default_qdisc=fq > /dev/null
sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null
CURRENT_ALGO=$(sysctl -n net.ipv4.tcp_congestion_control)
echo "    -> Congestion Control: $CURRENT_ALGO"

echo ">>> OPTIMIZATION COMPLETE."
