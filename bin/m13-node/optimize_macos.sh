#!/bin/bash
# -----------------------------------------------------------------------------
# M13 NODE: MINI-TITAN OPTIMIZATION (MACOS ONLY)
# COVERS: BSD SYSCTL TUNING v2
# -----------------------------------------------------------------------------

if [ "$(uname)" != "Darwin" ]; then
    echo ">>> FATAL: This script requires macOS. Aborting."
    exit 1
fi

echo ">>> ENGAGING PHYSICS OPTIMIZATIONS FOR MACOS..."

# 1. Increase Max Socket Buffer to 8MB (The Ceiling)
# We need 8MB here to comfortably house a 4MB UDP buffer + Metadata overhead.
sudo sysctl -w kern.ipc.maxsockbuf=8388608

# 2. Increase UDP Payload Buffer to 4MB
# This allows large bursts from the Hub to sit in RAM without dropping.
sudo sysctl -w net.inet.udp.recvspace=4194304
sudo sysctl -w net.inet.udp.maxdgram=65535

# 3. Fast-Fail Dead Routes
# Helps M13 detect network changes (WiFi <-> 5G) faster.
sudo sysctl -w net.inet.tcp.keepinit=10000

echo ">>> OPTIMIZATION COMPLETE."
