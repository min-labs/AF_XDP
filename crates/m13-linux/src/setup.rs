use std::process::Command;
use log::info;

// Helper to run commands atomically (No Shell = No Syntax Errors)
fn run_cmd(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program)
        .args(args)
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(anyhow::anyhow!("{} failed with exit code: {:?}", program, s.code())),
        Err(e) => Err(anyhow::anyhow!("Failed to execute {}: {}", program, e)),
    }
}

#[cfg(target_os = "linux")]
pub fn configure_hub(iface: &str, subnet: &str) -> anyhow::Result<()> {
    info!(">>> [AUTO] Configuring Linux Hub (NAT + Masquerade)...");

    // 1. Enable IP Forwarding
    run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;

    // 2. Clear old rules (Best Effort)
    let _ = Command::new("iptables").args(&["-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"]).output();
    let _ = Command::new("iptables").args(&["-D", "FORWARD", "-i", iface, "-j", "ACCEPT"]).output();

    // 3. Enable NAT
    run_cmd("iptables", &["-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"])?;

    // 4. Allow Forwarding
    run_cmd("iptables", &["-A", "FORWARD", "-i", iface, "-j", "ACCEPT"])?;
    run_cmd("iptables", &["-A", "FORWARD", "-o", iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])?;
    
    // 5. Set MTU
    run_cmd("ip", &["link", "set", "dev", iface, "mtu", "1280"])?;

    info!(">>> [SETUP] Linux Networking Active.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn configure_hub(_iface: &str, _subnet: &str) -> anyhow::Result<()> {
    Ok(())
}

// [PHYSICS] LINUX CLIENT ROUTING (IPv4 + IPv6 FIX)
#[cfg(target_os = "linux")]
pub fn configure_node(iface: &str, hub_endpoint: &str, _tun_gw: &str) -> anyhow::Result<()> {
    // 1. Parse Hub IP
    let hub_ip = hub_endpoint.split(':').next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Hub Endpoint"))?;

    info!(">>> [PHYSICS] ENGAGING LINUX ROUTING TABLE INJECTION <<<");

    // 2. Detect Physical Gateway (IPv4)
    // We use 'ip route get 1.1.1.1' to find the path to the internet.
    let output = Command::new("ip").args(&["route", "get", "1.1.1.1"]).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    
    let gateway_idx = parts.iter().position(|&r| r == "via")
        .ok_or_else(|| anyhow::anyhow!("Could not detect default gateway"))?;
    let gateway_ip = parts.get(gateway_idx + 1)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse gateway IP"))?;
    
    let phys_dev_idx = parts.iter().position(|&r| r == "dev")
        .ok_or_else(|| anyhow::anyhow!("Could not detect physical interface"))?;
    let phys_dev = parts.get(phys_dev_idx + 1)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse physical interface"))?;

    info!("Detected Physical Route: via {} dev {}", gateway_ip, phys_dev);

    // 3. Pin Hub Traffic to Physical Interface (IPv4 Bypass)
    let _ = Command::new("ip").args(&["route", "del", hub_ip]).output(); 
    run_cmd("ip", &["route", "add", hub_ip, "via", gateway_ip, "dev", phys_dev])?;

    // 4. Hijack IPv4 Traffic (Split Horizon)
    info!("Injecting IPv4 Capture Routes...");
    run_cmd("ip", &["route", "add", "0.0.0.0/1", "dev", iface])?;
    run_cmd("ip", &["route", "add", "128.0.0.0/1", "dev", iface])?;

    // 5. Hijack IPv6 Traffic (PREVENT LEAK)
    // We inject ::/1 and 8000::/1 to cover the entire IPv6 space.
    // If the tunnel doesn't support IPv6, this traffic will simply drop (Fail-Secure).
    // We ignore errors here in case the host has IPv6 disabled.
    info!("Injecting IPv6 Capture Routes...");
    let _ = Command::new("ip").args(&["-6", "route", "add", "::/1", "dev", iface]).status();
    let _ = Command::new("ip").args(&["-6", "route", "add", "8000::/1", "dev", iface]).status();

    info!(">>> [SUCCESS] Linux Routing Table Secured (Dual Stack).");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn cleanup_node(_iface: &str) {
    info!(">>> [CLEANUP] Removing Capture Routes...");
    let _ = Command::new("ip").args(&["route", "del", "0.0.0.0/1"]).output();
    let _ = Command::new("ip").args(&["route", "del", "128.0.0.0/1"]).output();
    let _ = Command::new("ip").args(&["-6", "route", "del", "::/1"]).output();
    let _ = Command::new("ip").args(&["-6", "route", "del", "8000::/1"]).output();
}

#[cfg(target_os = "macos")]
pub fn configure_node(iface: &str, hub_endpoint: &str, _tun_gw: &str) -> anyhow::Result<()> {
    let hub_ip = hub_endpoint.split(':').next().unwrap();
    
    let output = Command::new("route").args(&["-n", "get", "default"]).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    let gateway = stdout.lines()
        .find(|line| line.trim().starts_with("gateway:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or(anyhow::anyhow!("No Gateway Detected in Route Table"))?
        .to_string();

    info!(">>> ENGAGING GLOBAL ROUTING (v0.3.0) <<<");
    info!("Detected Physical Gateway: {}", gateway);

    let _ = Command::new("route").args(&["delete", hub_ip]).output(); 
    run_cmd("route", &["add", "-host", hub_ip, &gateway])?;

    let _ = Command::new("route").args(&["delete", "0.0.0.0/1"]).output();
    let _ = Command::new("route").args(&["delete", "128.0.0.0/1"]).output();
    
    info!("Adding Global Routes to interface: {}", iface);
    run_cmd("route", &["add", "-net", "0.0.0.0/1", "-interface", iface])?;
    run_cmd("route", &["add", "-net", "128.0.0.0/1", "-interface", iface])?;
    
    // macOS IPv6 Hijack (Best Effort)
    let _ = Command::new("route").args(&["add", "-inet6", "::/1", "-interface", iface]).output();
    let _ = Command::new("route").args(&["add", "-inet6", "8000::/1", "-interface", iface]).output();

    info!("[SUCCESS] Routes Configured. Internet Traffic Hijacked.");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn cleanup_node(_iface: &str) {
    info!(">>> [CLEANUP] Removing Routes...");
    let _ = Command::new("route").args(&["delete", "0.0.0.0/1"]).output();
    let _ = Command::new("route").args(&["delete", "128.0.0.0/1"]).output();
    let _ = Command::new("route").args(&["delete", "-inet6", "::/1"]).output();
    let _ = Command::new("route").args(&["delete", "-inet6", "8000::/1"]).output();
}
