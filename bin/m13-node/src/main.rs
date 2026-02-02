use clap::Parser;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use m13_linux::setup;
use m13_linux::{TunDevice, LinuxUdp, LinuxHsm, LinuxClock};
use m13_ulk::{M13Kernel, KernelConfig};
use m13_mem::SlabAllocator;
use m13_pqc::DsaKeypair;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use log::{info, warn};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::{
    process::Command,
    io::Write,
    fs::OpenOptions,
    os::unix::fs::PermissionsExt,
};

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Parser)]
struct Cli {
    #[arg(long)] hub: String,
    #[arg(long, default_value = "0.0.0.0:0")] bind: String,
    #[arg(long, default_value = "utun8")] iface: String, 
    #[arg(long, default_value = "10.13.13.2")] vip: String, 
}

// [SPRINT 41] AUTO-PHYSICS CONFIGURATION
fn ensure_hugepages() {
    #[cfg(target_os = "linux")]
    {
        info!(">>> [AUTO] CONFIGURING HUGEPAGES (128MB)...");
        let status = Command::new("sysctl")
            .args(&["-w", "vm.nr_hugepages=64"])
            .status();
            
        match status {
            Ok(s) if s.success() => info!("    -> Hugepages Reserved."),
            _ => warn!("    -> FAILED to reserve Hugepages. Run as Root?"),
        }
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    
    // [AUTO] ENGAGE MEMORY PHYSICS
    ensure_hugepages();
    
    let cli = Cli::parse();

    info!(">>> M13 NODE: v0.3.1 (Zero-Copy Ready) <<<");
    info!("Identity: {} on {}", cli.vip, cli.iface);

    // [PHYSICS] LINUX OPTIMIZATION ENGINE
    #[cfg(target_os = "linux")]
    {
        info!(">>> [AUTO] Engaging Linux Physics Protocols...");
        const PHYSICS_SCRIPT: &str = include_str!("../optimize_linux.sh");
        let script_path = "/tmp/m13_node_physics.sh";

        let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(script_path)?;
        file.write_all(PHYSICS_SCRIPT.as_bytes())?;
        
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o755);
        file.set_permissions(perms)?;
        drop(file);

        let _ = Command::new(script_path).status();
    }

    #[cfg(target_os = "macos")]
    {
        info!(">>> [AUTO] Engaging macOS Physics Protocols...");
        const PHYSICS_SCRIPT: &str = include_str!("../optimize_macos.sh");
        let script_path = "/tmp/m13_node_physics.sh";
        let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(script_path)?;
        file.write_all(PHYSICS_SCRIPT.as_bytes())?;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o755);
        file.set_permissions(perms)?;
        drop(file);
        let _ = Command::new(script_path).status();
    }

    let mut tun = TunDevice::new(&cli.iface, &cli.vip, "10.13.13.1")?;
    
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    setup::configure_node(tun.name(), &cli.hub, "10.13.13.1")?;

    let phy = LinuxUdp::new(&cli.bind, Some(&cli.hub))?;
    let mem = SlabAllocator::new(4096);
    
    let mut rng = rand::thread_rng();
    let identity = DsaKeypair::generate(&mut rng)?; 

    let config = KernelConfig { is_hub: false, enable_encryption: true };

    let mut kernel = M13Kernel::new(
        Box::new(phy), Box::new(LinuxHsm), Box::new(LinuxClock::new()), 
        mem, config, identity
    );

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        warn!("Signal received. Stopping...");
        r.store(false, Ordering::SeqCst);
    })?;

    info!("Node Kernel Active. Initiating Handshake...");
    let mut buf = [0u8; 65535];
    let mut tunnel_confirmed = false;

    while running.load(Ordering::SeqCst) {
        let mut work_done = false;
        for _ in 0..64 {
            match tun.read(&mut buf) {
                Ok(n) if n > 0 => { kernel.send_payload(&buf[..n]).ok(); work_done = true; },
                _ => break,
            }
        }
        if kernel.poll() { work_done = true; }
        while let Some(packet) = kernel.pop_ingress() {
            if !tunnel_confirmed {
                info!(">>> [NODE] TUNNEL ACTIVE (Round Trip Confirmed).");
                tunnel_confirmed = true;
            }
            let _ = tun.write(&packet);
            work_done = true;
        }
        if !work_done { std::thread::yield_now(); }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    setup::cleanup_node(tun.name());
    tun.shutdown();
    Ok(())
}
