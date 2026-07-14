mod config;
mod crypto;
#[cfg(target_os = "linux")]
mod nm;
mod tun;
mod tunnel;
mod web;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;
use tun_rs::DeviceBuilder;

#[derive(Parser)]
#[command(name = "bobvpn", about = "VPN over HTTPS on port 443")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the server
    Server {
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        insecure: bool,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Start the client
    Client {
        #[arg(long)]
        server: String,
        #[arg(long, default_value_t = false)]
        insecure: bool,
        #[arg(long, default_value_t = false)]
        force_http: bool,
    },
}

fn cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let ecode = Command::new(cmd)
        .args(args)
        .spawn()
        .with_context(|| format!("failed to spawn: {}", cmd))?
        .wait()
        .with_context(|| format!("failed to wait: {}", cmd))?;
    anyhow::ensure!(ecode.success(), "command failed: {} {:?}", cmd, args);
    Ok(())
}

// ---------------------------------------------------------------------------
// Platform-specific client network helpers
// ---------------------------------------------------------------------------

mod client_net {
    use super::*;

    #[cfg(target_os = "linux")]
    pub fn get_gateway() -> String {
        String::from_utf8_lossy(
            &Command::new("sh")
                .args(["-c", "ip route show default | awk '{print $3}'"])
                .output()
                .map(|o| o.stdout)
                .unwrap_or_default(),
        )
        .trim()
        .to_string()
    }

    #[cfg(target_os = "windows")]
    pub fn get_gateway() -> String {
        String::from_utf8_lossy(
            &Command::new("powershell")
                .args(["-Command",
                    "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"])
                .output()
                .map(|o| o.stdout)
                .unwrap_or_default(),
        )
        .trim()
        .to_string()
    }

    #[cfg(target_os = "linux")]
    pub fn get_gateway_v6() -> String {
        String::from_utf8_lossy(
            &Command::new("sh")
                .args(["-c", "ip -6 route show default | awk '{print $3}'"])
                .output()
                .map(|o| o.stdout)
                .unwrap_or_default(),
        )
        .trim()
        .to_string()
    }

    #[cfg(target_os = "windows")]
    pub fn get_gateway_v6() -> String {
        String::new()
    }

    #[cfg(target_os = "linux")]
    pub fn pin_route(ip: &str, gw: &str) -> Result<()> {
        let output = Command::new("ip").args(["route", "get", ip]).output()?;
        let route_info = String::from_utf8_lossy(&output.stdout);
        if route_info.contains("dev eth0") && !route_info.contains("via ") {
            cmd("ip", &["route", "replace", ip, "dev", "eth0", "scope", "link"])
        } else {
            cmd("ip", &["route", "replace", ip, "via", gw])
        }
    }

    #[cfg(target_os = "windows")]
    pub fn pin_route(ip: &str, gw: &str) -> Result<()> {
        cmd("route", &["add", ip, "mask", "255.255.255.255", gw])
    }

    #[cfg(target_os = "linux")]
    pub fn pin_route_v6(ip: &str, gw: &str) -> Result<()> {
        cmd("ip", &["-6", "route", "replace", ip, "via", gw, "dev", "eth0"])
    }

    #[cfg(target_os = "windows")]
    pub fn pin_route_v6(_ip: &str, _gw: &str) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn delete_default_routes() {
        let _ = cmd("sh", &["-c", "while ip route del default 2>/dev/null; do :; done; true"]);
    }

    #[cfg(target_os = "windows")]
    pub fn delete_default_routes() {
        let _ = cmd("powershell", &["-Command",
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Remove-NetRoute -Confirm:$false"]);
    }

    #[cfg(target_os = "linux")]
    pub fn delete_default_routes_v6() {
        let _ = cmd("sh", &["-c", "while ip -6 route del default 2>/dev/null; do :; done; true"]);
    }

    #[cfg(target_os = "windows")]
    pub fn delete_default_routes_v6() {}

    #[cfg(target_os = "linux")]
    pub fn set_default_route(gw: &str, tun: &str) -> Result<()> {
        cmd("ip", &["route", "add", "default", "via", gw, "dev", tun])
    }

    #[cfg(target_os = "windows")]
    pub fn set_default_route(gw: &str, tun: &str) -> Result<()> {
        cmd("powershell", &["-Command", &format!(
            "New-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop '{gw}' -InterfaceAlias '{tun}'"
        )])
    }

    #[cfg(target_os = "linux")]
    pub fn set_default_route_v6(gw: &str, tun: &str) -> Result<()> {
        cmd("ip", &["-6", "route", "add", "default", "via", gw, "dev", tun])
    }

    #[cfg(target_os = "windows")]
    pub fn set_default_route_v6(_gw: &str, _tun: &str) -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn add_tun_ipv6(tun: &str) {
        let _ = cmd("ip", &["-6", "addr", "add", &format!("{}/{}", config::CLIENT_IP_V6, config::TUN_PREFIX_V6), "dev", tun]);
    }

    #[cfg(target_os = "windows")]
    pub fn add_tun_ipv6(_tun: &str) {}

    #[cfg(target_os = "linux")]
    pub fn register_nm(tun: &str) {
        crate::nm::register_tun(tun);
    }

    #[cfg(target_os = "windows")]
    pub fn register_nm(_tun: &str) {}
}

use client_net::*;

// ---------------------------------------------------------------------------
// Server helpers (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn setup_server_network(tun_name: &str) {
    if let Err(e) = cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]) {
        log::warn!("failed to enable IP forwarding (may need root): {}", e);
    }
    let _ = cmd("sysctl", &["-w", "net.ipv4.conf.all.rp_filter=2"]);
    let subnet = format!("{}/{}", config::TUN_SUBNET, config::TUN_PREFIX);
    if let Err(e) = cmd(
        "iptables",
        &["-t", "nat", "-A", "POSTROUTING", "-s", &subnet, "-j", "MASQUERADE"],
    ) {
        log::warn!("failed to add IPv4 NAT rule: {}", e);
    }
    let _ = cmd("iptables", &["-P", "FORWARD", "ACCEPT"]);
    let _ = cmd("iptables", &["-A", "FORWARD", "-i", tun_name, "-j", "ACCEPT"]);
    let _ = cmd("iptables", &["-A", "FORWARD", "-o", tun_name, "-j", "ACCEPT"]);

    let _ = cmd("sysctl", &["-w", "net.ipv6.conf.all.forwarding=1"]);
    let _ = cmd("ip", &["-6", "addr", "add", &format!("{}/{}", config::SERVER_IP_V6, config::TUN_PREFIX_V6), "dev", tun_name]);
    let subnet_v6 = format!("{}/{}", config::TUN_SUBNET_V6, config::TUN_PREFIX_V6);
    let _ = cmd("ip6tables", &["-t", "nat", "-A", "POSTROUTING", "-s", &subnet_v6, "-j", "MASQUERADE"]);
    let _ = cmd("ip6tables", &["-P", "FORWARD", "ACCEPT"]);
    let _ = cmd("ip6tables", &["-A", "FORWARD", "-i", tun_name, "-j", "ACCEPT"]);
    let _ = cmd("ip6tables", &["-A", "FORWARD", "-o", tun_name, "-j", "ACCEPT"]);

    crate::nm::register_tun(tun_name);
    log::info!("IPv4 + IPv6 forwarding enabled, NAT configured");
}

#[cfg(not(target_os = "linux"))]
fn setup_server_network(_tun_name: &str) {
    log::warn!("server mode requires Linux for sysctl/iptables setup");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Server {
            domain,
            cert,
            key,
            insecure,
            port,
        } => {
            let port = port.unwrap_or_else(|| {
                std::env::var("PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(if insecure { config::DEV_PORT } else { config::SERVER_PORT })
            });

            let tun_dev = DeviceBuilder::new()
                .ipv4(config::SERVER_IP.to_string().as_str(), config::TUN_PREFIX, None)
                .mtu(config::TUN_MTU)
                .build_async()
                .context("failed to create TUN device")?;
            let tun_name = tun_dev.name()?;
            log::info!("TUN device created: {}", tun_name);
            let tun = tun::TunDevice::new(tun_dev);

            setup_server_network(&tun_name);

            if insecure {
                log::warn!("running without TLS (--insecure)");
                tunnel::server::run_plain(tun, port).await?;
                return Ok(());
            }

            let cert_mode = match (domain, cert, key) {
                (Some(d), None, None) => config::CertMode::Acme { domain: d },
                (None, Some(c), Some(k)) => {
                    config::CertMode::SelfSigned {
                        cert_path: c,
                        key_path: k,
                    }
                }
                _ => anyhow::bail!(
                    "server requires either --domain (ACME) or --cert and --key (self-signed)"
                ),
            };

            log::info!("IP forwarding enabled, NAT configured");

            tunnel::server::run(tun, cert_mode).await?;
        }
        Commands::Client { server, insecure, force_http } => {
            log::info!("starting bobvpn client, server: {} (insecure: {})", server, insecure);

            let tun_dev = DeviceBuilder::new()
                .ipv4(config::CLIENT_IP.to_string().as_str(), config::TUN_PREFIX, None)
                .mtu(config::TUN_MTU)
                .build_async()
                .context("failed to create TUN device")?;

            let tun_name = tun_dev.name()?;
            log::info!("TUN device created: {}", tun_name);

            let tun = tun::TunDevice::new(tun_dev);

            add_tun_ipv6(&tun_name);

            // Pin the VPN server via the current default gateway so the tunnel doesn't loop
            let current_gw = get_gateway();
            let current_gw_v6 = get_gateway_v6();
            let server_addr = format!("{}:443", server);
            if let Ok(addrs) = tokio::net::lookup_host(&server_addr).await {
                for addr in addrs {
                    if addr.is_ipv4() && !current_gw.is_empty() {
                        if let Err(e) = pin_route(&addr.ip().to_string(), &current_gw) {
                            log::warn!("failed to pin server route: {}", e);
                        }
                    }
                    if addr.is_ipv6() && !current_gw_v6.is_empty() {
                        if let Err(e) = pin_route_v6(&addr.ip().to_string(), &current_gw_v6) {
                            log::warn!("failed to pin server IPv6 route: {}", e);
                        }
                    }
                }
            }

            // Delete all existing default routes, then route through TUN
            delete_default_routes();
            delete_default_routes_v6();

            let gw = config::SERVER_IP.to_string();
            if let Err(e) = set_default_route(&gw, &tun_name) {
                log::warn!("failed to set IPv4 default route: {}", e);
            }
            let gw_v6 = config::SERVER_IP_V6.to_string();
            if let Err(e) = set_default_route_v6(&gw_v6, &tun_name) {
                log::warn!("failed to set IPv6 default route: {}", e);
            }

            register_nm(&tun_name);

            log::info!("current gateway: {}, v6 gateway: {}, server pin: {}, default route: via {} dev {}",
                current_gw, current_gw_v6, server_addr, config::SERVER_IP, tun_name);
            log::info!("routes configured, connecting to tunnel...");

            if force_http {
                log::warn!("forcing HTTP fallback (--force-http)");
                tunnel::client::run_http(tun, &server, insecure).await?;
            } else if insecure {
                log::warn!("skipping TLS, using plain WebSocket (--insecure)");
                tunnel::client::run_insecure(tun, &server).await?;
            } else {
                tunnel::client::run(tun, &server).await?;
            }
        }
    }

    Ok(())
}
