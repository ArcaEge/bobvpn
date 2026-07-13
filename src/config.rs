use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

pub const TUN_SUBNET: &str = "10.107.1.0";
pub const TUN_PREFIX: u8 = 24;
pub const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 107, 1, 2);
pub const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 107, 1, 1);

pub const TUN_SUBNET_V6: &str = "fd00:107:1::";
pub const TUN_PREFIX_V6: u8 = 64;
pub const CLIENT_IP_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x107, 0x1, 0, 0, 0, 0, 0x2);
pub const SERVER_IP_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x107, 0x1, 0, 0, 0, 0, 0x1);

pub const TUN_MTU: u16 = 1280;
pub const SERVER_PORT: u16 = 443;
pub const DEV_PORT: u16 = 8080;

pub const MAX_FRAME_SIZE: usize = 1500;
pub const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
pub const RECONNECT_BASE_DELAY: std::time::Duration = std::time::Duration::from_secs(1);
pub const RECONNECT_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(30);

pub enum CertMode {
    Acme { domain: String },
    SelfSigned { cert_path: PathBuf, key_path: PathBuf },
}

pub fn secret_path() -> PathBuf {
    dirs().join("secret")
}

pub fn cert_cache_path() -> PathBuf {
    dirs().join("certs")
}

fn dirs() -> PathBuf {
    let custom = std::env::var("BOBVPN_HOME").ok().map(PathBuf::from);
    custom.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        PathBuf::from(home).join(".config").join("bobvpn")
    })
}
