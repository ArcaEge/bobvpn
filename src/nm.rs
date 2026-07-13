use std::process::Command;

/// Register a TUN interface with NetworkManager so it shows up in
/// GNOME / KDE network settings and `nmcli device`.
///
/// This is best-effort — if NM is not running it silently succeeds.
pub fn register_tun(tun_name: &str) {
    let _ = std::fs::remove_file("/etc/NetworkManager/conf.d/90-bobvpn.conf");
    let uuid = uuid_v4_fallback();
    let con_name = format!("bobvpn-{}", tun_name);

    // Remove old connection if it exists from a previous run
    let _ = Command::new("nmcli")
        .args(["connection", "delete", &con_name])
        .output();

    let _ = Command::new("nmcli")
        .args([
            "connection",
            "add",
            "type",
            "generic",
            "con-name",
            &con_name,
            "ifname",
            tun_name,
            "connection.uuid",
            &uuid,
            "connection.autoconnect",
            "no",
            "ipv4.method",
            "link-local",
            "ipv6.method",
            "link-local",
        ])
        .output();

    let result = Command::new("nmcli")
        .args(["connection", "up", &con_name])
        .output();
    if let Ok(out) = result {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.is_empty() {
            log::warn!("nmcli up: {}", stderr.trim());
        }
    }
}

fn uuid_v4_fallback() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (now >> 32) as u32,
        (now >> 16) as u16,
        (now & 0xfff) as u16,
        0x4000 | ((now >> 48) & 0x3fff) as u16,
        (now >> 8) as u64 & 0xffffffffffff
    )
}
