use std::process::Command;

/// Register a TUN interface with NetworkManager so it shows up in
/// GNOME / KDE network settings and `nmcli device`.
///
/// This is best-effort — if NM is not running it silently succeeds.
pub fn register_tun(tun_name: &str) {
    // Mark bobvpn interfaces as unmanaged so NM doesn't fight for IP/route ownership.
    let _ = write_nm_unmanaged_conf();

    // Create a temporary dummy NM connection so the TUN appears in the GUI.
    let uuid = uuid_v4_fallback();
    let _ = Command::new("nmcli")
        .args([
            "connection",
            "add",
            "type",
            "tun",
            "con-name",
            &format!("bobvpn-{}", tun_name),
            "ifname",
            tun_name,
            "connection.uuid",
            &uuid,
            "tun.mode",
            "1",
            "ipv4.method",
            "disabled",
            "ipv6.method",
            "disabled",
            "connection.autoconnect",
            "no",
        ])
        .output();

    // (optional) activate the connection so NM marks it as "connected"
    let _ = Command::new("nmcli")
        .args([
            "connection",
            "up",
            &format!("bobvpn-{}", tun_name),
        ])
        .output();
}

fn write_nm_unmanaged_conf() -> Result<(), std::io::Error> {
    let path = "/etc/NetworkManager/conf.d/90-bobvpn.conf";
    let content = "[keyfile]\nunmanaged-devices=interface-name:bob*\n";
    std::fs::write(path, content)
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
